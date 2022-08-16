// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"strings"

	"github.com/copa-europe-tokens/pkg/config"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger-labs/orion-sdk-go/pkg/bcdb"
	sdkconfig "github.com/hyperledger-labs/orion-sdk-go/pkg/config"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
)

const (
	TokenDBSeparator      = "."
	TypesDBName           = "token-types"
	TokenTypeDBNamePrefix = "ttid" + TokenDBSeparator
)

//go:generate counterfeiter -o mocks/operations.go --fake-name Operations . Operations

type Operations interface {

	// Management API

	GetStatus() (string, error)

	// Generic token type API

	DeployTokenType(deployRequest *types.DeployRequest) (*types.DeployResponse, error)
	GetTokenType(tokenTypeId string) (*types.DeployResponse, error)
	GetTokenTypes() ([]*types.DeployResponse, error)

	// Non fungible token type (NFT) API

	PrepareMint(tokenTypeId string, mintRequest *types.MintRequest) (*types.MintResponse, error)
	PrepareTransfer(tokenId string, transferRequest *types.TransferRequest) (*types.TransferResponse, error)
	SubmitTx(submitRequest *types.SubmitRequest) (*types.SubmitResponse, error)
	GetToken(tokenId string) (*types.TokenRecord, error)
	GetTokensByOwner(tokenTypeId string, owner string) ([]*types.TokenRecord, error)

	// Annotations API

	PrepareRegister(tokenTypeId string, registerRequest *types.AnnotationRegisterRequest) (*types.AnnotationRegisterResponse, error)
	GetAnnotation(tokenId string) (*types.AnnotationRecord, error)
	GetAnnotationsByOwnerLink(tokenTypeId string, owner, link string) ([]*types.AnnotationRecord, error)

	// User API

	AddUser(userRecord *types.UserRecord) error
	UpdateUser(userRecord *types.UserRecord) error
	RemoveUser(userId string) error
	GetUser(userId string) (*types.UserRecord, error)

	// Fungible token type API

	FungibleDeploy(deployRequest *types.FungibleDeployRequest) (*types.FungibleDeployResponse, error)
	FungibleDescribe(typeId string) (*types.FungibleDescribeResponse, error)
	FungiblePrepareMint(typeId string, request *types.FungibleMintRequest) (*types.FungibleMintResponse, error)
	FungiblePrepareTransfer(typeId string, request *types.FungibleTransferRequest) (*types.FungibleTransferResponse, error)
	FungiblePrepareConsolidate(typeId string, request *types.FungibleConsolidateRequest) (*types.FungibleConsolidateResponse, error)
	FungibleSubmitTx(submitRequest *types.FungibleSubmitRequest) (*types.FungibleSubmitResponse, error)
	FungibleAccounts(typeId string, owner string, account string) ([]types.FungibleAccountRecord, error)
}

// TODO handle ServerTimeout on Commit

type Manager struct {
	config *config.Configuration
	lg     *logger.SugarLogger

	bcDB             bcdb.BCDB
	adminSession     bcdb.DBSession
	custodianSession bcdb.DBSession

	tokenTypesDBs map[string]bool
}

type TokenDescription struct {
	TypeId      string `json:"typeId"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Class       string `json:"class"`
	Url         string `json:"url,omitempty"`
}

func NewManager(config *config.Configuration, lg *logger.SugarLogger) (*Manager, error) {
	m := &Manager{
		config: config,
		lg:     lg,

		tokenTypesDBs: make(map[string]bool),
	}

	if len(config.Orion.CaConfig.RootCACertsPath) == 0 {
		return nil, errors.New("Bad config, empty root CA config")
	}

	if err := m.createDBInstance(); err != nil {
		return nil, err
	}

	if err := m.createAdminSession(); err != nil {
		return nil, err
	}

	if err := m.createTypesDB(); err != nil {
		return nil, err
	}

	if err := m.enrollCustodian(); err != nil {
		return nil, err
	}

	if err := m.createCustodianSession(); err != nil {
		return nil, err
	}

	tokenTypes, err := m.GetTokenTypes()
	if err != nil {
		return nil, err
	}
	m.lg.Debugf("Found token types: %+v", tokenTypes)
	for _, tt := range tokenTypes {
		dbName := TokenTypeDBNamePrefix + tt.TypeId
		m.tokenTypesDBs[dbName] = true
	}
	m.lg.Debugf("Found token types: %v", m.tokenTypesDBs)

	m.lg.Info("Connected to Orion")

	return m, nil
}

func (m *Manager) Close() error {
	//TODO
	return nil
}

func (m *Manager) GetStatus() (string, error) {
	tx, err := m.adminSession.ConfigTx()
	if err != nil {
		return "", errors.Wrap(err, "failed to get status")
	}
	config, err := tx.GetClusterConfig()
	if err != nil {
		return "", errors.Wrap(err, "failed to get status")
	}

	b := strings.Builder{}
	b.WriteString("{")
	for i, n := range config.Nodes {
		b.WriteString(nodeConfigToString(n))
		if i < len(config.Nodes)-1 {
			b.WriteString("; ")
		}
	}
	b.WriteString("}")
	return fmt.Sprintf("connected: %s", b.String()), nil
}

func (m *Manager) DeployTokenType(deployRequest *types.DeployRequest) (*types.DeployResponse, error) {
	if deployRequest.Name == "" {
		return nil, &ErrInvalid{ErrMsg: "token type name is empty"}
	}

	// Compute TypeId
	tokenTypeIDBase64, err := NameToID(deployRequest.Name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute hash of token type name")
	}
	tokenDBName := TokenTypeDBNamePrefix + tokenTypeIDBase64

	switch deployRequest.Class {
	case "": //backward compatibility
		deployRequest.Class = constants.TokenClass_NFT
	case constants.TokenClass_NFT:
	case constants.TokenClass_FUNGIBLE:
	case constants.TokenClass_ANNOTATIONS:
	default:
		return nil, &ErrInvalid{ErrMsg: "unsupported token class: " + deployRequest.Class}
	}

	tokenDesc := &TokenDescription{
		TypeId:      tokenTypeIDBase64,
		Name:        deployRequest.Name,
		Class:       deployRequest.Class,
		Description: deployRequest.Description,
	}

	// Check existence by looking into the custodian privileges
	userTx, err := m.adminSession.UsersTx()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create UsersTx")
	}
	custodian, err := userTx.GetUser(m.config.Users.Custodian.UserID)
	if err != nil {
		userTx.Abort()
		return nil, errors.Wrapf(err, "failed to get user: %s", m.config.Users.Custodian.UserID)
	}
	if _, exists := custodian.GetPrivilege().GetDbPermission()[tokenDBName]; exists {
		userTx.Abort()
		return nil, &ErrExist{ErrMsg: "token type already exists"}
	}

	// Save token description to Types-DB
	dataTx, err := m.adminSession.DataTx()
	if err != nil {
		userTx.Abort()
		return nil, errors.Wrap(err, "failed to create DataTx")
	}

	data, _, err := dataTx.Get(TypesDBName, tokenDBName)
	if err != nil {
		userTx.Abort()
		dataTx.Abort()
		return nil, errors.Wrapf(err, "failed to get %s %s", TypesDBName, tokenDBName)
	}
	if data != nil {
		userTx.Abort()
		dataTx.Abort()
		return nil, errors.Errorf("failed to deploy token: custodian does not have privilege, but token type description exists: %s", string(data))
	}

	data, err = json.Marshal(tokenDesc)
	if err != nil {
		m.lg.Panicf("failed to json.Marshal TokenDescription: %s", err)
	}
	err = dataTx.Put(TypesDBName, tokenDBName, data, nil)
	if err != nil {
		userTx.Abort()
		dataTx.Abort()
		return nil, errors.Wrapf(err, "failed to put %s %s", TypesDBName, tokenDBName)
	}
	txID, receiptEnv, err := dataTx.Commit(true)
	if err != nil {
		userTx.Abort()
		return nil, errors.Wrapf(err, "failed to commit %s %s", TypesDBName, tokenDBName)
	}

	m.lg.Infof("Saved token description: %+v; txID: %s, receipt: %+v", tokenDesc, txID, receiptEnv.GetResponse().GetReceipt())

	switch deployRequest.Class {
	case constants.TokenClass_NFT:
		err = m.deployNFT(deployRequest, tokenDBName, "owner")
	case constants.TokenClass_ANNOTATIONS:
		err = m.deployNFT(deployRequest, tokenDBName, "owner", "link")
	case constants.TokenClass_FUNGIBLE:
		err = errors.New("not implemented yet")

	default:
		err = &ErrInvalid{ErrMsg: "unsupported token class: " + deployRequest.Class}
	}

	if err != nil {
		userTx.Abort()
		return nil, err
	}

	// Add privilege to custodian
	custodian.Privilege.DbPermission[tokenDBName] = oriontypes.Privilege_ReadWrite

	err = userTx.PutUser(custodian, nil)
	if err != nil {
		userTx.Abort()
		return nil, errors.Wrap(err, "failed to put user")
	}

	txID, receiptEnv, err = userTx.Commit(true)
	if err != nil {
		return nil, errors.Wrap(err, "failed to commit user")
	}

	m.tokenTypesDBs[tokenDBName] = true
	m.lg.Infof("Custodian [%s] granted RW privilege to database: %s; txID: %s, receipt: %+v", m.config.Users.Custodian.UserID, tokenDBName, txID, receiptEnv.GetResponse().GetReceipt())

	return &types.DeployResponse{
		TypeId:      tokenTypeIDBase64,
		Name:        deployRequest.Name,
		Class:       deployRequest.Class,
		Description: deployRequest.Description,
		Url:         constants.TokensTypesSubTree + tokenTypeIDBase64,
	}, nil
}

func (m *Manager) deployNFT(deployRequest *types.DeployRequest, tokenDBName string, indices ...string) error {
	dBsTx, err := m.adminSession.DBsTx()
	if err != nil {
		return errors.Wrap(err, "failed to create DBsTx")
	}

	exists, err := dBsTx.Exists(tokenDBName)
	if err != nil {
		dBsTx.Abort()
		return errors.Wrap(err, "failed to query DB existence")
	}
	if exists {
		dBsTx.Abort()
		return errors.Errorf("failed to deploy token: custodian does not have privilege, but token database exists: %s", tokenDBName)
	}

	index := make(map[string]oriontypes.IndexAttributeType)
	for _, ind := range indices {
		index[ind] = oriontypes.IndexAttributeType_STRING
	}
	err = dBsTx.CreateDB(tokenDBName, index)
	if err != nil {
		dBsTx.Abort()
		return errors.Wrap(err, "failed to build DBsTx")
	}

	txID, receiptEnv, err := dBsTx.Commit(true)
	if err != nil {
		m.lg.Errorf("Failed to deploy: commit failed: %s", err.Error())
		if strings.Contains(err.Error(), fmt.Sprintf("[%s] already exists", tokenDBName)) {
			return &ErrExist{ErrMsg: "token type already exists"}
		}
		return errors.Wrap(err, "failed to deploy token type")
	}

	m.lg.Infof("Database created: %s, for token-name: %s; token-class: %s txID: %s, receipt: %+v", tokenDBName, deployRequest.Name, deployRequest.Class, txID, receiptEnv.GetResponse().GetReceipt())
	return nil
}

func (m *Manager) GetTokenType(tokenTypeId string) (*types.DeployResponse, error) {
	if err := validateMD5Base64ID(tokenTypeId, "token type"); err != nil {
		return nil, err
	}

	dataTx, err := m.custodianSession.DataTx()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create DataTx")
	}

	tokenDBName := TokenTypeDBNamePrefix + tokenTypeId
	val, meta, err := dataTx.Get(TypesDBName, tokenDBName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to Get %s", tokenDBName)
	}

	if val == nil {
		return nil, &ErrNotFound{ErrMsg: "not found"}
	}

	deployResponse := &types.DeployResponse{}
	err = json.Unmarshal(val, deployResponse)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to json.Unmarshal %s", tokenDBName)
	}
	deployResponse.Url = constants.TokensTypesSubTree + deployResponse.TypeId

	m.lg.Debugf("Token type deploy response: %+v; metadata: %v", deployResponse, meta)

	return deployResponse, nil
}

func (m *Manager) PrepareMint(tokenTypeId string, mintRequest *types.MintRequest) (*types.MintResponse, error) {
	if err := validateMD5Base64ID(tokenTypeId, "token type"); err != nil {
		return nil, err
	}

	// TODO enforce class

	if mintRequest.Owner == "" {
		return nil, &ErrInvalid{ErrMsg: "missing owner"}
	}
	if mintRequest.Owner == m.config.Users.Custodian.UserID {
		return nil, &ErrInvalid{ErrMsg: fmt.Sprintf("owner cannot be the custodian: %s", m.config.Users.Custodian.UserID)}
	}
	if mintRequest.Owner == m.config.Users.Admin.UserID {
		return nil, &ErrInvalid{ErrMsg: fmt.Sprintf("owner cannot be the admin: %s", m.config.Users.Admin.UserID)}
	}
	if mintRequest.AssetData == "" {
		return nil, &ErrInvalid{ErrMsg: "missing asset data"}
	}

	assetDataId, err := NameToID(mintRequest.AssetData)
	if err != nil {
		return nil, err
	}

	dataTx, err := m.custodianSession.DataTx()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create DataTx")
	}

	tokenDBName := TokenTypeDBNamePrefix + tokenTypeId
	val, meta, err := dataTx.Get(tokenDBName, assetDataId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to Get %s", tokenDBName)
	}
	if val != nil {
		m.lg.Debugf("token already exists: DB: %s, assetId: %s, record: %s, meta: %+v", tokenDBName, assetDataId, string(val), meta)
		return nil, &ErrExist{ErrMsg: "token already exists"}
	}

	record := &types.TokenRecord{
		AssetDataId:   assetDataId,
		Owner:         mintRequest.Owner,
		AssetData:     mintRequest.AssetData,
		AssetMetadata: mintRequest.AssetMetadata,
	}

	val, err = json.Marshal(record)
	if err != nil {
		return nil, errors.Wrap(err, "failed to json.Marshal record")
	}

	err = dataTx.Put(tokenDBName, assetDataId, val,
		&oriontypes.AccessControl{
			ReadWriteUsers: map[string]bool{
				m.config.Users.Custodian.UserID: true,
				mintRequest.Owner:               true,
			},
			SignPolicyForWrite: oriontypes.AccessControl_ALL,
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to Put")
	}

	dataTx.AddMustSignUser(mintRequest.Owner)

	txEnv, err := dataTx.SignConstructedTxEnvelopeAndCloseTx()
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct Tx envelope")
	}

	txEnvBytes, err := proto.Marshal(txEnv)
	if err != nil {
		return nil, errors.Wrap(err, "failed to proto.Marshal Tx envelope")
	}

	payloadBytes, err := json.Marshal(txEnv.(*oriontypes.DataTxEnvelope).Payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to json.Marshal DataTx")
	}
	payloadHash, err := ComputeSHA256Hash(payloadBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute hash of DataTx bytes")
	}

	m.lg.Debugf("Received mint request for token: %+v", record)

	mintResponse := &types.MintResponse{
		TokenId:       tokenTypeId + TokenDBSeparator + assetDataId,
		Owner:         mintRequest.Owner,
		TxEnvelope:    base64.StdEncoding.EncodeToString(txEnvBytes),
		TxPayloadHash: base64.StdEncoding.EncodeToString(payloadHash),
	}

	return mintResponse, nil
}

func (m *Manager) PrepareTransfer(tokenId string, transferRequest *types.TransferRequest) (*types.TransferResponse, error) {
	m.lg.Debugf("Received transfer request: %+v, for tokenId: %s", transferRequest, tokenId)

	tokenTypeId, assetId, err := parseTokenId(tokenId)
	if err != nil {
		return nil, err
	}

	// TODO enforce class

	if transferRequest.NewOwner == "" {
		return nil, &ErrInvalid{ErrMsg: "missing new owner"}
	}
	if transferRequest.NewOwner == m.config.Users.Custodian.UserID {
		return nil, &ErrInvalid{ErrMsg: fmt.Sprintf("new owner cannot be the custodian: %s", m.config.Users.Custodian.UserID)}
	}
	if transferRequest.NewOwner == m.config.Users.Admin.UserID {
		return nil, &ErrInvalid{ErrMsg: fmt.Sprintf("new owner cannot be the admin: %s", m.config.Users.Admin.UserID)}
	}

	dataTx, err := m.custodianSession.DataTx()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create DataTx")
	}
	defer dataTx.Abort()

	tokenDBName := TokenTypeDBNamePrefix + tokenTypeId
	if _, ok := m.tokenTypesDBs[tokenDBName]; !ok {
		return nil, &ErrNotFound{ErrMsg: fmt.Sprintf("token type not found: %s", tokenTypeId)}
	}

	val, meta, err := dataTx.Get(tokenDBName, assetId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to Get %s", tokenDBName)
	}
	if val == nil {
		return nil, &ErrNotFound{ErrMsg: fmt.Sprintf("token not found: %s", tokenId)}
	}

	record := &types.TokenRecord{}
	err = json.Unmarshal(val, record)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to json.Unmarshal %v", val)
	}

	if transferRequest.Owner != record.Owner {
		return nil, &ErrPermission{ErrMsg: fmt.Sprintf("not owner: %s", transferRequest.Owner)}
	}

	m.lg.Debugf("Token: %+v; meta: %+v", record, meta)

	record.Owner = transferRequest.NewOwner
	recordBytes, err := json.Marshal(record)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to json.Marshal %v", record)
	}

	acl := &oriontypes.AccessControl{
		ReadWriteUsers: map[string]bool{
			m.config.Users.Custodian.UserID: true,
			transferRequest.NewOwner:        true,
		},
		SignPolicyForWrite: oriontypes.AccessControl_ALL,
	}

	err = dataTx.Put(tokenDBName, assetId, recordBytes, acl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to Put")
	}

	txEnv, err := dataTx.SignConstructedTxEnvelopeAndCloseTx()
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct Tx envelope")
	}

	txEnvBytes, err := proto.Marshal(txEnv)
	if err != nil {
		return nil, errors.Wrap(err, "failed to proto.Marshal Tx envelope")
	}

	payloadBytes, err := json.Marshal(txEnv.(*oriontypes.DataTxEnvelope).Payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to json.Marshal DataTx")
	}
	payloadHash, err := ComputeSHA256Hash(payloadBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute hash of DataTx bytes")
	}

	transferResponse := &types.TransferResponse{
		TokenId:       tokenId,
		Owner:         transferRequest.Owner,
		NewOwner:      transferRequest.NewOwner,
		TxEnvelope:    base64.StdEncoding.EncodeToString(txEnvBytes),
		TxPayloadHash: base64.StdEncoding.EncodeToString(payloadHash),
	}

	return transferResponse, nil
}

func (m *Manager) SubmitTx(submitRequest *types.SubmitRequest) (*types.SubmitResponse, error) {
	tokenTypeId, assetId, err := parseTokenId(submitRequest.TokenId)
	if err != nil {
		return nil, err
	}

	m.lg.Infof("Custodian [%s] preparing to submit the Tx to the database,  tokenTypeId: %s, assetId: %s, signer: %s",
		m.config.Users.Custodian.UserID, tokenTypeId, assetId, submitRequest.Signer)

	txEnvBytes, err := base64.StdEncoding.DecodeString(submitRequest.TxEnvelope)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode TxEnvelope")
	}

	txEnv := &oriontypes.DataTxEnvelope{}
	err = proto.Unmarshal(txEnvBytes, txEnv)
	if err != nil {
		return nil, errors.Wrap(err, "failed to proto.Unmarshal TxEnvelope")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(submitRequest.Signature)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode Signature")
	}

	txEnv.Signatures[submitRequest.Signer] = sigBytes
	loadedTx, err := m.custodianSession.LoadDataTx(txEnv)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load tx envelope")
	}

	m.lg.Debugf("signed users: %+v", loadedTx.SignedUsers())

	txID, receiptEnv, err := loadedTx.Commit(true)
	if err != nil {
		if strings.Contains(err.Error(), "status: 401 Unauthorized") {
			return nil, &ErrPermission{ErrMsg: err.Error()}
		}

		if errV, ok := err.(*bcdb.ErrorTxValidation); ok {
			switch oriontypes.Flag_value[errV.Flag] {
			case int32(oriontypes.Flag_INVALID_NO_PERMISSION), int32(oriontypes.Flag_INVALID_UNAUTHORISED), int32(oriontypes.Flag_INVALID_MISSING_SIGNATURE):
				return nil, &ErrPermission{ErrMsg: err.Error()}
			default:
				return nil, &ErrInvalid{ErrMsg: err.Error()}
			}
		}

		return nil, err
	}

	m.lg.Infof("Custodian [%s] committed the Tx to the database, txID: %s, receipt: %+v", m.config.Users.Custodian.UserID, txID, receiptEnv.GetResponse().GetReceipt())

	receiptBytes, err := proto.Marshal(receiptEnv)

	return &types.SubmitResponse{
		TokenId:   submitRequest.TokenId,
		TxId:      txID,
		TxReceipt: base64.StdEncoding.EncodeToString(receiptBytes),
	}, nil
}

func (m *Manager) GetToken(tokenId string) (*types.TokenRecord, error) {
	tokenTypeId, assetId, err := parseTokenId(tokenId)
	if err != nil {
		return nil, err
	}

	//TODO enforce class

	dataTx, err := m.custodianSession.DataTx()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create DataTx")
	}
	defer dataTx.Abort()

	tokenDBName := TokenTypeDBNamePrefix + tokenTypeId
	if _, ok := m.tokenTypesDBs[tokenDBName]; !ok {
		return nil, &ErrNotFound{ErrMsg: fmt.Sprintf("token type not found: %s", tokenTypeId)}
	}

	val, meta, err := dataTx.Get(tokenDBName, assetId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to Get %s", tokenDBName)
	}
	if val == nil {
		return nil, &ErrNotFound{ErrMsg: "token not found"}
	}

	record := &types.TokenRecord{}
	err = json.Unmarshal(val, record)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to json.Unmarshal %v", val)
	}

	m.lg.Debugf("Token record: %v; metadata: %+v", record, meta)

	return record, nil
}

func (m *Manager) GetTokensByOwner(tokenTypeId string, owner string) ([]*types.TokenRecord, error) {
	tokenDBName := TokenTypeDBNamePrefix + tokenTypeId
	if _, ok := m.tokenTypesDBs[tokenDBName]; !ok {
		return nil, &ErrNotFound{ErrMsg: fmt.Sprintf("token type not found: %s", tokenTypeId)}
	}

	jq, err := m.custodianSession.Query()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create JSONQuery")
	}

	query := fmt.Sprintf(`{"selector": {"owner": {"$eq": "%s"}}}`, owner)
	results, err := jq.ExecuteJSONQuery(tokenDBName, query)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute JSONQuery")
	}

	var records []*types.TokenRecord
	for _, res := range results {
		record := &types.TokenRecord{}
		err = json.Unmarshal(res.GetValue(), record)
		if err != nil {
			return nil, errors.Wrap(err, "failed to json.Unmarshal JSONQuery result")
		}
		records = append(records, record)
	}

	return records, nil
}

func (m *Manager) GetTokenTypes() ([]*types.DeployResponse, error) {
	jq, err := m.custodianSession.Query()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create JSONQuery")
	}

	query := `{"selector": {"typeId": {"$lte": "~"}}}` //base64 chars are always smaller
	results, err := jq.ExecuteJSONQuery(TypesDBName, query)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute JSONQuery")
	}

	var records []*types.DeployResponse
	for _, res := range results {
		record := &types.DeployResponse{}
		err = json.Unmarshal(res.GetValue(), record)
		if err != nil {
			return nil, errors.Wrap(err, "failed to json.Unmarshal JSONQuery result")
		}
		record.Url = constants.TokensTypesSubTree + record.TypeId
		records = append(records, record)
	}

	return records, nil
}

func (m *Manager) PrepareRegister(tokenTypeId string, registerRequest *types.AnnotationRegisterRequest) (*types.AnnotationRegisterResponse, error) {
	if err := validateMD5Base64ID(tokenTypeId, "token type"); err != nil {
		return nil, err
	}

	// TODO enforce class

	if registerRequest.Owner == "" {
		return nil, &ErrInvalid{ErrMsg: "missing owner"}
	}
	if registerRequest.Owner == m.config.Users.Custodian.UserID {
		return nil, &ErrInvalid{ErrMsg: fmt.Sprintf("owner cannot be the custodian: %s", m.config.Users.Custodian.UserID)}
	}
	if registerRequest.Owner == m.config.Users.Admin.UserID {
		return nil, &ErrInvalid{ErrMsg: fmt.Sprintf("owner cannot be the admin: %s", m.config.Users.Admin.UserID)}
	}
	if registerRequest.AnnotationData == "" {
		return nil, &ErrInvalid{ErrMsg: "missing annotation data"}
	}

	annotDataId, err := NameToID(registerRequest.AnnotationData)
	if err != nil {
		return nil, err
	}

	dataTx, err := m.custodianSession.DataTx()
	if err != nil {
		dataTx.Abort()
		return nil, errors.Wrap(err, "failed to create DataTx")
	}

	tokenDBName := TokenTypeDBNamePrefix + tokenTypeId
	val, meta, err := dataTx.Get(tokenDBName, annotDataId)
	if err != nil {
		dataTx.Abort()
		return nil, errors.Wrapf(err, "failed to Get %s %s", tokenDBName, annotDataId)
	}
	if val != nil {
		m.lg.Debugf("annotation already exists: DB: %s, annotationId: %s, record: %s, meta: %+v", tokenDBName, annotDataId, string(val), meta)
		return nil, &ErrExist{ErrMsg: "token already exists"}
	}

	record := &types.AnnotationRecord{
		AnnotationDataId:   annotDataId,
		Owner:              registerRequest.Owner,
		Link:               registerRequest.Link,
		AnnotationData:     registerRequest.AnnotationData,
		AnnotationMetadata: registerRequest.AnnotationMetadata,
	}

	val, err = json.Marshal(record)
	if err != nil {
		return nil, errors.Wrap(err, "failed to json.Marshal record")
	}

	err = dataTx.Put(tokenDBName, annotDataId, val,
		&oriontypes.AccessControl{ // Read-only
			ReadUsers: map[string]bool{
				m.config.Users.Custodian.UserID: true,
				registerRequest.Owner:           true,
			},
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to Put")
	}

	dataTx.AddMustSignUser(registerRequest.Owner)

	txEnv, err := dataTx.SignConstructedTxEnvelopeAndCloseTx()
	if err != nil {
		return nil, errors.Wrap(err, "failed to construct Tx envelope")
	}

	txEnvBytes, err := proto.Marshal(txEnv)
	if err != nil {
		return nil, errors.Wrap(err, "failed to proto.Marshal Tx envelope")
	}

	payloadBytes, err := json.Marshal(txEnv.(*oriontypes.DataTxEnvelope).Payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to json.Marshal DataTx")
	}
	payloadHash, err := ComputeSHA256Hash(payloadBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute hash of DataTx bytes")
	}

	m.lg.Debugf("Received mint request for token: %+v", record)

	registerResponse := &types.AnnotationRegisterResponse{
		AnnotationId:  tokenTypeId + TokenDBSeparator + annotDataId,
		Owner:         registerRequest.Owner,
		Link:          registerRequest.Link,
		TxEnvelope:    base64.StdEncoding.EncodeToString(txEnvBytes),
		TxPayloadHash: base64.StdEncoding.EncodeToString(payloadHash),
	}

	return registerResponse, nil
}

func (m *Manager) GetAnnotation(tokenId string) (*types.AnnotationRecord, error) {
	tokenTypeId, assetId, err := parseTokenId(tokenId)
	if err != nil {
		return nil, err
	}

	dataTx, err := m.custodianSession.DataTx()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create DataTx")
	}
	defer dataTx.Abort()

	tokenDBName := TokenTypeDBNamePrefix + tokenTypeId
	_, ok := m.tokenTypesDBs[tokenDBName]
	if !ok {
		return nil, &ErrNotFound{ErrMsg: fmt.Sprintf("token type not found: %s", tokenTypeId)}
	}

	//TODO enforce class==ANNOTATIONS

	val, meta, err := dataTx.Get(tokenDBName, assetId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to Get %s", tokenDBName)
	}
	if val == nil {
		return nil, &ErrNotFound{ErrMsg: "token not found"}
	}

	record := &types.AnnotationRecord{}
	err = json.Unmarshal(val, record)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to json.Unmarshal %v", val)
	}

	m.lg.Debugf("Annotation record: %v; metadata: %+v", record, meta)

	return record, nil
}

func (m *Manager) GetAnnotationsByOwnerLink(tokenTypeId string, owner, link string) ([]*types.AnnotationRecord, error) {
	tokenDBName := TokenTypeDBNamePrefix + tokenTypeId
	if _, ok := m.tokenTypesDBs[tokenDBName]; !ok {
		return nil, &ErrNotFound{ErrMsg: fmt.Sprintf("token type not found: %s", tokenTypeId)}
	}

	//TODO enforce class

	jq, err := m.custodianSession.Query()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create JSONQuery")
	}

	var query string
	if owner != "" && link == "" {
		query = fmt.Sprintf(`{"selector": {"owner": {"$eq": "%s"}}}`, owner)
	} else if owner == "" && link != "" {
		query = fmt.Sprintf(`{"selector": {"link": {"$eq": "%s"}}}`, link)
	} else {
		query = fmt.Sprintf(`{"selector": {"$and": {"owner": {"$eq": "%s"}, "link": {"$eq": "%s"}}}}`, owner, link)
	}

	results, err := jq.ExecuteJSONQuery(tokenDBName, query)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute JSONQuery")
	}

	var records []*types.AnnotationRecord
	for _, res := range results {
		record := &types.AnnotationRecord{}
		err = json.Unmarshal(res.GetValue(), record)
		if err != nil {
			return nil, errors.Wrap(err, "failed to json.Unmarshal JSONQuery result")
		}
		records = append(records, record)
	}

	return records, nil
}

func (m *Manager) AddUser(userRecord *types.UserRecord) error {
	m.lg.Debugf("Add user: %v", userRecord)
	return m.writeUser(userRecord, true)
}

func (m *Manager) UpdateUser(userRecord *types.UserRecord) error {
	m.lg.Debugf("Update user: %v", userRecord)
	return m.writeUser(userRecord, false)
}

func (m *Manager) writeUser(userRecord *types.UserRecord, insert bool) error {
	userTx, err := m.adminSession.UsersTx()
	if err != nil {
		return errors.Wrap(err, "failed to create userTx")
	}

	user, err := userTx.GetUser(userRecord.Identity)
	if err != nil {
		userTx.Abort()
		return errors.Wrapf(err, "failed to get user: %s", userRecord.Identity)
	}

	if insert && user != nil {
		userTx.Abort()
		return &ErrExist{"user already exists"}
	}

	if !insert && user == nil {
		userTx.Abort()
		return &ErrNotFound{fmt.Sprintf("user not found: %s", userRecord.Identity)}
	}

	cert, err := base64.StdEncoding.DecodeString(userRecord.Certificate)
	if err != nil {
		return &ErrInvalid{ErrMsg: fmt.Sprintf("failed to decode certificate: %s", err.Error())}
	}

	privilege := &oriontypes.Privilege{
		DbPermission: make(map[string]oriontypes.Privilege_Access),
		Admin:        false,
	}
	// all token types or a partial list
	if len(userRecord.Privilege) == 0 {
		for db, _ := range m.tokenTypesDBs {
			privilege.DbPermission[db] = oriontypes.Privilege_ReadWrite
		}
	} else {
		for _, tt := range userRecord.Privilege {
			db := TokenTypeDBNamePrefix + tt
			if _, ok := m.tokenTypesDBs[db]; !ok {
				return &ErrInvalid{fmt.Sprintf("token type does not exist: %s", tt)}
			}
			privilege.DbPermission[db] = oriontypes.Privilege_ReadWrite
		}
	}
	user = &oriontypes.User{
		Id:          userRecord.Identity,
		Certificate: cert,
		Privilege:   privilege,
	}

	err = userTx.PutUser(user, nil)
	if err != nil {
		userTx.Abort()
		return errors.Wrapf(err, "failed to put user: %s", user.Id)
	}

	txID, receiptEnv, err := userTx.Commit(true)
	if err != nil {
		return errors.Wrap(err, "failed to commit user")
	}

	m.lg.Infof("User [%s] written to database, privilege: %+v; txID: %s, receipt: %+v", user.Id, user.GetPrivilege(), txID, receiptEnv.GetResponse().GetReceipt())

	return nil
}

func (m *Manager) RemoveUser(userId string) error {
	m.lg.Debugf("Removing user: %v", userId)

	userTx, err := m.adminSession.UsersTx()
	if err != nil {
		return errors.Wrap(err, "failed to create userTx")
	}

	user, err := userTx.GetUser(userId)
	if err != nil {
		userTx.Abort()
		return errors.Wrapf(err, "failed to get user: %s", userId)
	}

	if user == nil {
		return &ErrNotFound{ErrMsg: fmt.Sprintf("user not found: %s", userId)}
	}

	err = userTx.RemoveUser(userId)
	if err != nil {
		userTx.Abort()
		return errors.Wrapf(err, "failed to remove user: %s", userId)
	}

	txId, receiptEnv, err := userTx.Commit(true)
	if err != nil {
		return errors.Wrap(err, "failed to commit remove user")
	}

	m.lg.Infof("User [%s] removed from database; txID: %s, receipt: %+v", userId, txId, receiptEnv.GetResponse().GetReceipt())

	return nil
}

func (m *Manager) GetUser(userId string) (*types.UserRecord, error) {
	m.lg.Debugf("Getting user: %v", userId)

	userTx, err := m.adminSession.UsersTx()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create userTx")
	}
	defer userTx.Abort()

	user, err := userTx.GetUser(userId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user: %s", userId)
	}
	if user == nil {
		return nil, &ErrNotFound{fmt.Sprintf("user not found: %s", userId)}
	}

	userRecord := &types.UserRecord{
		Identity:    user.Id,
		Certificate: base64.StdEncoding.EncodeToString(user.Certificate),
		Privilege:   nil,
	}

	for dbName, _ := range user.Privilege.GetDbPermission() {
		tt := dbName[len(TokenTypeDBNamePrefix):]
		userRecord.Privilege = append(userRecord.Privilege, tt)
	}

	return userRecord, nil
}

func nodeConfigToString(n *oriontypes.NodeConfig) string {
	return fmt.Sprintf("Id: %s, Address: %s, Port: %d, Cert-hash: %x", n.Id, n.Address, n.Port, crc32.ChecksumIEEE(n.Certificate))
}

func (m *Manager) createDBInstance() (err error) {
	caPaths := append([]string{}, m.config.Orion.CaConfig.RootCACertsPath...)
	caPaths = append(caPaths, m.config.Orion.CaConfig.IntermediateCACertsPath...)

	connConfig := &sdkconfig.ConnectionConfig{
		ReplicaSet: m.config.Orion.Replicas,
		RootCAs:    caPaths,
		Logger:     m.lg,
	}

	m.bcDB, err = bcdb.Create(connConfig)

	return err
}

func (m *Manager) createAdminSession() (err error) {
	sessionConfig := &sdkconfig.SessionConfig{
		UserConfig:   &m.config.Users.Admin,
		TxTimeout:    m.config.Session.TxTimeout,
		QueryTimeout: m.config.Session.QueryTimeout,
	}

	m.adminSession, err = m.bcDB.Session(sessionConfig)

	return err
}

func (m *Manager) enrollCustodian() (err error) {
	pemUserCert, err := ioutil.ReadFile(m.config.Users.Custodian.CertPath)
	if err != nil {
		return err
	}
	certBlock, _ := pem.Decode(pemUserCert)

	tx, err := m.adminSession.UsersTx()
	if err != nil {
		return err
	}

	user, err := tx.GetUser(m.config.Users.Custodian.UserID)
	if err != nil {
		tx.Abort()
		return err
	}

	if user != nil {
		tx.Abort()
		if bytes.Compare(user.Certificate, certBlock.Bytes) != 0 {
			return errors.New("custodian certificate in DB is different than certificated in config")
		}

		return nil
	}

	err = tx.PutUser(
		&oriontypes.User{
			Id:          m.config.Users.Custodian.UserID,
			Certificate: certBlock.Bytes,
			Privilege: &oriontypes.Privilege{
				DbPermission: map[string]oriontypes.Privilege_Access{
					TypesDBName: oriontypes.Privilege_Read,
				},
				Admin: false,
			},
		},
		nil)

	txID, receiptEnv, err := tx.Commit(true)
	if err != nil {
		m.lg.Errorf("failed enrolling custodian: %s", err)
		return err
	}
	receipt := receiptEnv.GetResponse().GetReceipt()

	m.lg.Infof("Enrolled custodian: %s, txID: %s, receipt: %+v", m.config.Users.Custodian.UserID, txID, receipt)

	return nil
}

func (m *Manager) createCustodianSession() (err error) {
	sessionConfig := &sdkconfig.SessionConfig{
		UserConfig:   &m.config.Users.Custodian,
		TxTimeout:    m.config.Session.TxTimeout,
		QueryTimeout: m.config.Session.QueryTimeout,
	}

	m.custodianSession, err = m.bcDB.Session(sessionConfig)

	return err
}

// the types-DB saves: tokenDBName -> TokenDescription
func (m *Manager) createTypesDB() (err error) {
	tx, err := m.adminSession.DBsTx()
	if err != nil {
		return errors.Wrapf(err, "failed to create %s: failed to create DBsTx", TypesDBName)
	}

	exists, err := tx.Exists(TypesDBName)
	if err != nil {
		tx.Abort()
		return errors.Wrapf(err, "failed to query %s existence", TypesDBName)
	}
	if exists {
		m.lg.Infof("DB: %s, already exists", TypesDBName)
		tx.Abort()
		return nil
	}

	err = tx.CreateDB(TypesDBName,
		map[string]oriontypes.IndexAttributeType{
			"name":   oriontypes.IndexAttributeType_STRING,
			"typeId": oriontypes.IndexAttributeType_STRING,
		})
	if err != nil {
		return errors.Wrapf(err, "failed to CreateDB: %s", TypesDBName)
	}

	txID, receiptEnv, err := tx.Commit(true)

	if err != nil {
		return errors.Wrapf(err, "failed to Commit: %s", TypesDBName)
	}

	m.lg.Infof("Created DB: %s, TxID: %s, receipt: %+v", TypesDBName, txID, receiptEnv.GetResponse().GetReceipt())

	return nil
}
