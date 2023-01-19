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
	"sort"
	"strings"

	"github.com/copa-europe-tokens/internal/common"
	"github.com/copa-europe-tokens/pkg/config"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/hyperledger-labs/orion-sdk-go/pkg/bcdb"
	sdkconfig "github.com/hyperledger-labs/orion-sdk-go/pkg/config"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/hyperledger-labs/orion-server/pkg/marshal"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
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
	GetTokenType(tokenTypeId string) (*types.TokenDescription, error)
	GetTokenTypes() ([]*types.TokenDescription, error)

	// Non fungible token type (NFT) API

	PrepareMint(tokenTypeId string, mintRequest *types.MintRequest) (*types.MintResponse, error)
	PrepareTransfer(tokenId string, transferRequest *types.TransferRequest) (*types.TransferResponse, error)
	PrepareUpdate(tokenId string, updateRequest *types.UpdateRequest) (*types.UpdateResponse, error)
	SubmitTx(submitRequest *types.SubmitRequest) (*types.SubmitResponse, error)
	GetToken(tokenId string) (*types.TokenRecord, error)
	GetTokensByFilter(tokenTypeId, owner, link, reference string) ([]*types.TokenRecord, error)

	// Annotations API

	PrepareRegister(tokenTypeId string, registerRequest *types.AnnotationRegisterRequest) (*types.AnnotationRegisterResponse, error)
	GetAnnotation(tokenId string) (*types.AnnotationRecord, error)
	GetAnnotationsByFilter(tokenTypeId, owner, link, reference string) ([]*types.AnnotationRecord, error)

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
	FungibleMovements(typeId string, owner string, limit int64, startToken string) (*types.FungibleMovementsResponse, error)

	// Rights Offer API

	RightsOfferMint(typeId string, request *types.RightsOfferMintRequest) (*types.RightsOfferMintResponse, error)
	RightsOfferUpdate(offerId string, request *types.RightsOfferUpdateRequest) (*types.RightsOfferUpdateResponse, error)
	RightsOfferBuy(offerId string, request *types.RightsOfferBuyRequest) (*types.RightsOfferBuyResponse, error)
	RightsOfferSubmitTx(submitRequest *types.RightsOfferSubmitRequest) (*types.RightsOfferSubmitResponse, error)
	RightsOfferGet(offerId string) (*types.RightsOfferRecord, error)
	RightsOfferQuery(typeId string, owner string, asset string) ([]types.RightsOfferRecord, error)
}

// TODO handle ServerTimeout on Commit

type Manager struct {
	config *config.Configuration
	lg     *logger.SugarLogger

	bcDB             bcdb.BCDB
	adminSession     bcdb.DBSession
	custodianSession bcdb.DBSession

	//TODO support multiple instances of the token server
	tokenTypesDBs map[string]bool
}

func abort(ctx bcdb.TxContext) {
	if ctx != nil {
		_ = ctx.Abort()
	}
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

// ====================================================
// Management API
// ====================================================

func (m *Manager) Close() error {
	//TODO
	return nil
}

func (m *Manager) GetStatus() (string, error) {
	tx, err := m.adminSession.ConfigTx()
	if err != nil {
		return "", errors.Wrap(err, "failed to get status")
	}
	clusterConfig, err := tx.GetClusterConfig()
	if err != nil {
		return "", errors.Wrap(err, "failed to get status")
	}

	b := strings.Builder{}
	b.WriteString("{")
	for i, n := range clusterConfig.Nodes {
		b.WriteString(nodeConfigToString(n))
		if i < len(clusterConfig.Nodes)-1 {
			b.WriteString("; ")
		}
	}
	b.WriteString("}")
	return fmt.Sprintf("connected: %s", b.String()), nil
}

// ====================================================
// Generic token helpers
// ====================================================

func (m *Manager) deployNewTokenType(desc *types.TokenDescription, indices ...string) error {
	if desc.Name == "" {
		return common.NewErrInvalid("token type name is empty")
	}

	// Compute TypeId
	tokenTypeIDBase64, err := NameToID(desc.Name)
	if err != nil {
		return errors.Wrap(err, "failed to compute hash of token type name")
	}
	tokenDBName := TokenTypeDBNamePrefix + tokenTypeIDBase64
	desc.TypeId = tokenTypeIDBase64

	// Check existence by looking into the custodian privileges
	userTx, err := m.adminSession.UsersTx()
	if err != nil {
		return errors.Wrap(err, "failed to create UsersTx")
	}
	defer abort(userTx)

	custodian, _, err := userTx.GetUser(m.config.Users.Custodian.UserID)
	if err != nil {
		return wrapOrionError(err, "failed to get user [%s]", m.config.Users.Custodian.UserID)
	}
	if _, exists := custodian.GetPrivilege().GetDbPermission()[tokenDBName]; exists {
		return common.NewErrExist("Token type already exists")
	}

	// Save token description to Types-DB
	dataTx, err := m.adminSession.DataTx()
	if err != nil {
		return errors.Wrap(err, "failed to create DataTx")
	}
	defer abort(dataTx)

	existingTokenDesc, _, err := dataTx.Get(TypesDBName, tokenDBName)
	if err != nil {
		return wrapOrionError(err, "failed to get key [%s] from [%s]", tokenDBName, TypesDBName)
	}
	if existingTokenDesc != nil {
		return errors.Errorf("failed to deploy token: custodian does not have privilege, but token type description exists: %s", string(existingTokenDesc))
	}

	serializedDescription, err := json.Marshal(desc)
	if err != nil {
		m.lg.Panicf("failed to json.Marshal description: %s", err)
		return err
	}
	err = dataTx.Put(TypesDBName, tokenDBName, serializedDescription, nil)
	if err != nil {
		return wrapOrionError(err, "failed to put key [%s] to [%s]", tokenDBName, TypesDBName)
	}

	txID, receiptEnv, err := dataTx.Commit(true)
	if err != nil {
		return wrapOrionError(err, "failed to commit [%s] to [%s]", tokenDBName, TypesDBName)
	}

	m.lg.Infof("Saved token description: %+v; txID: %s, receipt: %+v", desc, txID, receiptEnv.GetResponse().GetReceipt())

	if err = m.createTokenDBTable(tokenDBName, indices...); err != nil {
		return err
	}

	// Add privilege to custodian
	custodian.Privilege.DbPermission[tokenDBName] = oriontypes.Privilege_ReadWrite

	err = userTx.PutUser(custodian, nil)
	if err != nil {
		return wrapOrionError(err, "failed to put user [%s]", m.config.Users.Custodian.UserID)
	}

	txID, receiptEnv, err = userTx.Commit(true)
	if err != nil {
		return wrapOrionError(err, "failed to commit user [%s]", m.config.Users.Custodian.UserID)
	}

	m.tokenTypesDBs[tokenDBName] = true
	m.lg.Infof("Custodian [%s] granted RW privilege to database: %s; description: %s, txID: %s, receipt: %+v", m.config.Users.Custodian.UserID, desc, tokenDBName, txID, receiptEnv.GetResponse().GetReceipt())

	return nil
}

func (m *Manager) createTokenDBTable(tokenDBName string, indices ...string) error {
	dBsTx, err := m.adminSession.DBsTx()
	if err != nil {
		return errors.Wrap(err, "failed to create DBsTx")
	}
	defer abort(dBsTx)

	exists, err := dBsTx.Exists(tokenDBName)
	if err != nil {
		return errors.Wrap(err, "failed to query DB existence")
	}
	if exists {
		return errors.Errorf("failed to deploy token: custodian does not have privilege, but token database exists: %s", tokenDBName)
	}

	index := make(map[string]oriontypes.IndexAttributeType)
	for _, ind := range indices {
		index[ind] = oriontypes.IndexAttributeType_STRING
	}
	err = dBsTx.CreateDB(tokenDBName, index)
	if err != nil {
		return errors.Wrap(err, "failed to build DBsTx")
	}

	txID, receiptEnv, err := dBsTx.Commit(true)
	if err != nil {
		m.lg.Errorf("Failed to deploy: commit failed: %s", err.Error())
		return wrapOrionError(err, "failed to deploy token type [%s]", tokenDBName)
	}

	m.lg.Infof("Database created: %s, txID: %s, receipt: %+v", tokenDBName, txID, receiptEnv.GetResponse().GetReceipt())
	return nil
}

// ====================================================
// NFT functional API implementation
// ====================================================

func (m *Manager) DeployTokenType(deployRequest *types.DeployRequest) (*types.DeployResponse, error) {
	var indices []string
	switch deployRequest.Class {
	case "": //backward compatibility
		deployRequest.Class = constants.TokenClass_NFT
		fallthrough
	case constants.TokenClass_NFT, constants.TokenClass_ANNOTATIONS:
		indices = []string{"owner", "link", "reference"}
	case constants.TokenClass_RIGHTS_OFFER:
		indices = []string{"owner", "asset"}
	case constants.TokenClass_FUNGIBLE:
		return nil, &ErrInvalid{ErrMsg: fmt.Sprintf("Class is not supported via this API call: %s", deployRequest.Class)}
	default:
		return nil, &ErrInvalid{ErrMsg: fmt.Sprintf("unsupported token class: %s", deployRequest.Class)}
	}

	tokenDesc := types.TokenDescription{
		Name:        deployRequest.Name,
		Description: deployRequest.Description,
		Class:       deployRequest.Class,
	}

	if err := m.deployNewTokenType(&tokenDesc, indices...); err != nil {
		return nil, convertErrorType(err)
	}

	return &types.DeployResponse{
		TypeId:      tokenDesc.TypeId,
		Name:        tokenDesc.Name,
		Class:       tokenDesc.Class,
		Description: tokenDesc.Description,
		Url:         constants.TokensTypesSubTree + tokenDesc.TypeId,
	}, nil
}

func (m *Manager) GetTokenType(tokenTypeId string) (*types.TokenDescription, error) {
	if err := validateMD5Base64ID(tokenTypeId, "token type"); err != nil {
		return nil, convertErrorType(err)
	}

	dataTx, err := m.custodianSession.DataTx()
	defer abort(dataTx)
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

	desc := &types.TokenDescription{}
	err = json.Unmarshal(val, desc)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to json.Unmarshal %s", tokenDBName)
	}
	desc.Url = constants.TokensTypesSubTree + desc.TypeId

	m.lg.Debugf("Token type deploy response: %+v; metadata: %v", desc, meta)

	return desc, nil
}

func (m *Manager) PrepareMint(tokenTypeId string, mintRequest *types.MintRequest) (*types.MintResponse, error) {
	// TODO enforce class

	ctx, err := newTxContext(m).tokenType(tokenTypeId)
	if err != nil {
		return nil, err
	}
	defer ctx.Abort()

	tokenCtx, err := ctx.asset(mintRequest.AssetData)
	if err != nil {
		return nil, err
	}
	record, err := tokenCtx.mint(mintRequest.Owner, mintRequest.AssetMetadata, mintRequest.Link, mintRequest.Reference)
	if err != nil {
		return nil, convertErrorType(err)
	}

	if err := ctx.Prepare(); err != nil {
		return nil, convertErrorType(err)
	}

	m.lg.Debugf("Received mint request for token: %+v", record)

	return &types.MintResponse{
		TokenId:       tokenCtx.tokenId,
		Owner:         mintRequest.Owner,
		TxEnvelope:    tokenCtx.GetTxEnvelope(),
		TxPayloadHash: tokenCtx.GetTxPayloadHash(),
	}, nil
}

func (m *Manager) PrepareTransfer(tokenId string, transferRequest *types.TransferRequest) (*types.TransferResponse, error) {
	m.lg.Debugf("Received transfer request: %+v, for tokenId: %s", transferRequest, tokenId)

	tokenTypeId, assetId, err := parseTokenId(tokenId)
	if err != nil {
		return nil, convertErrorType(err)
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

	payloadBytes, err := marshal.DefaultMarshaler().Marshal(txEnv.(*oriontypes.DataTxEnvelope).Payload)
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

func (m *Manager) PrepareUpdate(tokenId string, updateRequest *types.UpdateRequest) (*types.UpdateResponse, error) {
	m.lg.Debugf("Received update request: %+v, for tokenId: %s", updateRequest, tokenId)

	tokenTypeId, assetId, err := parseTokenId(tokenId)
	if err != nil {
		return nil, convertErrorType(err)
	}

	// TODO enforce class

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

	if updateRequest.Owner != record.Owner {
		return nil, &ErrPermission{ErrMsg: fmt.Sprintf("not owner: %s", updateRequest.Owner)}
	}

	m.lg.Debugf("Token: %+v; meta: %+v", record, meta)
	m.lg.Debugf("Token: %+v; updating asset metadata from: [%s] to: [%s]", record, record.AssetMetadata, updateRequest.AssetMetadata)

	record.AssetMetadata = updateRequest.AssetMetadata

	recordBytes, err := json.Marshal(record)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to json.Marshal %v", record)
	}

	err = dataTx.Put(tokenDBName, assetId, recordBytes, meta.AccessControl)
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

	payloadBytes, err := marshal.DefaultMarshaler().Marshal(txEnv.(*oriontypes.DataTxEnvelope).Payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to json.Marshal DataTx")
	}
	payloadHash, err := ComputeSHA256Hash(payloadBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute hash of DataTx bytes")
	}

	updateResponse := &types.UpdateResponse{
		TokenId:       tokenId,
		Owner:         updateRequest.Owner,
		AssetMetadata: updateRequest.AssetMetadata,
		TxEnvelope:    base64.StdEncoding.EncodeToString(txEnvBytes),
		TxPayloadHash: base64.StdEncoding.EncodeToString(payloadHash),
	}

	return updateResponse, nil
}

func (m *Manager) SubmitTx(submitRequest *types.SubmitRequest) (*types.SubmitResponse, error) {
	tokenTypeId, assetId, err := parseTokenId(submitRequest.TokenId)
	if err != nil {
		return nil, convertErrorType(err)
	}

	m.lg.Infof("Custodian [%s] preparing to submit the Tx to the database,  tokenTypeId: %s, assetId: %s, signer: %s",
		m.config.Users.Custodian.UserID, tokenTypeId, assetId, submitRequest.Signer)

	ctx := submitContextFromNFT(submitRequest)
	if err := m.submitTx(ctx); err != nil {
		return nil, convertErrorType(err)
	}
	return ctx.ToNFTResponse(), nil
}

func (m *Manager) submitTx(ctx *SubmitContext) error {
	m.lg.Infof("Custodian [%s] preparing to submit TX to the database, context: %s, signer: %s",
		m.config.Users.Custodian.UserID, ctx.TxContext, ctx.Signer)

	txEnvBytes, err := base64.StdEncoding.DecodeString(ctx.TxEnvelope)
	if err != nil {
		return errors.Wrap(err, "failed to decode TxEnvelope")
	}

	txEnv := &oriontypes.DataTxEnvelope{}
	err = proto.Unmarshal(txEnvBytes, txEnv)
	if err != nil {
		return errors.Wrap(err, "failed to proto.Unmarshal TxEnvelope")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(ctx.Signature)
	if err != nil {
		return errors.Wrap(err, "failed to decode Signature")
	}

	txEnv.Signatures[ctx.Signer] = sigBytes
	loadedTx, err := m.custodianSession.LoadDataTx(txEnv)
	if err != nil {
		return errors.Wrap(err, "failed to load tx envelope")
	}

	m.lg.Debugf("signed users: %+v", loadedTx.SignedUsers())

	txID, receiptEnv, err := loadedTx.Commit(true)
	if err != nil {
		return wrapOrionError(err, "failed to submit transaction for %s", ctx.TxContext)
	}

	m.lg.Infof("Custodian [%s] committed the Tx to the database, txID: %s, receipt: %+v", m.config.Users.Custodian.UserID, txID, receiptEnv.GetResponse().GetReceipt())

	receiptBytes, err := proto.Marshal(receiptEnv)
	if err != nil {
		return err
	}

	ctx.TxId = txID
	ctx.TxReceipt = base64.StdEncoding.EncodeToString(receiptBytes)

	return nil
}

func (m *Manager) GetToken(tokenId string) (*types.TokenRecord, error) {
	tokenTypeId, assetId, err := parseTokenId(tokenId)
	if err != nil {
		return nil, convertErrorType(err)
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

func (m *Manager) GetTokensByFilter(tokenTypeId string, owner, link, reference string) ([]*types.TokenRecord, error) {
	ctx, err := newTxContext(m).tokenType(tokenTypeId)
	if err != nil {
		return nil, convertErrorType(err)
	}
	defer ctx.Abort()

	results, err := ctx.Query(map[string]string{
		"owner":     owner,
		"link":      link,
		"reference": reference,
	})
	if err != nil {
		return nil, convertErrorType(err)
	}

	records := make([]*types.TokenRecord, len(results))
	for i, res := range results {
		if err = json.Unmarshal(res.GetValue(), &records[i]); err != nil {
			return nil, errors.Wrap(err, "failed to json.Unmarshal JSONQuery result")
		}
	}
	return records, nil
}

// ====================================================
// Generic tokens API (cont.)
// ====================================================

func (m *Manager) GetTokenTypes() ([]*types.TokenDescription, error) {
	jq, err := m.custodianSession.Query()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create JSONQuery")
	}

	query := `{"selector": {"typeId": {"$lte": "~"}}}` //base64 chars are always smaller
	results, err := jq.ExecuteJSONQuery(TypesDBName, query)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute JSONQuery")
	}

	var records []*types.TokenDescription
	for _, res := range results {
		record := &types.TokenDescription{}
		err = json.Unmarshal(res.GetValue(), record)
		if err != nil {
			return nil, errors.Wrap(err, "failed to json.Unmarshal JSONQuery result")
		}
		record.Url = constants.TokensTypesSubTree + record.TypeId
		records = append(records, record)
	}

	return records, nil
}

// ====================================================
// Annotations API
// ====================================================

func (m *Manager) PrepareRegister(tokenTypeId string, registerRequest *types.AnnotationRegisterRequest) (*types.AnnotationRegisterResponse, error) {
	if err := validateMD5Base64ID(tokenTypeId, "token type"); err != nil {
		return nil, convertErrorType(err)
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
		Reference:          registerRequest.Reference,
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

	payloadBytes, err := marshal.DefaultMarshaler().Marshal(txEnv.(*oriontypes.DataTxEnvelope).Payload)
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
		Reference:     registerRequest.Reference,
		TxEnvelope:    base64.StdEncoding.EncodeToString(txEnvBytes),
		TxPayloadHash: base64.StdEncoding.EncodeToString(payloadHash),
	}

	return registerResponse, nil
}

func (m *Manager) GetAnnotation(tokenId string) (*types.AnnotationRecord, error) {
	tokenTypeId, assetId, err := parseTokenId(tokenId)
	if err != nil {
		return nil, convertErrorType(err)
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

func (m *Manager) GetAnnotationsByFilter(tokenTypeId, owner, link, reference string) ([]*types.AnnotationRecord, error) {
	// TODO enforce class
	ctx, err := newTxContext(m).tokenType(tokenTypeId)
	if err != nil {
		return nil, convertErrorType(err)
	}
	defer ctx.Abort()

	results, err := ctx.Query(map[string]string{
		"owner":     owner,
		"link":      link,
		"reference": reference,
	})
	if err != nil {
		return nil, convertErrorType(err)
	}
	defer ctx.Abort()

	records := make([]*types.AnnotationRecord, len(results))
	for i, res := range results {
		if err = json.Unmarshal(res.GetValue(), &records[i]); err != nil {
			return nil, errors.Wrap(err, "failed to json.Unmarshal JSONQuery result")
		}
	}
	return records, nil
}

// ====================================================
// Users API
// ====================================================

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

	user, _, err := userTx.GetUser(userRecord.Identity)
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

	user, _, err := userTx.GetUser(userId)
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

	user, _, err := userTx.GetUser(userId)
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

// ====================================================
// Generic tokens Helpers
// ====================================================

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
	defer abort(tx)

	user, _, err := tx.GetUser(m.config.Users.Custodian.UserID)
	if err != nil {
		return err
	}

	if user != nil {
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
	defer abort(tx)

	exists, err := tx.Exists(TypesDBName)
	if err != nil {
		return errors.Wrapf(err, "failed to query %s existence", TypesDBName)
	}
	if exists {
		m.lg.Infof("DB: %s, already exists", TypesDBName)
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

func (m *Manager) validateUserId(userId string) error {
	if userId == "" {
		return common.NewErrInvalid("Invalid user ID: empty.")
	}

	if userId == m.config.Users.Custodian.UserID || userId == m.config.Users.Admin.UserID {
		return common.NewErrInvalid("Invalid user ID: the user '%s' cannot participate in token activities.", userId)
	}

	return nil
}

// ====================================================
// Fungible functional API implementation
// ====================================================

func (m *Manager) FungibleDeploy(request *types.FungibleDeployRequest) (*types.FungibleDeployResponse, error) {
	// Validates user to avoid creating a token with an invalid owner
	userCtx, err := newUserTxContext(m, request.ReserveOwner)
	if err != nil {
		return nil, err
	}
	defer userCtx.Abort()
	if err = userCtx.ValidateUserExists(); err != nil {
		return nil, err
	}

	desc := types.TokenDescription{
		Name:        request.Name,
		Description: request.Description,
		Class:       constants.TokenClass_FUNGIBLE,
		Extension: map[string]string{
			"reserveOwner": request.ReserveOwner,
		},
	}
	if err = m.deployNewTokenType(&desc, "owner", "account"); err != nil {
		return nil, err
	}

	if err = userCtx.AddPrivilege(desc.TypeId); err != nil {
		return nil, err
	}
	if err = userCtx.Commit(); err != nil {
		return nil, err
	}

	return &types.FungibleDeployResponse{
		TypeId:       desc.TypeId,
		Name:         desc.Name,
		Description:  desc.Description,
		ReserveOwner: request.ReserveOwner,
		Supply:       0,
		Url:          FungibleTypeURL(desc.TypeId),
	}, nil
}

func (m *Manager) FungibleDescribe(typeId string) (*types.FungibleDescribeResponse, error) {
	ctx, err := newTxContext(m).fungible(typeId)
	if err != nil {
		return nil, err
	}
	defer ctx.Abort()

	desc, err := ctx.getDescription()
	if err != nil {
		return nil, err
	}

	reserve, err := ctx.getReserveAccount()
	if err != nil {
		return nil, err
	}

	reserveOwner, err := ctx.getReserveOwner()
	if err != nil {
		return nil, err
	}

	return &types.FungibleDescribeResponse{
		TypeId:       desc.TypeId,
		Name:         desc.Name,
		Description:  desc.Description,
		ReserveOwner: reserveOwner,
		Supply:       reserve.Supply,
		Url:          FungibleTypeURL(desc.TypeId),
	}, nil
}

func (m *Manager) FungiblePrepareMint(typeId string, request *types.FungibleMintRequest) (*types.FungibleMintResponse, error) {
	if request.Supply == 0 {
		return nil, common.NewErrInvalid("Supply must be a positive integer (supply > 0).")
	}

	ctx, err := newTxContext(m).fungible(typeId)
	if err != nil {
		return nil, err
	}
	defer ctx.Abort()

	reserve, err := ctx.getReserveAccount()
	if err != nil {
		return nil, err
	}

	reserve.Balance += request.Supply
	reserve.Supply += request.Supply

	if err = ctx.putReserveAccount(reserve); err != nil {
		return nil, err
	}

	if err = ctx.Prepare(); err != nil {
		return nil, err
	}
	m.lg.Debugf("Processed mint request for token: %s", ctx.typeId)

	return &types.FungibleMintResponse{
		TypeId:        typeId,
		TxEnvelope:    ctx.GetTxEnvelope(),
		TxPayloadHash: ctx.GetTxPayloadHash(),
	}, nil
}

func (m *Manager) FungiblePrepareTransfer(typeId string, request *types.FungibleTransferRequest) (*types.FungibleTransferResponse, error) {
	ctx, err := newTxContext(m).fungible(typeId)
	if err != nil {
		return nil, err
	}
	defer ctx.Abort()

	// If account isn't specified, the main account is used
	if request.Account == "" {
		request.Account = mainAccount
	}

	newRecord, err := ctx.transfer(request.Owner, request.Account, request.NewOwner, request.Quantity, request.Comment)
	if err != nil {
		return nil, err
	}
	if err = ctx.Prepare(); err != nil {
		return nil, err
	}

	return &types.FungibleTransferResponse{
		TypeId:        ctx.typeId,
		Owner:         request.Owner,
		Account:       request.Account,
		NewOwner:      newRecord.Owner,
		NewAccount:    newRecord.Account,
		TxEnvelope:    ctx.GetTxEnvelope(),
		TxPayloadHash: ctx.GetTxPayloadHash(),
	}, nil
}

func (m *Manager) FungiblePrepareConsolidate(typeId string, request *types.FungibleConsolidateRequest) (*types.FungibleConsolidateResponse, error) {
	ctx, err := newTxContext(m).fungible(typeId)
	if err != nil {
		return nil, err
	}
	defer ctx.Abort()

	// We don't need to validate the user since an invalid user will not have any accounts anyway.

	if request.Accounts != nil {
		// Validate the list before the TX starts.
		if len(request.Accounts) == 0 {
			return nil, common.NewErrInvalid("If an account list is specified, it must have at least one account.")
		}

		for _, accName := range request.Accounts {
			if accName == "" {
				return nil, common.NewErrInvalid("Account name cannot be empty")
			} else if accName == mainAccount {
				return nil, common.NewErrInvalid("The main account cannot be consolidated")
			}
		}
	} else {
		// We query all user's accounts before the TX starts.
		// Yet, we need to read all records again inside the TX context, so it will be included in the read-set.
		records, err := ctx.queryAccounts(request.Owner, "")
		if err != nil {
			return nil, err
		}

		for _, record := range records {
			if record.Account == mainAccount {
				continue
			}
			request.Accounts = append(request.Accounts, record.Account)
		}

		if len(request.Accounts) == 0 {
			return nil, common.NewErrNotFound("Did not found accounts to consolidate for user [%s]", request.Owner)
		}
	}

	rawMainRecord, existed, err := ctx.getAccountRecordRaw(request.Owner, mainAccount)
	if err != nil {
		return nil, err
	}

	var mainRecord *types.FungibleAccountRecord
	if !existed {
		mainRecord = &types.FungibleAccountRecord{
			Account: mainAccount,
			Owner:   request.Owner,
			Balance: 0,
			Comment: mainAccount,
		}
	} else {
		mainRecord, err = unmarshalAccountRecord(rawMainRecord)
		if err != nil {
			return nil, err
		}
	}

	for _, accName := range request.Accounts {
		accRecord, err := ctx.getAccountRecord(request.Owner, accName)
		if err != nil {
			return nil, err
		}

		mainRecord.Balance += accRecord.Balance

		if err = ctx.deleteAccountRecord(accRecord); err != nil {
			return nil, err
		}
	}

	if err = ctx.putAccountRecord(mainRecord); err != nil {
		return nil, err
	}

	if err = ctx.Prepare(); err != nil {
		return nil, err
	}

	return &types.FungibleConsolidateResponse{
		TypeId:        typeId,
		Owner:         request.Owner,
		TxEnvelope:    ctx.GetTxEnvelope(),
		TxPayloadHash: ctx.GetTxPayloadHash(),
	}, nil
}

func (m *Manager) FungibleSubmitTx(submitRequest *types.FungibleSubmitRequest) (*types.FungibleSubmitResponse, error) {
	ctx := submitContextFromFungible(submitRequest)
	if err := m.submitTx(ctx); err != nil {
		return nil, err
	}
	return ctx.ToFungibleResponse(), nil
}

func (m *Manager) FungibleAccounts(typeId string, owner string, account string) ([]types.FungibleAccountRecord, error) {
	ctx, err := newTxContext(m).fungible(typeId)
	if err != nil {
		return nil, err
	}
	defer ctx.Abort()
	return ctx.queryAccounts(owner, account)
}

func (m *Manager) FungibleMovements(typeId string, owner string, limit int64, startToken string) (*types.FungibleMovementsResponse, error) {
	ctx, err := newTxContext(m).fungible(typeId)
	if err != nil {
		return nil, err
	}
	defer ctx.Abort()
	if err := ctx.validateTokenType(constants.TokenClass_FUNGIBLE, "type ID"); err != nil {
		return nil, err
	}

	start := MovementStartPosition{}
	if err := start.Unmarshal(startToken); err != nil {
		return nil, common.NewErrInvalid("invalid start token: %s.", err)
	}

	ptx, err := m.adminSession.Provenance()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create provenance TX")
	}
	mainAccountKey := getAccountKey(owner, mainAccount)
	allHistory, err := ptx.GetHistoricalData(ctx.dbName, mainAccountKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read account's historical data")
	}

	// We sort the values from newest to oldest (the highest version is first)
	sort.SliceStable(allHistory, func(i, j int) bool {
		return versionCompare(allHistory[i].Metadata.Version, allHistory[j].Metadata.Version) > 0
	})

	var history []*oriontypes.ValueWithMetadata
	for i, v := range allHistory {
		if start.Compare(v.Metadata.Version) > 0 {
			history = allHistory[i:]
			break
		}
	}

	var movements []types.FungibleMovementRecord
	for _, v := range history {
		if limit > 0 && int64(len(movements)) >= limit {
			break
		}

		mainRecord, err := unmarshalAccountRecord(v.Value)
		if err != nil {
			return nil, err
		}

		ver := v.Metadata.Version
		movement := types.FungibleMovementRecord{
			Version: types.TxVersion{
				BlockNum: ver.BlockNum,
				TxNum:    ver.TxNum,
			},
			MainBalance: mainRecord.Balance,
		}

		op, err := ctx.getMovementTxOperations(owner, ver)
		if err != nil {
			return nil, err
		}

		if op.ownerRead[mainAccountKey] == nil || op.ownerWrite[mainAccountKey] == nil {
			return nil, common.NewErrInternal("movement TX referred to a data tx that do not update the main account: %+v", op)
		}

		// Outgoing transfers
		for accKey, o := range op.otherWrite {
			accRecord, err := unmarshalAccountRecord(o.Value)
			if err != nil {
				return nil, err
			}
			movement.DestinationAccounts = append(movement.DestinationAccounts, types.FungibleOutgoingTxAccountRecord{
				Account:  accKey,
				Quantity: accRecord.Balance,
				Comment:  accRecord.Comment,
			})
		}

		// Consolidation
		for incomingKey := range op.ownerDelete {
			o, ok := op.ownerRead[incomingKey]
			if !ok {
				return nil, common.NewErrInternal("movement TX identified as consolidation, but referred to a data tx that deletes account without reading it")
			}
			incomingVer := o.Version
			incomingOp, err := ctx.getMovementTxOperations(owner, incomingVer)
			if err != nil {
				return nil, err
			}
			if len(incomingOp.otherRead) != 1 {
				return nil, common.NewErrInternal("movement TX identified as consolidation, but referred to a data tx that read more/less than one non owner account")
			}
			accWrite, ok := incomingOp.ownerWrite[incomingKey]
			if !ok {
				return nil, common.NewErrInternal("consolidation TX read version incorrect")
			}
			accRecord, err := unmarshalAccountRecord(accWrite.Value)
			if err != nil {
				return nil, err
			}
			var sourceOwner string
			for sourceKey := range incomingOp.otherRead {
				sourceOwner, _ = splitAccountKey(sourceKey)
			}
			movement.SourceAccounts = append(movement.SourceAccounts, types.FungibleIncomingTxAccountRecord{
				Version: types.TxVersion{
					BlockNum: incomingVer.BlockNum,
					TxNum:    incomingVer.TxNum,
				},
				Account:     incomingKey,
				Quantity:    accRecord.Balance,
				Comment:     accRecord.Comment,
				SourceOwner: sourceOwner,
			})
		}

		movements = append(movements, movement)
		start.Version = ver
	}

	if len(movements) == len(history) {
		start.Version = nil
	}

	nextStartToken, err := start.Marshal()
	if err != nil {
		return nil, err
	}
	return &types.FungibleMovementsResponse{
		TypeId:         typeId,
		Owner:          owner,
		Movements:      movements,
		NextStartToken: nextStartToken,
	}, nil
}

// ====================================================
// Rights Offer functional API implementation
// ====================================================

func (m *Manager) RightsOfferMint(typeId string, request *types.RightsOfferMintRequest) (*types.RightsOfferMintResponse, error) {
	ctx := newTxContext(m)
	defer ctx.Abort()

	if request.Name == "" {
		return nil, common.NewErrInvalid("Offer's name cannot be empty.")
	}

	assetCtx, err := ctx.token(request.Asset)
	if err != nil {
		return nil, err
	}
	assetDesc, err := assetCtx.GetToken()
	if err != nil {
		return nil, err
	}
	if err := assetCtx.validateTokenType(constants.TokenClass_NFT, "asset"); err != nil {
		return nil, err
	}
	if assetDesc.Owner != request.Owner {
		return nil, common.NewErrInvalid("Offer's owner must own the asset.")
	}

	rightsCtx, err := ctx.tokenType(request.Rights)
	if err != nil {
		return nil, err
	}
	if err := rightsCtx.validateTokenType(constants.TokenClass_NFT, "rights"); err != nil {
		return nil, err
	}

	priceCtx, err := ctx.fungible(request.Currency)
	if err != nil {
		return nil, err
	}
	if err := priceCtx.validateTokenType(constants.TokenClass_FUNGIBLE, "price"); err != nil {
		return nil, err
	}

	offerTypeCtx, err := ctx.offerType(typeId)
	if err != nil {
		return nil, err
	}
	if err := offerTypeCtx.validateTokenType(constants.TokenClass_RIGHTS_OFFER, "type ID"); err != nil {
		return nil, err
	}
	offerCtx, err := offerTypeCtx.offerName(request.Name)
	if err != nil {
		return nil, err
	}
	record := &types.RightsOfferRecord{
		OfferId:  offerCtx.tokenId,
		Name:     request.Name,
		Owner:    request.Owner,
		Asset:    request.Asset,
		Rights:   request.Rights,
		Template: request.Template,
		Price:    request.Price,
		Currency: request.Currency,
		Enabled:  true,
	}
	if err := offerCtx.putOfferRecord(record); err != nil {
		return nil, err
	}
	if err := ctx.Prepare(); err != nil {
		return nil, err
	}
	return &types.RightsOfferMintResponse{
		OfferId:       offerCtx.tokenId,
		TxEnvelope:    ctx.GetTxEnvelope(),
		TxPayloadHash: ctx.GetTxPayloadHash(),
	}, nil
}

func (m *Manager) RightsOfferUpdate(offerId string, request *types.RightsOfferUpdateRequest) (*types.RightsOfferUpdateResponse, error) {
	ctx, err := newTxContext(m).offer(offerId)
	if err != nil {
		return nil, err
	}
	defer ctx.Abort()
	if err := ctx.validateTokenType(constants.TokenClass_RIGHTS_OFFER, "offerId"); err != nil {
		return nil, err
	}
	record, err := ctx.getOfferRecord()
	if err != nil {
		return nil, err
	}

	if record.Enabled == request.Enable {
		return nil, common.NewErrInvalid("the offer state was not changed - enabled: %t", record.Enabled)
	}

	record.Enabled = request.Enable
	if err := ctx.putOfferRecord(record); err != nil {
		return nil, err
	}
	if err := ctx.Prepare(); err != nil {
		return nil, err
	}
	return &types.RightsOfferUpdateResponse{
		OfferId:       ctx.tokenId,
		TxEnvelope:    ctx.GetTxEnvelope(),
		TxPayloadHash: ctx.GetTxPayloadHash(),
	}, nil
}

func (m *Manager) RightsOfferBuy(offerId string, request *types.RightsOfferBuyRequest) (*types.RightsOfferBuyResponse, error) {
	ctx := newTxContext(m)
	defer ctx.Abort()

	offerCtx, err := ctx.offer(offerId)
	if err != nil {
		return nil, err
	}
	if err := offerCtx.validateTokenType(constants.TokenClass_RIGHTS_OFFER, "offerId"); err != nil {
		return nil, err
	}
	offer, err := offerCtx.getOfferRecord()
	if err != nil {
		return nil, err
	}
	if !offer.Enabled {
		return nil, common.NewErrInvalid("offer '%s' is disabled", offerId)
	}

	fungCtx, err := ctx.fungible(offer.Currency)
	if err != nil {
		return nil, err
	}
	newRecord, err := fungCtx.transfer(request.BuyerId, "main", offer.Owner, offer.Price,
		fmt.Sprintf("payment for requireOffer %s", offerId))
	if err != nil {
		return nil, err
	}

	rightsTxID, err := ctx.TxID()
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to fetch transaction's tx ID")
	}
	record := &types.RightsRecord{
		RightsId: rightsTxID,
		Template: offer.Template,
	}
	rawRecord, err := json.Marshal(record)
	if err != nil {
		return nil, errors.Wrap(err, "failed to json.Marshal record")
	}
	assetData := string(rawRecord)

	rightsCtx, err := ctx.tokenType(offer.Rights)
	if err != nil {
		return nil, err
	}
	assetCtx, err := rightsCtx.asset(assetData)
	if err != nil {
		return nil, err
	}
	if _, err := assetCtx.mint(request.BuyerId, request.Metadata, offer.Asset, offer.OfferId); err != nil {
		return nil, err
	}

	if err := ctx.Prepare(); err != nil {
		return nil, err
	}
	return &types.RightsOfferBuyResponse{
		OfferId:       offerId,
		TokenId:       assetCtx.tokenId,
		Transfer:      *newRecord,
		TxEnvelope:    ctx.GetTxEnvelope(),
		TxPayloadHash: ctx.GetTxPayloadHash(),
	}, nil
}

func (m *Manager) RightsOfferSubmitTx(submitRequest *types.RightsOfferSubmitRequest) (*types.RightsOfferSubmitResponse, error) {
	ctx := submitContextFromRights(submitRequest)
	if err := m.submitTx(ctx); err != nil {
		return nil, err
	}
	return ctx.ToRightsResponse(), nil
}

func (m *Manager) RightsOfferGet(offerId string) (*types.RightsOfferRecord, error) {
	ctx, err := newTxContext(m).offer(offerId)
	if err != nil {
		return nil, err
	}
	defer ctx.Abort()
	if err := ctx.validateTokenType(constants.TokenClass_RIGHTS_OFFER, "offer ID"); err != nil {
		return nil, err
	}
	offer, err := ctx.getOfferRecord()
	if err != nil {
		return nil, err
	}
	return offer, nil
}

func (m *Manager) RightsOfferQuery(typeId string, owner string, asset string) ([]types.RightsOfferRecord, error) {
	ctx, err := newTxContext(m).tokenType(typeId)
	if err != nil {
		return nil, err
	}
	defer ctx.Abort()
	if err := ctx.validateTokenType(constants.TokenClass_RIGHTS_OFFER, "type ID"); err != nil {
		return nil, err
	}

	results, err := ctx.Query(map[string]string{
		"owner": owner,
		"asset": asset,
	})
	if err != nil {
		return nil, err
	}

	records := make([]types.RightsOfferRecord, len(results))
	for i, res := range results {
		if err = json.Unmarshal(res.GetValue(), &records[i]); err != nil {
			return nil, errors.Wrap(err, "failed to json.Unmarshal JSONQuery result")
		}
	}
	return records, nil
}
