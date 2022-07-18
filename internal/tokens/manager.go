// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/copa-europe-tokens/pkg/config"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger-labs/orion-sdk-go/pkg/bcdb"
	sdkconfig "github.com/hyperledger-labs/orion-sdk-go/pkg/config"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
)

const (
	TypesDBName           = "token-types"
	TokenTypeDBNamePrefix = "ttid."
)

func getTokenTypeDBName(typeId string) (string, error) {
	if err := validateMD5Base64ID(typeId, "token type"); err != nil {
		return "", err
	}

	return TokenTypeDBNamePrefix + typeId, nil
}

func getTokenTypeId(tokenDbName string) (string, error) {
	if !strings.HasPrefix(tokenDbName, TokenTypeDBNamePrefix) {
		return "", errors.Errorf("%s is not a valid DB name. Must start with: %s", tokenDbName, TokenTypeDBNamePrefix)
	}
	return tokenDbName[len(TokenTypeDBNamePrefix):], nil
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

func abort(ctx bcdb.TxContext) {
	if ctx != nil {
		_ = ctx.Abort()
	}
}

type CommonTokenDescription struct {
	TypeId      string `json:"typeId"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Class       string `json:"class"`
}

type TokenDescription interface {
	common() *CommonTokenDescription
}

func (desc *CommonTokenDescription) common() *CommonTokenDescription {
	return desc
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
		dbName, err := getTokenTypeDBName(tt["typeId"])
		if err != nil {
			return nil, errors.Wrapf(err, "Detected invalid type ID in DB: %v", tt["typeId"])
		}
		m.tokenTypesDBs[dbName] = true
	}
	m.lg.Debugf("Found token types: %v", m.tokenTypesDBs)

	m.lg.Info("Connected to Orion")

	return m, nil
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

	user, err := tx.GetUser(m.config.Users.Custodian.UserID)
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

func (m *Manager) deployNewTokenType(desc TokenDescription, indices ...string) error {
	commonDesc := desc.common()
	if commonDesc.Name == "" {
		return NewErrInvalid("token type name is empty")
	}

	// Compute TypeId
	tokenTypeIDBase64, err := NameToID(commonDesc.Name)
	if err != nil {
		return errors.Wrap(err, "failed to compute hash of token type name")
	}
	commonDesc.TypeId = tokenTypeIDBase64

	tokenDBName, err := getTokenTypeDBName(tokenTypeIDBase64)
	if err != nil {
		return errors.Wrap(err, "Created invalid type ID")
	}

	// Check existence by looking into the custodian privileges
	userTx, err := m.adminSession.UsersTx()
	if err != nil {
		return errors.Wrap(err, "failed to create UsersTx")
	}
	defer abort(userTx)

	custodian, err := userTx.GetUser(m.config.Users.Custodian.UserID)
	if err != nil {
		return errors.Wrapf(err, "failed to get user: %s", m.config.Users.Custodian.UserID)
	}
	if _, exists := custodian.GetPrivilege().GetDbPermission()[tokenDBName]; exists {
		return NewErrExist("token type already exists")
	}

	// Save token description to Types-DB
	dataTx, err := m.adminSession.DataTx()
	if err != nil {
		return errors.Wrap(err, "failed to create DataTx")
	}
	defer abort(dataTx)

	existingTokenDesc, _, err := dataTx.Get(TypesDBName, tokenDBName)
	if err != nil {
		return errors.Wrapf(err, "failed to get %s %s", TypesDBName, tokenDBName)
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
		return errors.Wrapf(err, "failed to put %s %s", TypesDBName, tokenDBName)
	}

	txID, receiptEnv, err := dataTx.Commit(true)
	if err != nil {
		return errors.Wrapf(err, "failed to commit %s %s", TypesDBName, tokenDBName)
	}

	m.lg.Infof("Saved token description: %+v; txID: %s, receipt: %+v", desc, txID, receiptEnv.GetResponse().GetReceipt())

	err = m.createTokenDBTable(tokenDBName, indices...)
	if err != nil {
		return err
	}

	// Add privilege to custodian
	custodian.Privilege.DbPermission[tokenDBName] = oriontypes.Privilege_ReadWrite

	err = userTx.PutUser(custodian, nil)
	if err != nil {
		return errors.Wrap(err, "failed to put user")
	}

	txID, receiptEnv, err = userTx.Commit(true)
	if err != nil {
		return errors.Wrap(err, "failed to commit user")
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
		if strings.Contains(err.Error(), fmt.Sprintf("[%s] already exists", tokenDBName)) {
			return NewErrExist("token type already exists")
		}
		return errors.Wrap(err, "failed to deploy token type")
	}

	m.lg.Infof("Database created: %s, txID: %s, receipt: %+v", tokenDBName, txID, receiptEnv.GetResponse().GetReceipt())
	return nil
}

type TokenContext struct {
	m           *Manager
	dataTx      bcdb.DataTxContext
	tokenDBName string
	typeId      string
}

type TokenDBTxEnvelope struct {
	TxEnvelope    string
	TxPayloadHash string
}

// Create a new common token context without initiating a TX.
func (m *Manager) newTokenContext(typeId string) (*TokenContext, error) {
	tokenDBName, err := getTokenTypeDBName(typeId)
	if err != nil {
		return nil, err
	}

	return &TokenContext{
		m:           m,
		tokenDBName: tokenDBName,
		typeId:      typeId,
	}, nil
}

// Create a new common token context and initiating a TX.
func (m *Manager) newTokenContextTx(typeId string) (*TokenContext, error) {
	ctx, err := m.newTokenContext(typeId)
	if err != nil {
		return nil, err
	}

	return ctx, ctx.initTx()
}

// Initialize a TX.
func (ctx *TokenContext) initTx() error {
	if ctx.dataTx != nil {
		abort(ctx.dataTx)
	}

	dataTx, err := ctx.m.custodianSession.DataTx()
	if err != nil {
		return errors.Wrap(err, "failed to create DataTx")
	}
	ctx.dataTx = dataTx

	return nil
}

// Aborts a TX if it was initiated
func (ctx *TokenContext) abort() {
	if ctx != nil && ctx.dataTx != nil {
		abort(ctx.dataTx)
	}
}

func (ctx *TokenContext) getTokenDescription(result interface{}) error {
	dataTx, err := ctx.m.adminSession.DataTx()
	if err != nil {
		return errors.Wrap(err, "failed to create DataTx")
	}
	defer abort(dataTx)

	val, meta, err := dataTx.Get(TypesDBName, ctx.tokenDBName)
	if err != nil {
		return errors.Wrapf(err, "failed to Get %s", ctx.tokenDBName)
	}
	if val == nil {
		return NewErrNotFound("token type not found: %v", ctx.typeId)
	}

	if err = json.Unmarshal(val, result); err != nil {
		return errors.Wrapf(err, "failed to json.Unmarshal %s for DB %s", val, ctx.tokenDBName)
	}

	ctx.m.lg.Debugf("Token type description: %+v; metadata: %v", result, meta)

	return nil
}

func (ctx *TokenContext) prepare() (*TokenDBTxEnvelope, error) {
	txEnv, err := ctx.dataTx.SignConstructedTxEnvelopeAndCloseTx()
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

	return &TokenDBTxEnvelope{
		TxEnvelope:    base64.StdEncoding.EncodeToString(txEnvBytes),
		TxPayloadHash: base64.StdEncoding.EncodeToString(payloadHash),
	}, nil
}
