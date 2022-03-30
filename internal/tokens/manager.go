// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"bytes"
	"crypto"
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
	GetStatus() (string, error)
	DeployTokenType(deployRequest *types.DeployRequest) (*types.DeployResponse, error)
	GetTokenType(tokenTypeId string) (*types.DeployResponse, error)
}

type Manager struct {
	config *config.Configuration
	lg     *logger.SugarLogger

	bcDB             bcdb.BCDB
	adminSession     bcdb.DBSession
	custodianSession bcdb.DBSession
}

type TokenDescription struct {
	TypeId      string `json:"typeId"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Url         string `json:"url,omitempty"`
}

func NewManager(config *config.Configuration, lg *logger.SugarLogger) (*Manager, error) {
	m := &Manager{
		config: config,
		lg:     lg,
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

	if err := m.createTypesDB(); err != nil {
		return nil, err
	}

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
	tokenDesc := &TokenDescription{
		TypeId:      tokenTypeIDBase64,
		Name:        deployRequest.Name,
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

	// create the token DB
	dBsTx, err := m.adminSession.DBsTx()
	if err != nil {
		userTx.Abort()
		return nil, errors.Wrap(err, "failed to create DBsTx")
	}

	exists, err := dBsTx.Exists(tokenDBName)
	if err != nil {
		userTx.Abort()
		return nil, errors.Wrap(err, "failed to query DB existence")
	}
	if exists {
		userTx.Abort()
		dBsTx.Abort()
		return nil, errors.Errorf("failed to deploy token: custodian does not have privilege, but token database exists: %s", tokenDBName)
	}

	index := make(map[string]oriontypes.IndexAttributeType)
	index["owner"] = oriontypes.IndexAttributeType_STRING
	err = dBsTx.CreateDB(tokenDBName, index)
	if err != nil {
		dBsTx.Abort()
		return nil, errors.Wrap(err, "failed to build DBsTx")
	}

	txID, receiptEnv, err = dBsTx.Commit(true)
	if err != nil {
		userTx.Abort()
		m.lg.Errorf("Failed to deploy: commit failed: %s", err.Error())
		if strings.Contains(err.Error(), fmt.Sprintf("[%s] already exists", tokenDBName)) {
			return nil, &ErrExist{ErrMsg: "token type already exists"}
		}
		return nil, errors.Wrap(err, "failed to deploy token type")
	}

	m.lg.Infof("Database created: %s, for token-name: %s; txID: %s, receipt: %+v", tokenDBName, deployRequest.Name, txID, receiptEnv.GetResponse().GetReceipt())

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

	m.lg.Infof("Custodian [%s] granted RW privilege to database: %s; txID: %s, receipt: %+v", m.config.Users.Custodian.UserID, tokenDBName, txID, receiptEnv.GetResponse().GetReceipt())

	return &types.DeployResponse{
		TypeId:      tokenTypeIDBase64,
		Name:        deployRequest.Name,
		Description: deployRequest.Description,
		Url:         constants.TokensTypesEndpoint + "/" + tokenTypeIDBase64,
	}, nil
}

func (m *Manager) GetTokenType(tokenTypeId string) (*types.DeployResponse, error) {
	if tokenTypeId == "" {
		return nil, &ErrInvalid{ErrMsg: "token type ID is empty"}
	}

	if len(tokenTypeId) > base64.RawURLEncoding.EncodedLen(crypto.MD5.Size()) {
		return nil, &ErrInvalid{ErrMsg: "token type ID is too long"}
	}
	if _, err := base64.RawURLEncoding.DecodeString(tokenTypeId); err != nil {
		return nil, &ErrInvalid{ErrMsg: "token type ID is not in base64url"}
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
	deployResponse.Url = constants.TokensTypesEndpoint + "/" + deployResponse.TypeId

	m.lg.Debugf("Token type deploy response: %+v; metadata: %v", deployResponse, meta)

	return deployResponse, nil
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
				DbPermission: map[string]oriontypes.Privilege_Access{TypesDBName: oriontypes.Privilege_Read},
				Admin:        false,
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
