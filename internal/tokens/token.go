// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"encoding/base64"
	"encoding/json"

	"github.com/copa-europe-tokens/internal/common"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger-labs/orion-sdk-go/pkg/bcdb"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
)

// TokenTxContext handles a token transaction from start to finish
type TokenTxContext struct {
	lg               *logger.SugarLogger
	typeId           string
	tokenDBName      string
	custodianId      string
	custodianSession bcdb.DBSession

	// Evaluated lazily
	dataTx        bcdb.DataTxContext
	description   *types.TokenDescription
	TxEnvelope    string
	TxPayloadHash string
}

func getTokenTypeDBName(typeId string) (string, error) {
	if err := validateMD5Base64ID(typeId, "token type"); err != nil {
		return "", common.NewErrInvalid("Invalid type ID: %s", err)
	}
	return TokenTypeDBNamePrefix + typeId, nil
}

// Create a new common token context without initiating a TX.
func newTokenTxContext(m *Manager, typeId string) (*TokenTxContext, error) {
	tokenDBName, err := getTokenTypeDBName(typeId)
	if err != nil {
		return nil, err
	}
	return &TokenTxContext{
		lg:               m.lg,
		custodianSession: m.custodianSession,
		custodianId:      m.config.Users.Custodian.UserID,
		tokenDBName:      tokenDBName,
		typeId:           typeId,
	}, nil
}

// ResetTx creates a new transaction. It will abort previous transaction if existed.
func (ctx *TokenTxContext) ResetTx() error {
	if ctx.dataTx != nil {
		if err := ctx.dataTx.Abort(); err != nil {
			return err
		}
	}

	dataTx, err := ctx.custodianSession.DataTx()
	if err != nil {
		return errors.Wrap(err, "failed to create DataTx")
	}
	ctx.dataTx = dataTx

	return nil
}

// Returns an existing transaction or creates a new one
func (ctx *TokenTxContext) tx() (bcdb.DataTxContext, error) {
	if ctx.dataTx == nil {
		if err := ctx.ResetTx(); err != nil {
			return nil, err
		}
	}
	return ctx.dataTx, nil
}

func (ctx *TokenTxContext) Get(key string) ([]byte, error) {
	tx, err := ctx.tx()
	if err != nil {
		return nil, err
	}
	val, meta, err := tx.Get(ctx.tokenDBName, key)
	if err != nil {
		return nil, wrapOrionError(err, "failed to get ket [%v] from db [%s] with metadata [%+v]", key, ctx.tokenDBName, meta)
	}
	return val, nil
}

func (ctx *TokenTxContext) Put(key string, val []byte, owner string, mustSign bool) error {
	tx, err := ctx.tx()
	if err != nil {
		return err
	}
	err = tx.Put(ctx.tokenDBName, key, val, &oriontypes.AccessControl{
		ReadWriteUsers: map[string]bool{
			ctx.custodianId: true,
			owner:           true,
		},
		SignPolicyForWrite: oriontypes.AccessControl_ALL,
	})
	if err != nil {
		return wrapOrionError(err, "failed to put [%s] in db [%s]", key, ctx.tokenDBName)
	}

	if mustSign {
		tx.AddMustSignUser(owner)
	}

	return nil
}

func (ctx *TokenTxContext) Delete(key string) error {
	tx, err := ctx.tx()
	if err != nil {
		return err
	}
	if err = tx.Delete(ctx.tokenDBName, key); err != nil {
		return wrapOrionError(err, "Fail to delete [%s] from db [%s]", key, ctx.tokenDBName)
	}
	return nil
}

// Abort a TX if it was initiated
func (ctx *TokenTxContext) Abort() {
	if ctx != nil && ctx.dataTx != nil {
		abort(ctx.dataTx)
		ctx.dataTx = nil
	}
}

func (ctx *TokenTxContext) Prepare() error {
	if ctx.dataTx == nil {
		return errors.New("Attempt to prepare a transaction, but transaction was not created.")
	}

	txEnv, err := ctx.dataTx.SignConstructedTxEnvelopeAndCloseTx()
	if err != nil {
		return errors.Wrap(err, "failed to construct Tx envelope")
	}

	txEnvBytes, err := proto.Marshal(txEnv)
	if err != nil {
		return errors.Wrap(err, "failed to proto.Marshal Tx envelope")
	}

	payloadBytes, err := json.Marshal(txEnv.(*oriontypes.DataTxEnvelope).Payload)
	if err != nil {
		return errors.Wrap(err, "failed to json.Marshal DataTx")
	}

	payloadHash, err := ComputeSHA256Hash(payloadBytes)
	if err != nil {
		return errors.Wrap(err, "failed to compute hash of DataTx bytes")
	}

	ctx.TxEnvelope = base64.StdEncoding.EncodeToString(txEnvBytes)
	ctx.TxPayloadHash = base64.StdEncoding.EncodeToString(payloadHash)
	return nil
}

func (ctx *TokenTxContext) getDescription() (*types.TokenDescription, error) {
	if ctx.description != nil {
		return ctx.description, nil
	}

	// We create a new session since other users don't have read permissions to the types DB
	dataTx, err := ctx.custodianSession.DataTx()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create DataTx")
	}
	defer abort(dataTx)

	val, meta, err := dataTx.Get(TypesDBName, ctx.tokenDBName)
	if err != nil {
		return nil, wrapOrionError(err, "failed to Get description of type [%s]", ctx.typeId)
	}
	if val == nil {
		return nil, common.NewErrNotFound("token type not found")
	}

	desc := types.TokenDescription{}
	if err = json.Unmarshal(val, &desc); err != nil {
		return nil, errors.Wrapf(err, "failed to json.Unmarshal %s for type %s", val, ctx.typeId)
	}
	ctx.lg.Debugf("Token type description: %+v; metadata: %v", &desc, meta)

	ctx.description = &desc
	return ctx.description, nil
}
