// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"encoding/base64"
	"encoding/json"

	"github.com/copa-europe-tokens/internal/common"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger-labs/orion-sdk-go/pkg/bcdb"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
)

type TokenContext struct {
	m             *Manager
	dataTx        bcdb.DataTxContext
	tokenDBName   string
	typeId        string
	TxEnvelope    string
	TxPayloadHash string
}

func getTokenTypeDBName(typeId string) (string, error) {
	if err := validateMD5Base64ID(typeId, "token type"); err != nil {
		return "", common.WrapErrInvalid(err)
	}

	return TokenTypeDBNamePrefix + typeId, nil
}

// Create a new common token context without initiating a TX.
func newTokenContext(m *Manager, typeId string) (*TokenContext, error) {
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
func newTokenContextTx(m *Manager, typeId string) (*TokenContext, error) {
	ctx, err := newTokenContext(m, typeId)
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

func (ctx *TokenContext) prepare() error {
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
		return common.NewErrNotFound("token type not found: %v", ctx.typeId)
	}

	if err = json.Unmarshal(val, result); err != nil {
		return errors.Wrapf(err, "failed to json.Unmarshal %s for DB %s", val, ctx.tokenDBName)
	}

	ctx.m.lg.Debugf("Token type description: %+v; metadata: %v", result, meta)

	return nil
}
