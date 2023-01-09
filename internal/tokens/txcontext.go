// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/copa-europe-tokens/internal/common"
	"github.com/hyperledger-labs/orion-sdk-go/pkg/bcdb"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/hyperledger-labs/orion-server/pkg/marshal"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

type internalTxContext struct {
	// Evaluated lazily
	dataTx        bcdb.DataTxContext
	TxEnvelope    string
	TxPayloadHash string
}

type TxContext struct {
	lg               *logger.SugarLogger
	custodianId      string
	adminId          string
	custodianSession bcdb.DBSession
	i                *internalTxContext
}

type DbTxContext struct {
	TxContext
	dbName string
}

// Create a new common context without initiating a TX.
func newTxContext(m *Manager) *TxContext {
	return &TxContext{
		lg:               m.lg,
		custodianSession: m.custodianSession,
		custodianId:      m.config.Users.Custodian.UserID,
		adminId:          m.config.Users.Admin.UserID,
		i:                &internalTxContext{},
	}
}

// Create a new TXContext with its own detached dataTX
func (ctx *TxContext) detach() *TxContext {
	newCtx := *ctx
	newCtx.i = &internalTxContext{}
	return &newCtx
}

func (ctx *TxContext) db(dbName string) *DbTxContext {
	return &DbTxContext{
		TxContext: *ctx,
		dbName:    dbName,
	}
}

func (ctx *TxContext) validateUserId(userId string) error {
	if userId == "" {
		return common.NewErrInvalid("Invalid user ID: empty.")
	}

	if userId == ctx.custodianId || userId == ctx.adminId {
		return common.NewErrInvalid("Invalid user ID: the user '%s' cannot participate in token activities.", userId)
	}

	return nil
}

func (ctx *TxContext) tokenType(typeId string) (*TokenTypeTxContext, error) {
	tokenDBName, err := getTokenTypeDBName(typeId)
	if err != nil {
		return nil, err
	}
	return &TokenTypeTxContext{
		DbTxContext: *ctx.db(tokenDBName),
		typeId:      typeId,
	}, nil
}

func (ctx *TxContext) token(tokenId string) (*TokenTxContext, error) {
	typeId, assetId, err := parseTokenId(tokenId)
	if err != nil {
		return nil, err
	}
	tokenTypeCtx, err := ctx.tokenType(typeId)
	if err != nil {
		return nil, err
	}
	return &TokenTxContext{
		TokenTypeTxContext: *tokenTypeCtx,
		tokenId:            tokenId,
		assetId:            assetId,
	}, nil
}

func (ctx *TxContext) fungible(typeId string) (*FungibleTxContext, error) {
	genericCtx, err := ctx.tokenType(typeId)
	if err != nil {
		return nil, err
	}
	return &FungibleTxContext{*genericCtx}, nil
}

func (ctx *TxContext) offerType(typeId string) (*OfferTypeTxContext, error) {
	genericCtx, err := ctx.tokenType(typeId)
	if err != nil {
		return nil, err
	}
	return &OfferTypeTxContext{*genericCtx}, nil
}

func (ctx *TxContext) offer(offerId string) (*OfferTxContext, error) {
	genericCtx, err := ctx.token(offerId)
	if err != nil {
		return nil, err
	}
	return &OfferTxContext{*genericCtx}, nil
}

// ResetTx creates a new transaction. It will abort previous transaction if existed.
func (ctx *TxContext) ResetTx() error {
	if ctx.i.dataTx != nil {
		if err := ctx.i.dataTx.Abort(); err != nil {
			return err
		}
	}

	dataTx, err := ctx.custodianSession.DataTx()
	if err != nil {
		return errors.Wrap(err, "failed to create DataTx")
	}
	ctx.i.dataTx = dataTx

	return nil
}

// Returns an existing transaction or creates a new one
func (ctx *TxContext) tx() (bcdb.DataTxContext, error) {
	if ctx.i.dataTx == nil {
		if err := ctx.ResetTx(); err != nil {
			return nil, err
		}
	}
	return ctx.i.dataTx, nil
}

func (ctx *TxContext) TxID() (txID string, err error) {
	tx, err := ctx.tx()
	if err != nil {
		return
	}

	txID = tx.TxID()
	return
}

// Abort a TX if it was initiated
func (ctx *TxContext) Abort() {
	if ctx != nil && ctx.i.dataTx != nil {
		abort(ctx.i.dataTx)
		ctx.i.dataTx = nil
	}
}

func (ctx *TxContext) Prepare() error {
	if ctx.i.dataTx == nil {
		return errors.New("Attempt to prepare a transaction, but transaction was not created.")
	}

	txEnv, err := ctx.i.dataTx.SignConstructedTxEnvelopeAndCloseTx()
	if err != nil {
		return errors.Wrap(err, "failed to construct Tx envelope")
	}

	txEnvBytes, err := proto.Marshal(txEnv)
	if err != nil {
		return errors.Wrap(err, "failed to proto.Marshal Tx envelope")
	}

	payloadBytes, err := marshal.DefaultMarshaler().Marshal(txEnv.(*oriontypes.DataTxEnvelope).Payload)
	if err != nil {
		return errors.Wrap(err, "failed to json.Marshal DataTx")
	}

	payloadHash, err := ComputeSHA256Hash(payloadBytes)
	if err != nil {
		return errors.Wrap(err, "failed to compute hash of DataTx bytes")
	}

	ctx.i.TxEnvelope = base64.StdEncoding.EncodeToString(txEnvBytes)
	ctx.i.TxPayloadHash = base64.StdEncoding.EncodeToString(payloadHash)
	return nil
}

func (ctx *TxContext) GetTxEnvelope() string {
	return ctx.i.TxEnvelope
}

func (ctx *TxContext) GetTxPayloadHash() string {
	return ctx.i.TxPayloadHash
}

func (ctx *DbTxContext) GetMarshal(key string, record interface{}) (existed bool, err error) {
	rawRecord, existed, err := ctx.Get(key)
	if err != nil {
		return
	}
	existed = existed && rawRecord != nil
	if !existed {
		return
	}
	if err = json.Unmarshal(rawRecord, &record); err != nil {
		err = common.WrapErrInternal(err, "Failed to json.Unmarshal %s", rawRecord)
		return
	}
	return
}

func (ctx *DbTxContext) Get(key string) (value []byte, existed bool, err error) {
	tx, err := ctx.tx()
	if err != nil {
		return
	}
	value, meta, err := tx.Get(ctx.dbName, key)
	if err != nil {
		err = wrapOrionError(err, "failed to get key [%v] from db [%s] with metadata [%+v]", key, ctx.dbName, meta)
		return
	}
	existed = meta != nil
	return
}

func (ctx *DbTxContext) PutMarshal(key string, val interface{}, owner string, mustSign bool) error {
	rawVal, err := json.Marshal(val)
	if err != nil {
		return common.WrapErrInternal(err, "failed to json.Marshal record")
	}
	return ctx.Put(key, rawVal, owner, mustSign)
}

func (ctx *DbTxContext) Put(key string, val []byte, owner string, mustSign bool) error {
	tx, err := ctx.tx()
	if err != nil {
		return err
	}
	err = tx.Put(ctx.dbName, key, val, &oriontypes.AccessControl{
		ReadWriteUsers: map[string]bool{
			ctx.custodianId: true,
			owner:           true,
		},
		SignPolicyForWrite: oriontypes.AccessControl_ALL,
	})
	if err != nil {
		return wrapOrionError(err, "failed to put [%s] in db [%s]", key, ctx.dbName)
	}

	if mustSign {
		tx.AddMustSignUser(owner)
	}

	return nil
}

func (ctx *DbTxContext) Delete(key string) error {
	tx, err := ctx.tx()
	if err != nil {
		return err
	}
	if err = tx.Delete(ctx.dbName, key); err != nil {
		return wrapOrionError(err, "Fail to delete [%s] from db [%s]", key, ctx.dbName)
	}
	return nil
}

func (ctx *DbTxContext) Query(fields map[string]string) ([]*oriontypes.KVWithMetadata, error) {
	queryMap := map[string]map[string]string{}
	for k, v := range fields {
		if v != "" {
			queryMap[k] = map[string]string{"$eq": v}
		}
	}

	if len(queryMap) == 0 {
		return nil, common.NewErrInvalid("query must contain at least one qualifier")
	}

	selector, err := json.Marshal(queryMap)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal JSONQuery selector")
	}
	query := fmt.Sprintf(`{"selector": {"$and": %s}}`, selector)

	jq, err := ctx.custodianSession.Query()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create JSONQuery")
	}
	queryResults, err := jq.ExecuteJSONQuery(ctx.dbName, query)
	if err != nil {
		return nil, wrapOrionError(err, "Failed to execute JSONQuery for DB [%s]", ctx.dbName)
	}
	return queryResults, nil
}
