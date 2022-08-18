// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"encoding/json"
	"fmt"

	"github.com/copa-europe-tokens/internal/common"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/google/uuid"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
)

const (
	reserveAccount = "reserve"
	mainAccount    = "main"
)

type FungibleTokenDescription struct {
	CommonTokenDescription
	ReserveOwner string `json:"reserveOwner"`
}

type ReserveAccountComment struct {
	Supply uint64 `json:"supply"`
}

type ReserveAccountRecord struct {
	Balance uint64
	Supply  uint64
}

type FungibleContext struct {
	TokenContext
	desc FungibleTokenDescription
}

func newFungibleContext(m *Manager, typeId string) (*FungibleContext, error) {
	genericCtx, err := newTokenContext(m, typeId)
	if err != nil {
		return nil, err
	}

	ctx := FungibleContext{TokenContext: *genericCtx}

	if err := ctx.getTokenDescription(&ctx.desc); err != nil {
		return nil, err
	}

	if ctx.desc.Class != constants.TokenClass_FUNGIBLE {
		return nil, common.NewErrInvalid("Type %v is not a fungible token.", typeId)
	}

	return &ctx, nil
}

func newFungibleContextTx(m *Manager, typeId string) (*FungibleContext, error) {
	ctx, err := newFungibleContext(m, typeId)
	if err != nil {
		return nil, err
	}
	return ctx, ctx.initTx()
}

func getAccountKey(owner string, account string) string {
	return fmt.Sprintf("%s:%s", owner, account)
}

func getAccountKeyFromRecord(record *types.FungibleAccountRecord) string {
	return getAccountKey(record.Owner, record.Account)
}

func (ctx *FungibleContext) getAccountRecordTxRaw(owner string, account string) ([]byte, error) {
	accountKey := getAccountKey(owner, account)
	val, _, err := ctx.dataTx.Get(ctx.tokenDBName, accountKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get %v from %s", accountKey, ctx.tokenDBName)
	}
	return val, nil
}

func unmarshalAccountRecord(rawRecord []byte) (*types.FungibleAccountRecord, error) {
	record := types.FungibleAccountRecord{}
	if err := json.Unmarshal(rawRecord, &record); err != nil {
		return nil, errors.Wrapf(err, "failed to json.Unmarshal %s", rawRecord)
	}
	return &record, nil
}

func (ctx *FungibleContext) getAccountRecordTx(owner string, account string) (*types.FungibleAccountRecord, error) {
	val, err := ctx.getAccountRecordTxRaw(owner, account)
	if err != nil {
		return nil, err
	}
	if val == nil {
		ctx.m.lg.Debugf("Account does not exists: DB: %s, user %s, account: %s", ctx.tokenDBName, owner, account)
		return nil, common.NewErrNotFound("account [%v] of user [%s] does not exists", account, owner)
	}

	return unmarshalAccountRecord(val)
}

func (ctx *FungibleContext) putAccountRecordTx(record *types.FungibleAccountRecord) error {
	accountKey := getAccountKeyFromRecord(record)

	val, err := json.Marshal(record)
	if err != nil {
		return errors.Wrap(err, "failed to json.Marshal record")
	}

	err = ctx.dataTx.Put(ctx.tokenDBName, accountKey, val, &oriontypes.AccessControl{
		ReadWriteUsers: map[string]bool{
			ctx.m.config.Users.Custodian.UserID: true,
			record.Owner:                        true,
		},
		SignPolicyForWrite: oriontypes.AccessControl_ALL,
	})
	if err != nil {
		return errors.Wrap(err, "failed to Put")
	}

	if record.Account == mainAccount || record.Account == reserveAccount {
		ctx.dataTx.AddMustSignUser(record.Owner)
	}

	ctx.m.lg.Debugf("putAccountRecordTx: key=%v, record=%v", accountKey, record)

	return nil
}

func (ctx *FungibleContext) deleteAccountRecordTx(record *types.FungibleAccountRecord) error {
	return ctx.dataTx.Delete(ctx.tokenDBName, getAccountKeyFromRecord(record))
}

func decodeReserveAccountComment(serializedComment string) (*ReserveAccountComment, error) {
	comment := ReserveAccountComment{Supply: 0}
	if serializedComment == "" {
		return &comment, nil
	}

	if err := json.Unmarshal([]byte(serializedComment), &comment); err != nil {
		return nil, errors.Wrapf(err, "failed to json.Unmarshal comment %s", serializedComment)
	}
	return &comment, nil
}

func encodeReserveAccountComment(comment *ReserveAccountComment) (string, error) {
	byteComment, err := json.Marshal(comment)
	if err != nil {
		return "", errors.Wrap(err, "failed to json.Marshal comment")
	}
	return string(byteComment), nil
}

func (ctx *FungibleContext) getReserveAccount() (*ReserveAccountRecord, error) {
	reserve := ReserveAccountRecord{
		Balance: 0,
		Supply:  0,
	}

	rawRecord, err := ctx.getAccountRecordTxRaw(ctx.desc.ReserveOwner, reserveAccount)
	if err != nil {
		return nil, err
	}

	if rawRecord == nil {
		return &reserve, nil
	}

	record, err := unmarshalAccountRecord(rawRecord)
	if err != nil {
		return nil, err
	}

	reserve.Balance = record.Balance

	comment, err := decodeReserveAccountComment(record.Comment)
	if err != nil {
		return nil, err
	}

	reserve.Supply = comment.Supply

	return &reserve, nil
}

func (ctx *FungibleContext) putReserveAccount(reserve *ReserveAccountRecord) error {
	serializedComment, err := encodeReserveAccountComment(&ReserveAccountComment{Supply: reserve.Supply})
	if err != nil {
		return err
	}

	return ctx.putAccountRecordTx(&types.FungibleAccountRecord{
		Account: reserveAccount,
		Owner:   ctx.desc.ReserveOwner,
		Balance: reserve.Balance,
		Comment: serializedComment,
	})
}

func FungibleTypeURL(typeId string) string {
	return common.URLForType(constants.FungibleTypeRoot, typeId)
}

func (ctx *FungibleContext) queryFungibleAccounts(owner string, account string) ([]types.FungibleAccountRecord, error) {
	jq, err := ctx.m.custodianSession.Query()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create JSONQuery")
	}

	var query string
	if owner != "" && account != "" {
		query = fmt.Sprintf(`
		{
			"selector":
			{
				"$and": {
					"owner": {"$eq": "%s"},
					"account": {"$eq": "%s"}
				}
			}
		}`, owner, account)
	} else if owner != "" {
		query = fmt.Sprintf(`
		{
			"selector": {
				"owner": {"$eq": "%s"}
			}
		}`, owner)
	} else if account != "" {
		query = fmt.Sprintf(`
		{
			"selector": {
				"account": {"$eq": "%s"}
			}
		}`, account)
	} else {
		query = `
		{
			"selector": {
				"owner": {"$lte": "~"}
			}
		}`
	}

	queryResults, err := jq.ExecuteJSONQuery(ctx.tokenDBName, query)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute JSONQuery")
	}

	records := make([]types.FungibleAccountRecord, len(queryResults))
	for i, res := range queryResults {
		if err = json.Unmarshal(res.GetValue(), &records[i]); err != nil {
			return nil, errors.Wrap(err, "failed to json.Unmarshal JSONQuery result")
		}
	}
	return records, nil
}

func (ctx *FungibleContext) internalFungiblePrepareTransfer(request *types.FungibleTransferRequest) (*types.FungibleTransferResponse, error) {
	txUUID, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to generate tx ID")
	}
	newRecord := types.FungibleAccountRecord{
		Account: txUUID.String(),
		Owner:   request.NewOwner,
		Balance: request.Quantity,
		Comment: request.Comment,
	}

	if err := ctx.initTx(); err != nil {
		return nil, err
	}

	// Verify that the new generated account does not exist
	val, err := ctx.getAccountRecordTxRaw(newRecord.Owner, newRecord.Account)
	if err != nil {
		return nil, err
	}
	if val != nil {
		// Account already exist. We need to retry with a new TX
		// to avoid false sharing between the existing account.
		return nil, nil // Signify the calling method to retry.
	}

	fromRecord, err := ctx.getAccountRecordTx(request.Owner, request.Account)
	if err != nil {
		return nil, err
	}

	if request.Quantity > fromRecord.Balance {
		return nil, common.NewErrInvalid("Insufficient funds in account %v of %v. Requested %v, Balance: %v", fromRecord.Account, fromRecord.Owner, request.Quantity, fromRecord.Balance)
	}

	fromRecord.Balance -= request.Quantity

	if err = ctx.putAccountRecordTx(fromRecord); err != nil {
		return nil, err
	}

	err = ctx.putAccountRecordTx(&newRecord)
	if err != nil {
		return nil, err
	}

	env, err := ctx.prepare()
	if err != nil {
		return nil, err
	}

	return &types.FungibleTransferResponse{
		TypeId:        ctx.typeId,
		Owner:         request.Owner,
		Account:       request.Account,
		NewOwner:      newRecord.Owner,
		NewAccount:    newRecord.Account,
		TxEnvelope:    env.TxEnvelope,
		TxPayloadHash: env.TxPayloadHash,
	}, nil
}
