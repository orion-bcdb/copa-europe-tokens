// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/copa-europe-tokens/internal/common"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/hyperledger-labs/orion-sdk-go/pkg/bcdb"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
)

const (
	reserveAccountUser = "reserve"
	mainAccount        = "main"
)

func FungibleTypeURL(typeId string) string {
	return common.URLForType(constants.FungibleTypeRoot, typeId)
}

type ReserveAccountComment struct {
	Supply uint64 `json:"supply"`
}

type ReserveAccountRecord struct {
	Balance uint64
	Supply  uint64
}

type MovementStartPosition struct {
	Version *oriontypes.Version `json:"version,omitempty"`
}

func (p *MovementStartPosition) Marshal() (string, error) {
	if p.Version == nil {
		return "", nil
	}
	data, err := json.Marshal(p)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal start token")

	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func (p *MovementStartPosition) Unmarshal(raw string) error {
	if raw == "" {
		p.Version = nil
		return nil
	}

	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, p)
}

// behaves like v1 - v2
func versionCompare(v1, v2 *oriontypes.Version) int {
	if v1 == nil && v2 == nil {
		return 0
	} else if v1 == nil {
		return -1
	} else if v2 == nil {
		return 1
	} else if v1.BlockNum != v2.BlockNum {
		if v1.BlockNum < v2.BlockNum {
			return -1
		} else {
			return 1
		}
	} else if v1.TxNum != v2.TxNum {
		if v1.TxNum < v2.TxNum {
			return -1
		} else {
			return 1
		}
	}

	return 0
}

func (p *MovementStartPosition) Compare(v *oriontypes.Version) int {
	if p.Version == nil {
		return 1
	}
	return versionCompare(p.Version, v)
}

type FungibleTxContext struct {
	TokenTypeTxContext
	ledger bcdb.Ledger
}

func getAccountKey(owner string, account string) string {
	return fmt.Sprintf("%s:%s", owner, account)
}

func splitAccountKey(key string) (owner string, account string) {
	// Account is either the main account or the txID, which does not contain ":".
	lastInd := strings.LastIndex(key, ":")
	owner = key[:lastInd]
	account = key[lastInd+1:]
	return
}

func getAccountKeyFromRecord(record *types.FungibleAccountRecord) string {
	return getAccountKey(record.Owner, record.Account)
}

func (ctx *FungibleTxContext) getReserveOwner() (string, error) {
	desc, err := ctx.getDescription()
	if err != nil {
		return "", err
	}
	owner, ok := desc.Extension["reserveOwner"]
	if !ok {
		return "", common.NewErrInternal("Reserve owner is not specified for token type [%s]", ctx.typeId)
	}
	return owner, nil
}

func (ctx *FungibleTxContext) getAccountRecordRaw(owner string, account string) ([]byte, bool, error) {
	return ctx.Get(getAccountKey(owner, account))
}

func unmarshalAccountRecord(rawRecord []byte) (*types.FungibleAccountRecord, error) {
	record := types.FungibleAccountRecord{}
	if err := json.Unmarshal(rawRecord, &record); err != nil {
		return nil, errors.Wrapf(err, "Failed to json.Unmarshal %s", rawRecord)
	}
	return &record, nil
}

func (ctx *FungibleTxContext) getAccountRecord(owner string, account string) (*types.FungibleAccountRecord, error) {
	record := &types.FungibleAccountRecord{}
	existed, err := ctx.GetMarshal(getAccountKey(owner, account), record)
	if err != nil {
		return nil, err
	}
	if !existed {
		ctx.lg.Debugf("Account does not exists: DB: %s, user %s, account: %s", ctx.dbName, owner, account)
		return nil, common.NewErrNotFound("Account does not exists [%v:%v]", owner, account)
	}
	return record, nil
}

func (ctx *FungibleTxContext) putAccountRecord(record *types.FungibleAccountRecord) error {
	val, err := json.Marshal(record)
	if err != nil {
		return errors.Wrap(err, "failed to json.Marshal record")
	}

	recordOwner := record.Owner
	if record.Owner == reserveAccountUser {
		recordOwner, err = ctx.getReserveOwner()
		if err != nil {
			return err
		}
	}

	return ctx.Put(getAccountKeyFromRecord(record), val, recordOwner, record.Account == mainAccount)
}

func (ctx *FungibleTxContext) deleteAccountRecord(record *types.FungibleAccountRecord) error {
	return ctx.Delete(getAccountKeyFromRecord(record))
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

func (ctx *FungibleTxContext) getReserveAccount() (*ReserveAccountRecord, error) {
	rawRecord, existed, err := ctx.getAccountRecordRaw(reserveAccountUser, mainAccount)
	if err != nil {
		return nil, err
	}
	if !existed {
		return &ReserveAccountRecord{Balance: 0, Supply: 0}, nil
	}

	record, err := unmarshalAccountRecord(rawRecord)
	if err != nil {
		return nil, err
	}
	comment, err := decodeReserveAccountComment(record.Comment)
	if err != nil {
		return nil, err
	}

	return &ReserveAccountRecord{
		Balance: record.Balance,
		Supply:  comment.Supply,
	}, nil
}

func (ctx *FungibleTxContext) putReserveAccount(reserve *ReserveAccountRecord) error {
	serializedComment, err := encodeReserveAccountComment(&ReserveAccountComment{Supply: reserve.Supply})
	if err != nil {
		return err
	}
	return ctx.putAccountRecord(&types.FungibleAccountRecord{
		Account: mainAccount,
		Owner:   reserveAccountUser,
		Balance: reserve.Balance,
		Comment: serializedComment,
	})
}

func (ctx *FungibleTxContext) queryAccounts(owner string, account string) ([]types.FungibleAccountRecord, error) {
	queryResults, err := ctx.Query(map[string]string{
		"owner":   owner,
		"account": account,
	})
	if err != nil {
		return nil, err
	}

	records := make([]types.FungibleAccountRecord, len(queryResults))
	for i, res := range queryResults {
		if err = json.Unmarshal(res.GetValue(), &records[i]); err != nil {
			return nil, errors.Wrap(err, "Failed to json.Unmarshal JSONQuery result")
		}
	}
	return records, nil
}

func (ctx *FungibleTxContext) transfer(
	fromUser, fromAccount, toUser string, quantity uint64, comment string,
) (*types.FungibleAccountRecord, error) {
	// No need to validate the existing owner. We will fail later if the owner's account does not exist.
	// If the new owner doesn't exist, then we will fail during the submit phase.
	err := ctx.validateUserId(toUser)
	if err != nil {
		return nil, err
	}

	if toUser == fromUser {
		return nil, common.NewErrInvalid("The recipient of the transfer transaction must be different then the current owner")
	}

	// If account isn't specified, the main account is used
	if fromAccount == "" {
		fromAccount = mainAccount
	}

	txID, err := ctx.TxID()
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to fetch transaction's tx ID")
	}
	newRecord := &types.FungibleAccountRecord{
		Account: txID,
		Owner:   toUser,
		Balance: quantity,
		Comment: comment,
	}

	// Verify that the new generated account does not exist
	_, existed, err := ctx.getAccountRecordRaw(newRecord.Owner, newRecord.Account)
	if err != nil {
		return nil, err
	}
	if existed {
		return nil, common.NewErrInternal("Transaction ID collision. Please retry.")
	}

	fromRecord, err := ctx.getAccountRecord(fromUser, fromAccount)
	if err != nil {
		return nil, err
	}

	if quantity > fromRecord.Balance {
		return nil, common.NewErrInvalid("Insufficient funds in account %v of %v. Requested %v, Balance: %v", fromRecord.Account, fromRecord.Owner, quantity, fromRecord.Balance)
	}

	fromRecord.Balance -= quantity

	if err = ctx.putAccountRecord(fromRecord); err != nil {
		return nil, err
	}
	if err = ctx.putAccountRecord(newRecord); err != nil {
		return nil, err
	}

	return newRecord, nil
}

func (ctx *FungibleTxContext) ltx() (bcdb.Ledger, error) {
	if ctx.ledger != nil {
		return ctx.ledger, nil
	}
	ltx, err := ctx.custodianSession.Ledger()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ledger TX")
	}
	ctx.ledger = ltx
	return ltx, nil
}

type OwnerAccountOperation struct {
	ownerRead   map[string]*oriontypes.DataRead
	ownerWrite  map[string]*oriontypes.DataWrite
	ownerDelete map[string]*oriontypes.DataDelete
	otherRead   map[string]*oriontypes.DataRead
	otherWrite  map[string]*oriontypes.DataWrite
	otherDelete map[string]*oriontypes.DataDelete
}

func (ctx *FungibleTxContext) getMovementTxOperations(owner string, ver *oriontypes.Version) (*OwnerAccountOperation, error) {
	ltx, err := ctx.ltx()
	if err != nil {
		return nil, err
	}
	tx, err := ltx.GetTxContent(ver.BlockNum, ver.TxNum)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read tx data")
	}
	env := tx.GetDataTxEnvelope()
	if env == nil {
		return nil, common.NewErrInternal("movement TX referred to a non data tx")
	}
	if len(env.Payload.DbOperations) == 0 {
		return nil, common.NewErrInternal("movement TX referred to a data tx that had no modifications")
	}
	if len(env.Payload.DbOperations) > 1 {
		return nil, common.NewErrInternal("movement TX referred to a data tx that modified more than one token type")
	}
	dbOp := env.Payload.DbOperations[0]
	if dbOp.DbName != ctx.dbName {
		return nil, common.NewErrInternal("movement TX referred to a data tx that modified the wrong token type")
	}
	ret := &OwnerAccountOperation{
		ownerRead:   map[string]*oriontypes.DataRead{},
		ownerWrite:  map[string]*oriontypes.DataWrite{},
		ownerDelete: map[string]*oriontypes.DataDelete{},
		otherRead:   map[string]*oriontypes.DataRead{},
		otherWrite:  map[string]*oriontypes.DataWrite{},
		otherDelete: map[string]*oriontypes.DataDelete{},
	}

	userAccountPrefix := getAccountKey(owner, "")
	for _, o := range dbOp.DataReads {
		if strings.HasPrefix(o.Key, userAccountPrefix) {
			ret.ownerRead[o.Key] = o
		} else {
			ret.otherRead[o.Key] = o
		}
	}
	for _, o := range dbOp.DataWrites {
		if strings.HasPrefix(o.Key, userAccountPrefix) {
			ret.ownerWrite[o.Key] = o
		} else {
			ret.otherWrite[o.Key] = o
		}
	}
	for _, o := range dbOp.DataDeletes {
		if strings.HasPrefix(o.Key, userAccountPrefix) {
			ret.ownerDelete[o.Key] = o
		} else {
			ret.otherDelete[o.Key] = o
		}
	}
	return ret, nil
}
