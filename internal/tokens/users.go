package tokens

import (
	"github.com/copa-europe-tokens/internal/common"
	"github.com/hyperledger-labs/orion-sdk-go/pkg/bcdb"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
)

// UserTxContext handles a user transaction from start to finish
type UserTxContext struct {
	lg           *logger.SugarLogger
	userId       string
	adminSession bcdb.DBSession

	// Evaluated lazily
	userTx bcdb.UsersTxContext
	record *oriontypes.User
}

func newUserTxContext(m *Manager, userId string) (*UserTxContext, error) {
	err := m.validateUserId(userId)
	if err != nil {
		return nil, err
	}
	return &UserTxContext{
		lg:           m.lg,
		adminSession: m.adminSession,
		userId:       userId,
	}, nil
}

// ResetTx creates a new transaction. It will abort previous transaction if existed.
func (ctx *UserTxContext) ResetTx() error {
	if ctx.userTx != nil {
		if err := ctx.userTx.Abort(); err != nil {
			return err
		}
	}

	userTx, err := ctx.adminSession.UsersTx()
	if err != nil {
		return errors.Wrap(err, "failed to create UsersTx")
	}
	ctx.userTx = userTx

	return nil
}

// Returns an existing transaction or creates a new one
func (ctx *UserTxContext) tx() (bcdb.UsersTxContext, error) {
	if ctx.userTx == nil {
		if err := ctx.ResetTx(); err != nil {
			return nil, err
		}
	}
	return ctx.userTx, nil
}

// Abort a TX if it was initiated
func (ctx *UserTxContext) Abort() {
	if ctx != nil && ctx.userTx != nil {
		abort(ctx.userTx)
		ctx.userTx = nil
	}
}

func (ctx *UserTxContext) Commit() error {
	if ctx.userTx == nil {
		return errors.New("Attempt to commit a transaction, but transaction was not created.")
	}

	txID, receiptEnv, err := ctx.userTx.Commit(true)
	if err != nil {
		return errors.Wrap(err, "failed to commit user")
	}

	ctx.lg.Infof("User [%s] written to database, txID: %s, receipt: %+v", ctx.userId, txID, receiptEnv.GetResponse().GetReceipt())
	return nil
}

func (ctx *UserTxContext) getUserRecord() (*oriontypes.User, error) {
	if ctx.record != nil {
		return ctx.record, nil
	}

	tx, err := ctx.tx()
	if err != nil {
		return nil, err
	}

	user, err := tx.GetUser(ctx.userId)
	if err != nil {
		return nil, wrapOrionError(err, "failed to get user [%s]", ctx.userId)
	}

	ctx.record = user
	return ctx.record, nil
}

func (ctx *UserTxContext) Get() (*oriontypes.User, error) {
	record, err := ctx.getUserRecord()
	if err != nil {
		return nil, err
	}

	if record == nil {
		return nil, common.NewErrNotFound("user not found: %s", ctx.userId)
	}

	return record, nil
}

func (ctx *UserTxContext) ValidateUserExists() error {
	_, err := ctx.Get()
	return err
}

func (ctx *UserTxContext) Put(record *oriontypes.User) error {
	tx, err := ctx.tx()
	if err != nil {
		return err
	}
	err = tx.PutUser(record, nil)
	if err != nil {
		return errors.Wrapf(err, "failed to put user: %s", record.Id)
	}
	ctx.record = record

	return nil
}

func (ctx *UserTxContext) AddPrivilege(typeIds ...string) error {
	if len(typeIds) == 0 {
		return nil
	}

	record, err := ctx.Get()
	if err != nil {
		return err
	}

	dbPerm := record.Privilege.DbPermission
	if dbPerm == nil {
		dbPerm = make(map[string]oriontypes.Privilege_Access)
		record.Privilege.DbPermission = dbPerm
	}

	for _, typeId := range typeIds {
		dbName, err := getTokenTypeDBName(typeId)
		if err != nil {
			return err
		}
		dbPerm[dbName] = oriontypes.Privilege_ReadWrite
	}

	return ctx.Put(record)
}
