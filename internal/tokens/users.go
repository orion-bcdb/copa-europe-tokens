package tokens

import (
	"github.com/copa-europe-tokens/internal/common"
	"github.com/hyperledger-labs/orion-sdk-go/pkg/bcdb"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
)

type UserContext struct {
	m      *Manager
	userTx bcdb.UsersTxContext
	userId string
	record *oriontypes.User
}

func validateUserId(m *Manager, userId string) error {
	if userId == "" {
		return common.NewErrInvalid("Invalid user ID: empty.")
	}

	if userId == m.config.Users.Custodian.UserID || userId == m.config.Users.Admin.UserID {
		return common.NewErrInvalid("Invalid user ID: the user '%s' cannot participate in token activities.", userId)
	}

	return nil
}

func newUserContextTx(m *Manager, userId string) (*UserContext, error) {
	err := validateUserId(m, userId)
	if err != nil {
		return nil, err
	}

	userTx, err := m.adminSession.UsersTx()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create UserTx")
	}

	return &UserContext{
		m:      m,
		userId: userId,
		userTx: userTx,
	}, nil
}

func newExistingUserContextTx(m *Manager, userId string) (*UserContext, error) {
	ctx, err := newUserContextTx(m, userId)
	if err != nil {
		return nil, err
	}

	err = ctx.fetchExistingUser()
	if err != nil {
		ctx.abort()
		return nil, err
	}

	return ctx, nil
}

// Aborts a TX if it was initiated
func (ctx *UserContext) abort() {
	if ctx != nil && ctx.userTx != nil {
		abort(ctx.userTx)
	}
}

func (ctx *UserContext) commit() error {
	txID, receiptEnv, err := ctx.userTx.Commit(true)
	if err != nil {
		return errors.Wrap(err, "failed to commit user")
	}

	ctx.m.lg.Infof("User [%s] written to database, txID: %s, receipt: %+v", ctx.userId, txID, receiptEnv.GetResponse().GetReceipt())
	return nil
}

func (ctx *UserContext) fetchUser() error {
	if ctx.record != nil {
		return nil
	}

	user, err := ctx.userTx.GetUser(ctx.userId)
	if err != nil {
		return errors.Wrapf(err, "failed to get user: %s", ctx.userId)
	}

	ctx.record = user
	return nil
}

func (ctx *UserContext) fetchExistingUser() error {
	err := ctx.fetchUser()
	if err != nil {
		return nil
	}

	if ctx.record == nil {
		return common.NewErrNotFound("user not found: %s", ctx.userId)
	}

	return nil
}

func (ctx *UserContext) addUserPrivilege(typeIds ...string) error {
	if len(typeIds) == 0 {
		return nil
	}

	err := ctx.fetchExistingUser()
	if err != nil {
		return err
	}

	dbPerm := ctx.record.Privilege.DbPermission
	if dbPerm == nil {
		dbPerm = make(map[string]oriontypes.Privilege_Access)
	}

	for _, typeId := range typeIds {
		dbName, err := getTokenTypeDBName(typeId)
		if err != nil {
			return err
		}
		if _, ok := ctx.m.tokenTypesDBs[dbName]; !ok {
			return common.NewErrInvalid("token type does not exist: %s", typeId)
		}
		dbPerm[dbName] = oriontypes.Privilege_ReadWrite
	}

	ctx.record.Privilege.DbPermission = dbPerm

	err = ctx.userTx.PutUser(ctx.record, nil)
	if err != nil {
		return errors.Wrapf(err, "failed to put user: %s", ctx.record.Id)
	}

	return nil
}
