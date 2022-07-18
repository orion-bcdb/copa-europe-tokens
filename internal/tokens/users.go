package tokens

import (
	"encoding/base64"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/hyperledger-labs/orion-sdk-go/pkg/bcdb"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
)

type UserContext struct {
	m      *Manager
	userTx bcdb.UsersTxContext
	userId string
}

func (m *Manager) validateUserId(userId string) error {
	if userId == "" {
		return NewErrInvalid("Invalid user ID: empty.")
	}

	if userId == m.config.Users.Custodian.UserID || userId == m.config.Users.Admin.UserID {
		return NewErrInvalid("Invalid user ID: the user '%s' cannot participate in token activities.", userId)
	}

	return nil
}

func (m *Manager) newUserContextTx(userId string) (*UserContext, error) {
	err := m.validateUserId(userId)
	if err != nil {
		return nil, err
	}

	ctx := UserContext{
		m:      m,
		userId: userId,
	}

	return &ctx, ctx.initTx()
}

func (ctx *UserContext) initTx() error {
	if ctx.userTx != nil {
		abort(ctx.userTx)
	}

	userTx, err := ctx.m.adminSession.UsersTx()
	if err != nil {
		return errors.Wrap(err, "failed to create UserTx")
	}
	ctx.userTx = userTx

	return nil
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

func (m *Manager) validateUserExists(userId string) error {
	ctx, err := m.newUserContextTx(userId)
	if err != nil {
		return err
	}
	defer ctx.abort()

	_, err = ctx.getExistingUser()
	return err
}

func (ctx *UserContext) getExistingUser() (*oriontypes.User, error) {
	user, err := ctx.userTx.GetUser(ctx.userId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user: %s", ctx.userId)
	}

	if user == nil {
		return nil, NewErrNotFound("user not found: %s", ctx.userId)
	}

	return user, nil
}

func (m *Manager) writeUser(userRecord *types.UserRecord, insert bool) error {
	ctx, err := m.newUserContextTx(userRecord.Identity)
	if err != nil {
		return err
	}
	defer ctx.abort()

	err = ctx.write(userRecord, insert)
	if err != nil {
		return err
	}

	return ctx.commit()
}

func (ctx *UserContext) write(userRecord *types.UserRecord, insert bool) error {
	user, err := ctx.userTx.GetUser(ctx.userId)
	if err != nil {
		return errors.Wrapf(err, "failed to get user: %s", ctx.userId)
	}

	if insert && user != nil {
		return NewErrExist("user already exists: %s", ctx.userId)
	}

	if !insert && user == nil {
		return NewErrNotFound("user not found: %s", ctx.userId)
	}

	cert, err := base64.StdEncoding.DecodeString(userRecord.Certificate)
	if err != nil {
		return NewErrInvalid("failed to decode certificate: %s", err.Error())
	}

	privilege := &oriontypes.Privilege{
		DbPermission: make(map[string]oriontypes.Privilege_Access),
		Admin:        false,
	}

	// all token types or a partial list
	if len(userRecord.Privilege) == 0 {
		for db := range ctx.m.tokenTypesDBs {
			privilege.DbPermission[db] = oriontypes.Privilege_ReadWrite
		}
	} else {
		for _, tt := range userRecord.Privilege {
			db, err := getTokenTypeDBName(tt)
			if err != nil {
				return err
			}

			if _, ok := ctx.m.tokenTypesDBs[db]; !ok {
				return NewErrInvalid("token type does not exist: %s", tt)
			}
			privilege.DbPermission[db] = oriontypes.Privilege_ReadWrite
		}
	}

	user = &oriontypes.User{
		Id:          userRecord.Identity,
		Certificate: cert,
		Privilege:   privilege,
	}

	err = ctx.userTx.PutUser(user, nil)
	if err != nil {
		return errors.Wrapf(err, "failed to put user: %s", user.Id)
	}

	return nil
}

func (m *Manager) addUserPrivilege(userId string, typeIds ...string) error {
	ctx, err := m.newUserContextTx(userId)
	if err != nil {
		return err
	}
	defer ctx.abort()

	err = ctx.addPrivilege(typeIds...)
	if err != nil {
		return err
	}

	return ctx.commit()
}

func (ctx *UserContext) addPrivilege(typeIds ...string) error {
	if len(typeIds) == 0 {
		return nil
	}

	user, err := ctx.getExistingUser()
	if err != nil {
		return err
	}

	dbPerm := user.Privilege.DbPermission
	if dbPerm == nil {
		dbPerm = make(map[string]oriontypes.Privilege_Access)
	}

	for _, typeId := range typeIds {
		dbName, err := getTokenTypeDBName(typeId)
		if err != nil {
			return err
		}
		if _, ok := ctx.m.tokenTypesDBs[dbName]; !ok {
			return NewErrInvalid("token type does not exist: %s", typeId)
		}
		dbPerm[dbName] = oriontypes.Privilege_ReadWrite
	}

	user.Privilege.DbPermission = dbPerm

	err = ctx.userTx.PutUser(user, nil)
	if err != nil {
		return errors.Wrapf(err, "failed to put user: %s", user.Id)
	}

	return nil
}

// ====================================================
// Users functional API implementation
// ====================================================

func (m *Manager) AddUser(userRecord *types.UserRecord) error {
	m.lg.Debugf("Add user: %v", userRecord)
	return m.writeUser(userRecord, true)
}

func (m *Manager) UpdateUser(userRecord *types.UserRecord) error {
	m.lg.Debugf("Update user: %v", userRecord)
	return m.writeUser(userRecord, false)
}

func (m *Manager) RemoveUser(userId string) error {
	m.lg.Debugf("Removing user: %v", userId)

	ctx, err := m.newUserContextTx(userId)
	if err != nil {
		return err
	}
	defer ctx.abort()

	_, err = ctx.getExistingUser()
	if err != nil {
		return err
	}

	err = ctx.userTx.RemoveUser(userId)
	if err != nil {
		return errors.Wrapf(err, "failed to remove user: %s", userId)
	}

	return ctx.commit()
}

func (m *Manager) GetUser(userId string) (*types.UserRecord, error) {
	m.lg.Debugf("Getting user: %v", userId)

	ctx, err := m.newUserContextTx(userId)
	if err != nil {
		return nil, err
	}
	defer ctx.abort()

	user, err := ctx.getExistingUser()
	if err != nil {
		return nil, err
	}

	userRecord := &types.UserRecord{
		Identity:    user.Id,
		Certificate: base64.StdEncoding.EncodeToString(user.Certificate),
		Privilege:   nil,
	}

	for dbName := range user.Privilege.GetDbPermission() {
		typeId, err := getTokenTypeId(dbName)
		if err != nil {
			return nil, err
		}
		userRecord.Privilege = append(userRecord.Privilege, typeId)
	}

	return userRecord, nil
}
