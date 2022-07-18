// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"net/http"

	"github.com/copa-europe-tokens/internal/tokens"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
)

type userHandler struct{ operationsHandler }

func NewUserHandler(manager tokens.Operations, lg *logger.SugarLogger) *userHandler {
	d := userHandler{newOperationsHandler(manager, lg)}

	d.addHandler(constants.TokensUsersEndpoint, d.addUser, http.StatusCreated).Methods(http.MethodPost)
	d.addHandler(constants.TokensUsersMatch, d.queryUser, http.StatusOK).Methods(http.MethodGet)
	d.addHandler(constants.TokensUsersMatch, d.updateUser, http.StatusOK).Methods(http.MethodPut)
	d.addHandler(constants.TokensUsersMatch, d.deleteUser, http.StatusOK).Methods(http.MethodDelete)

	return &d
}

func (d *userHandler) addUser(request *http.Request, _ map[string]string) (interface{}, error) {
	userRecord := &types.UserRecord{}
	if err := decode(request, userRecord); err != nil {
		return nil, err
	}
	err := d.manager.AddUser(userRecord)
	return nil, err
}

func (d *userHandler) deleteUser(_ *http.Request, params map[string]string) (interface{}, error) {
	err := d.manager.RemoveUser(params[userIdPlaceholder])
	return nil, err
}

func (d *userHandler) queryUser(_ *http.Request, params map[string]string) (interface{}, error) {
	return d.manager.GetUser(params[userIdPlaceholder])
}

func (d *userHandler) updateUser(request *http.Request, params map[string]string) (interface{}, error) {
	userRecord := &types.UserRecord{}
	if err := decode(request, userRecord); err != nil {
		return nil, err
	}

	if params[userIdPlaceholder] != userRecord.Identity {
		return nil, tokens.NewErrInvalid("inconsistent userId parameter versus user record identity")
	}

	err := d.manager.UpdateUser(userRecord)
	return nil, err
}
