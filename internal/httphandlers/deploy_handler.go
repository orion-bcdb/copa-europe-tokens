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

type deployHandler struct{ operationsHandler }

func NewDeployHandler(manager tokens.Operations, lg *logger.SugarLogger) *deployHandler {
	d := deployHandler{newOperationsHandler(manager, lg)}

	d.addHandler(constants.TokensTypesQuery, d.queryType, http.StatusOK).Methods(http.MethodGet)
	d.addHandler(constants.TokensTypesEndpoint, d.listTypes, http.StatusOK).Methods(http.MethodGet)
	d.addHandler(constants.TokensTypesEndpoint, d.deployType, http.StatusCreated).Methods(http.MethodPost)

	return &d
}

func (d *deployHandler) listTypes(_ *http.Request, _ map[string]string) (interface{}, error) {
	return d.manager.GetTokenTypes()
}

func (d *deployHandler) queryType(_ *http.Request, params map[string]string) (interface{}, error) {
	return d.manager.GetTokenType(params[typeIdPlaceholder])
}

func (d *deployHandler) deployType(request *http.Request, _ map[string]string) (interface{}, error) {
	deployRequest := &types.DeployRequest{}
	if err := decode(request, deployRequest); err != nil {
		return nil, err
	}
	return d.manager.DeployTokenType(deployRequest)
}
