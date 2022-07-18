// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"net/http"

	"github.com/copa-europe-tokens/internal/tokens"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
)

type statusHandler struct{ operationsHandler }

func NewStatusHandler(manager tokens.Operations, lg *logger.SugarLogger) *statusHandler {
	return &statusHandler{newOperationsHandler(manager, lg)}
}

func (d *statusHandler) ServeHTTP(response http.ResponseWriter, _ *http.Request) {
	stat, err := d.manager.GetStatus()
	if err != nil {
		SendHTTPResponse(response, http.StatusServiceUnavailable, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
	} else {
		SendHTTPResponse(response, http.StatusOK, &types.StatusResponse{Status: stat}, d.lg)
	}
}
