// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"encoding/json"
	"net/http"

	"github.com/copa-europe-tokens/internal/tokens"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
)

type statusHandler struct {
	manager *tokens.Manager
	lg      *logger.SugarLogger
}

func NewStatusHandler(manager *tokens.Manager, lg *logger.SugarLogger) *statusHandler {
	return &statusHandler{
		manager: manager,
		lg:      lg}
}

func (d *statusHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	stat, err := d.manager.GetStatus()
	if err != nil {
		SendHTTPResponse(response, http.StatusServiceUnavailable, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
	}
	SendHTTPResponse(response, http.StatusOK, &types.StatusResponse{Status: stat}, d.lg)
}

// SendHTTPResponse writes HTTP response back including HTTP code number and encode payload
func SendHTTPResponse(w http.ResponseWriter, code int, payload interface{}, lg *logger.SugarLogger) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if _, err := w.Write(response); err != nil {
		lg.Warningf("Failed to write response [%v] to the response writer", w)
	}
}
