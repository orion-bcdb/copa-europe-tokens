// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"encoding/json"
	"net/http"

	"github.com/hyperledger-labs/orion-server/pkg/logger"
)

// SendHTTPResponse writes HTTP response back including HTTP code number and encode payload
func SendHTTPResponse(w http.ResponseWriter, code int, payload interface{}, lg *logger.SugarLogger) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if _, err := w.Write(response); err != nil {
		lg.Warningf("Failed to write response [%v] to the response writer", w)
	}
}
