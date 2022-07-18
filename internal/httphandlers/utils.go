// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"encoding/json"
	"github.com/copa-europe-tokens/internal/tokens"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/gorilla/mux"
	"net/http"

	"github.com/hyperledger-labs/orion-server/pkg/logger"
)

type RequestHandler func(http.ResponseWriter, *http.Request)
type TokenRequestHandler func(*http.Request, map[string]string) (interface{}, error)

type operationsHandler struct {
	mux.Router
	manager tokens.Operations
	lg      *logger.SugarLogger
}

func newOperationsHandler(manager tokens.Operations, lg *logger.SugarLogger) operationsHandler {
	return operationsHandler{
		Router:  *mux.NewRouter(),
		manager: manager,
		lg:      lg,
	}
}

func decode(request *http.Request, requestBody interface{}) error {
	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&requestBody); err != nil {
		return tokens.WrapErrInvalid(err)
	}
	return nil
}

// SendHttpResponseOrError writes response if not error. Otherwise, writes an HttpResponseErr.
func SendHttpResponseOrError(
	writer http.ResponseWriter, response interface{}, err error, successStatus int, lg *logger.SugarLogger,
) {
	status := successStatus
	if err != nil {
		response = &types.HttpResponseErr{ErrMsg: err.Error()}
		if tokenHttpErr, ok := err.(*tokens.TokenHttpErr); ok {
			status = tokenHttpErr.StatusCode
		} else {
			status = http.StatusInternalServerError
		}
	}
	SendHTTPResponse(writer, status, response, lg)
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

func getParameters(request *http.Request) map[string]string {
	// Get rest URI vars
	params := mux.Vars(request)

	// Get optional query parameters
	query := request.URL.Query()
	for key := range query {
		params[key] = query.Get(key)
	}

	return params
}

func (d *operationsHandler) genericHandler(handler TokenRequestHandler, successStatus int) RequestHandler {
	return func(writer http.ResponseWriter, request *http.Request) {
		params := getParameters(request)
		res, err := handler(request, params)
		SendHttpResponseOrError(writer, res, err, successStatus, d.lg)
	}
}

func (d *operationsHandler) addHandler(path string, handler TokenRequestHandler, successStatus int) *mux.Route {
	return d.HandleFunc(path, d.genericHandler(handler, successStatus))
}
