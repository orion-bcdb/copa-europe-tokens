// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"encoding/json"
	"github.com/copa-europe-tokens/internal/common"
	"net/http"

	"github.com/copa-europe-tokens/internal/tokens"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/gorilla/mux"
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

type RequestHandler func(http.ResponseWriter, *http.Request)
type TokenRequestHandler func(*http.Request, map[string]string) (interface{}, error)

type tokenRouter struct {
	mux.Router
	manager tokens.Operations
	lg      *logger.SugarLogger
}

func newTokenRouter(manager tokens.Operations, lg *logger.SugarLogger) tokenRouter {
	return tokenRouter{
		Router:  *mux.NewRouter(),
		manager: manager,
		lg:      lg,
	}
}

// decode wraps the decoding procedure
func decode(request *http.Request, requestBody interface{}) error {
	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&requestBody); err != nil {
		return common.WrapErrInvalid(err)
	}
	return nil
}

// getParameters fetches the REST URI variables and optional query parameters
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

// sendHttpResponseOrError writes response if not error. Otherwise, writes an HttpResponseErr.
func (d *tokenRouter) sendHttpResponseOrError(
	writer http.ResponseWriter, response interface{}, err error, successStatus int,
) {
	status := successStatus
	if err != nil {
		response = &types.HttpResponseErr{ErrMsg: err.Error()}
		if tokenHttpErr, ok := err.(*common.TokenHttpErr); ok {
			status = tokenHttpErr.StatusCode
		} else {
			status = http.StatusInternalServerError
		}
	}
	SendHTTPResponse(writer, status, response, d.lg)
}

func (d *tokenRouter) genericHandler(handler TokenRequestHandler, successStatus int) RequestHandler {
	return func(writer http.ResponseWriter, request *http.Request) {
		res, err := handler(request, getParameters(request))
		d.sendHttpResponseOrError(writer, res, err, successStatus)
	}
}

func (d *tokenRouter) addHandler(path string, handler TokenRequestHandler, successStatus int) *mux.Route {
	return d.HandleFunc(path, d.genericHandler(handler, successStatus))
}
