// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"encoding/json"
	"net/http"

	"github.com/copa-europe-tokens/internal/tokens"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/gorilla/mux"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
)

type deployHandler struct {
	router  *mux.Router
	manager tokens.Operations
	lg      *logger.SugarLogger
}

func NewDeployHandler(manager tokens.Operations, lg *logger.SugarLogger) *deployHandler {
	handler := &deployHandler{
		router:  mux.NewRouter(),
		manager: manager,
		lg:      lg,
	}

	handler.router.HandleFunc(constants.TokensTypesQuery, handler.queryType).Methods(http.MethodGet)
	handler.router.HandleFunc(constants.TokensTypesEndpoint, handler.listTypes).Methods(http.MethodGet)
	handler.router.HandleFunc(constants.TokensTypesEndpoint, handler.deployType).Methods(http.MethodPost)

	return handler
}

func (d *deployHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	d.router.ServeHTTP(response, request)
}

func (d *deployHandler) listTypes(response http.ResponseWriter, request *http.Request) {
	tokenTypes, err := d.manager.GetTokenTypes()
	if err != nil {
		switch err.(type) {
		case *tokens.ErrInvalid:
			SendHTTPResponse(response, http.StatusBadRequest, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		case *tokens.ErrNotFound:
			SendHTTPResponse(response, http.StatusNotFound, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		default:
			SendHTTPResponse(response, http.StatusInternalServerError, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		}

		return
	}

	SendHTTPResponse(response, http.StatusOK, tokenTypes, d.lg)
}

func (d *deployHandler) queryType(response http.ResponseWriter, request *http.Request) {
	params := mux.Vars(request)
	tokenTypeId := params["typeId"]

	deployResponse, err := d.manager.GetTokenType(tokenTypeId)
	if err != nil {
		switch err.(type) {
		case *tokens.ErrInvalid:
			SendHTTPResponse(response, http.StatusBadRequest, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		case *tokens.ErrNotFound:
			SendHTTPResponse(response, http.StatusNotFound, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		default:
			SendHTTPResponse(response, http.StatusInternalServerError, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		}

		return
	}

	SendHTTPResponse(response, http.StatusOK, deployResponse, d.lg)
}

func (d *deployHandler) deployType(response http.ResponseWriter, request *http.Request) {
	deployRequest := &types.DeployRequest{}

	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(deployRequest); err != nil {
		SendHTTPResponse(response, http.StatusBadRequest, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		return
	}

	deployResponse, err := d.manager.DeployTokenType(deployRequest)
	if err != nil {
		switch err.(type) {
		case *tokens.ErrExist:
			SendHTTPResponse(response, http.StatusConflict, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		case *tokens.ErrInvalid:
			SendHTTPResponse(response, http.StatusBadRequest, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		default:
			SendHTTPResponse(response, http.StatusInternalServerError, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		}

		return
	}

	SendHTTPResponse(response, http.StatusCreated, deployResponse, d.lg)
}
