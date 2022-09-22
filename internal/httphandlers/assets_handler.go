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

type assetsHandler struct {
	router  *mux.Router
	manager tokens.Operations
	lg      *logger.SugarLogger
}

func NewAssetsHandler(manager tokens.Operations, lg *logger.SugarLogger) *assetsHandler {
	handler := &assetsHandler{
		router:  mux.NewRouter(),
		manager: manager,
		lg:      lg,
	}

	// GET /tokens/assets?typeId="token-type-id"&owner="user-id"&link="token-id"
	qAll := []string{"type", `{typeId:[A-Za-z0-9_\-]+}`, "owner", "{ownerId:.+}", "link", "{linkId:.+}"}
	handler.router.HandleFunc(constants.TokensAssetsEndpoint, handler.queryAssetByOwnerLink).Methods(http.MethodGet).Queries(qAll...)
	qOwner := []string{"type", `{typeId:[A-Za-z0-9_\-]+}`, "owner", "{ownerId:.+}"}
	handler.router.HandleFunc(constants.TokensAssetsEndpoint, handler.queryAssetByOwnerLink).Methods(http.MethodGet).Queries(qOwner...)
	qLink := []string{"type", `{typeId:[A-Za-z0-9_\-]+}`, "link", "{linkId:.+}"}
	handler.router.HandleFunc(constants.TokensAssetsEndpoint, handler.queryAssetByOwnerLink).Methods(http.MethodGet).Queries(qLink...)

	// GET /tokens/assets/[token-id]
	handler.router.HandleFunc(constants.TokensAssetsQuery, handler.queryAsset).Methods(http.MethodGet)
	handler.router.HandleFunc(constants.TokensAssetsPrepareMintMatch, handler.prepareMint).Methods(http.MethodPost)
	handler.router.HandleFunc(constants.TokensAssetsPrepareTransferMatch, handler.prepareTransfer).Methods(http.MethodPost)
	handler.router.HandleFunc(constants.TokensAssetsSubmit, handler.submit).Methods(http.MethodPost)

	return handler
}

func (d *assetsHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	d.router.ServeHTTP(response, request)
}

func (d *assetsHandler) queryAsset(response http.ResponseWriter, request *http.Request) {
	params := mux.Vars(request)
	tokenId := params["tokenId"]

	tokenRecord, err := d.manager.GetToken(tokenId)
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

	SendHTTPResponse(response, http.StatusOK, tokenRecord, d.lg)
}

func (d *assetsHandler) queryAssetByOwnerLink(response http.ResponseWriter, request *http.Request) {
	params := mux.Vars(request)
	typeId := params["typeId"]
	ownerId := params["ownerId"]
	linkId := params["linkId"]

	tokenRecords, err := d.manager.GetTokensByOwnerLink(typeId, ownerId, linkId)
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

	SendHTTPResponse(response, http.StatusOK, tokenRecords, d.lg)
}

func (d *assetsHandler) prepareMint(response http.ResponseWriter, request *http.Request) {
	params := mux.Vars(request)
	tokenTypeId := params["typeId"]

	mintRequest := &types.MintRequest{}

	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(mintRequest); err != nil {
		SendHTTPResponse(response, http.StatusBadRequest, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		return
	}

	mintResponse, err := d.manager.PrepareMint(tokenTypeId, mintRequest)
	if err != nil {
		switch err.(type) {
		case *tokens.ErrExist:
			SendHTTPResponse(response, http.StatusConflict, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		case *tokens.ErrInvalid:
			SendHTTPResponse(response, http.StatusBadRequest, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		case *tokens.ErrNotFound:
			SendHTTPResponse(response, http.StatusNotFound, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		default:
			SendHTTPResponse(response, http.StatusInternalServerError, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		}

		return
	}

	SendHTTPResponse(response, http.StatusOK, mintResponse, d.lg)
}

func (d *assetsHandler) prepareTransfer(response http.ResponseWriter, request *http.Request) {
	params := mux.Vars(request)
	tokenId := params["tokenId"]

	transferRequest := &types.TransferRequest{}

	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(transferRequest); err != nil {
		SendHTTPResponse(response, http.StatusBadRequest, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		return
	}

	mintResponse, err := d.manager.PrepareTransfer(tokenId, transferRequest)
	if err != nil {
		switch err.(type) {
		case *tokens.ErrPermission:
			SendHTTPResponse(response, http.StatusForbidden, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		case *tokens.ErrInvalid:
			SendHTTPResponse(response, http.StatusBadRequest, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		case *tokens.ErrNotFound:
			SendHTTPResponse(response, http.StatusNotFound, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		default:
			SendHTTPResponse(response, http.StatusInternalServerError, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		}

		return
	}

	SendHTTPResponse(response, http.StatusOK, mintResponse, d.lg)
}

func (d *assetsHandler) submit(response http.ResponseWriter, request *http.Request) {
	submitRequest := &types.SubmitRequest{}

	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(submitRequest); err != nil {
		SendHTTPResponse(response, http.StatusBadRequest, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		return
	}

	submitResponse, err := d.manager.SubmitTx(submitRequest)
	if err != nil {
		switch err.(type) {
		case *tokens.ErrExist:
			SendHTTPResponse(response, http.StatusConflict, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		case *tokens.ErrInvalid:
			SendHTTPResponse(response, http.StatusBadRequest, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		case *tokens.ErrNotFound:
			SendHTTPResponse(response, http.StatusNotFound, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		case *tokens.ErrPermission:
			SendHTTPResponse(response, http.StatusForbidden, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		default:
			SendHTTPResponse(response, http.StatusInternalServerError, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		}

		return
	}

	SendHTTPResponse(response, http.StatusOK, submitResponse, d.lg)
}
