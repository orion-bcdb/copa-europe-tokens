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

type eventsHandler struct {
	router  *mux.Router
	manager tokens.Operations
	lg      *logger.SugarLogger
}

func NewAnnotationsHandler(manager tokens.Operations, lg *logger.SugarLogger) *eventsHandler {
	handler := &eventsHandler{
		router:  mux.NewRouter(),
		manager: manager,
		lg:      lg,
	}

	// GET /tokens/annotations/list/[tokenTypeId]?typeId="token-type-id"&owner="user-id"&link="token-id"
	qAll := []string{"type", `{typeId:[A-Za-z0-9_\-]+}`, "owner", "{ownerId:.+}", "link", "{linkId:.+}"}
	handler.router.HandleFunc(constants.TokensAnnotationsEndpoint, handler.listAnnotations).Methods(http.MethodGet).Queries(qAll...)
	qOwner := []string{"type", `{typeId:[A-Za-z0-9_\-]+}`, "owner", "{ownerId:.+}"}
	handler.router.HandleFunc(constants.TokensAnnotationsEndpoint, handler.listAnnotations).Methods(http.MethodGet).Queries(qOwner...)
	qLink := []string{"type", `{typeId:[A-Za-z0-9_\-]+}`, "link", "{linkId:.+}"}
	handler.router.HandleFunc(constants.TokensAnnotationsEndpoint, handler.listAnnotations).Methods(http.MethodGet).Queries(qLink...)

	// GET /tokens/annotations/[annotation-id]
	handler.router.HandleFunc(constants.TokensAnnotationsQuery, handler.queryAnnotation).Methods(http.MethodGet)

	// POST "/tokens/annotations/prepare-register/{typeId}"
	handler.router.HandleFunc(constants.TokensAnnotationsPrepareRegisterMatch, handler.prepareRegister).Methods(http.MethodPost)
	// POST "/tokens/annotations/submit"
	handler.router.HandleFunc(constants.TokensAnnotationsSubmit, handler.submit).Methods(http.MethodPost)

	return handler
}

func (d *eventsHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	d.router.ServeHTTP(response, request)
}

func (d *eventsHandler) queryAnnotation(response http.ResponseWriter, request *http.Request) {
	params := mux.Vars(request)
	annotationId := params["annotationId"]

	record, err := d.manager.GetAnnotation(annotationId)

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

	SendHTTPResponse(response, http.StatusOK, record, d.lg)
}

func (d *eventsHandler) listAnnotations(response http.ResponseWriter, request *http.Request) {
	params := mux.Vars(request)
	typeId := params["typeId"]
	ownerId := params["ownerId"]
	linkId := params["linkId"]

	tokenRecords, err := d.manager.GetAnnotationsByOwnerLink(typeId, ownerId, linkId)

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

func (d *eventsHandler) prepareRegister(response http.ResponseWriter, request *http.Request) {
	params := mux.Vars(request)
	tokenTypeId := params["typeId"]

	regRequest := &types.AnnotationRegisterRequest{}

	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(regRequest); err != nil {
		SendHTTPResponse(response, http.StatusBadRequest, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		return
	}

	regResponse, err := d.manager.PrepareRegister(tokenTypeId, regRequest)
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

	SendHTTPResponse(response, http.StatusOK, regResponse, d.lg)
}

func (d *eventsHandler) submit(response http.ResponseWriter, request *http.Request) {
	submitRequest := &types.SubmitRequest{}

	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(submitRequest); err != nil {
		SendHTTPResponse(response, http.StatusBadRequest, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		return
	}

	resp, err := d.manager.SubmitTx(submitRequest)
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

	SendHTTPResponse(response, http.StatusOK, resp, d.lg)
}
