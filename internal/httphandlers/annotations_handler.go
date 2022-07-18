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
	"github.com/pkg/errors"
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

	handler.router.HandleFunc(constants.TokensAnnotationsPrepareRegisterMatch, handler.prepareRegister).Methods(http.MethodPost)
	handler.router.HandleFunc(constants.TokensAssetsSubmit, handler.submit).Methods(http.MethodPost)

	return handler
}

func (d *eventsHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	d.router.ServeHTTP(response, request)
}

func (d *eventsHandler) queryAnnotation(response http.ResponseWriter, request *http.Request) {
	params := mux.Vars(request)
	annotationId := params["annotationId"]

	//TODO call manager
	err := errors.Errorf("not implemented yet: queryAnnotation: %s", annotationId)
	//TODO return eventRecord
	SendHttpResponseOrError(response, &types.AnnotationRecord{}, err, http.StatusOK, d.lg)
}

func (d *eventsHandler) listAnnotations(response http.ResponseWriter, request *http.Request) {
	params := mux.Vars(request)
	typeId := params["typeId"]

	//TODO call manager
	err := errors.Errorf("not implemented yet: listAnnotations: %s", typeId)
	//TODO return eventRecord
	SendHttpResponseOrError(response, &types.AnnotationRecord{}, err, http.StatusOK, d.lg)
}

func (d *eventsHandler) prepareRegister(response http.ResponseWriter, request *http.Request) {
	params := mux.Vars(request)
	typeId := params["typeId"]

	//TODO call manager
	err := errors.Errorf("not implemented yet: %s", typeId)
	//TODO return registerResponse
	SendHttpResponseOrError(response, &types.AnnotationRecord{}, err, http.StatusOK, d.lg)
}

func (d *eventsHandler) submit(response http.ResponseWriter, request *http.Request) {
	submitRequest := &types.SubmitRequest{}

	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(submitRequest); err != nil {
		SendHTTPResponse(response, http.StatusBadRequest, &types.HttpResponseErr{ErrMsg: err.Error()}, d.lg)
		return
	}

	//TODO call manager
	err := errors.New("not implemented yet")
	//TODO submit
	SendHttpResponseOrError(response, &types.SubmitResponse{}, err, http.StatusOK, d.lg)
}
