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

type assetsHandler struct{ operationsHandler }

func NewAssetsHandler(manager tokens.Operations, lg *logger.SugarLogger) *assetsHandler {
	d := assetsHandler{newOperationsHandler(manager, lg)}

	// GET /tokens/assets/?type=[token-type-id],owner=[user-id]
	d.addHandler(constants.TokensAssetsEndpoint, d.queryAssetByOwner, http.StatusOK).Methods(http.MethodGet).Queries(
		"type", `{typeId:[A-Za-z0-9_\-]+}`, "owner", "{ownerId:.+}")
	// GET /tokens/assets/[token-id]
	d.addHandler(constants.TokensAssetsQuery, d.queryAsset, http.StatusOK).Methods(http.MethodGet)
	d.addHandler(constants.TokensAssetsPrepareMintMatch, d.prepareMint, http.StatusOK).Methods(http.MethodPost)
	d.addHandler(constants.TokensAssetsPrepareTransferMatch, d.prepareTransfer, http.StatusOK).Methods(http.MethodPost)
	d.addHandler(constants.TokensAssetsSubmit, d.submit, http.StatusOK).Methods(http.MethodPost)

	return &d
}

func (d *assetsHandler) queryAsset(_ *http.Request, params map[string]string) (interface{}, error) {
	return d.manager.GetToken(params[tokenIdPlaceholder])
}

func (d *assetsHandler) queryAssetByOwner(_ *http.Request, params map[string]string) (interface{}, error) {
	return d.manager.GetTokensByOwner(params["typeId"], params["ownerId"])
}

func (d *assetsHandler) prepareMint(request *http.Request, params map[string]string) (interface{}, error) {
	mintRequest := &types.MintRequest{}
	if err := decode(request, mintRequest); err != nil {
		return nil, err
	}
	return d.manager.PrepareMint(params[typeIdPlaceholder], mintRequest)
}

func (d *assetsHandler) prepareTransfer(request *http.Request, params map[string]string) (interface{}, error) {
	transferRequest := &types.TransferRequest{}
	if err := decode(request, transferRequest); err != nil {
		return nil, err
	}
	return d.manager.PrepareTransfer(params[tokenIdPlaceholder], transferRequest)
}

func (d *assetsHandler) submit(request *http.Request, _ map[string]string) (interface{}, error) {
	submitRequest := &types.SubmitRequest{}
	if err := decode(request, submitRequest); err != nil {
		return nil, err
	}
	return d.manager.SubmitTx(submitRequest)
}
