package httphandlers

import (
	"net/http"

	"github.com/copa-europe-tokens/internal/tokens"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
)

const offerIdPlaceholder = "offerId"

type rightsOfferHandler struct{ tokenRouter }

func NewRightsOfferHandler(manager tokens.Operations, lg *logger.SugarLogger) http.Handler {
	d := rightsOfferHandler{newTokenRouter(manager, lg)}
	d.StrictSlash(true)
	d.addHandler(constants.RightsOfferMint, d.handleMint, http.StatusOK).Methods(http.MethodPost)
	d.addHandler(constants.RightsOfferUpdate, d.handleUpdate, http.StatusOK).Methods(http.MethodPost)
	d.addHandler(constants.RightsOfferBuy, d.handleBuy, http.StatusOK).Methods(http.MethodPost)
	d.addHandler(constants.RightsOfferSubmit, d.handleSubmit, http.StatusOK).Methods(http.MethodPost)
	d.addHandler(constants.RightsOfferGet, d.handleGet, http.StatusOK).Methods(http.MethodGet)
	d.addHandler(constants.RightsOfferQuery, d.handleQuery, http.StatusOK).Methods(http.MethodGet)
	return &d
}

func (d *rightsOfferHandler) handleMint(request *http.Request, params map[string]string) (interface{}, error) {
	requestBody := types.RightsOfferMintRequest{}
	if err := decode(request, &requestBody); err != nil {
		return nil, err
	}
	return d.manager.RightsOfferMint(params[typeIdPlaceholder], &requestBody)
}

func (d *rightsOfferHandler) handleUpdate(request *http.Request, params map[string]string) (interface{}, error) {
	requestBody := types.RightsOfferUpdateRequest{}
	if err := decode(request, &requestBody); err != nil {
		return nil, err
	}
	return d.manager.RightsOfferUpdate(params[offerIdPlaceholder], &requestBody)
}

func (d *rightsOfferHandler) handleBuy(request *http.Request, params map[string]string) (interface{}, error) {
	requestBody := types.RightsOfferBuyRequest{}
	if err := decode(request, &requestBody); err != nil {
		return nil, err
	}
	return d.manager.RightsOfferBuy(params[offerIdPlaceholder], &requestBody)
}

func (d *rightsOfferHandler) handleGet(_ *http.Request, params map[string]string) (interface{}, error) {
	return d.manager.RightsOfferGet(params[offerIdPlaceholder])
}

func (d *rightsOfferHandler) handleQuery(_ *http.Request, params map[string]string) (interface{}, error) {
	return d.manager.RightsOfferQuery(params[typeIdPlaceholder], params["owner"], params["asset"])
}

func (d *rightsOfferHandler) handleSubmit(request *http.Request, _ map[string]string) (interface{}, error) {
	submitRequest := types.RightsOfferSubmitRequest{}
	if err := decode(request, &submitRequest); err != nil {
		return nil, err
	}
	return d.manager.RightsOfferSubmitTx(&submitRequest)
}
