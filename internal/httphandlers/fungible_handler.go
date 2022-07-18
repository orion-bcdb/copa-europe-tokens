package httphandlers

import (
	"fmt"
	"github.com/copa-europe-tokens/internal/tokens"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/gorilla/mux"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"net/http"
)

type fungibleHandler struct{ operationsHandler }

func (d *fungibleHandler) addTypeHandler(
	path constants.ResourceURI, handler TokenRequestHandler, successStatus int,
) *mux.Route {
	placeholder := fmt.Sprintf("{%s}", typeIdPlaceholder)
	return d.addHandler(path.ForResource(placeholder), handler, successStatus)
}

func NewFungibleHandler(manager tokens.Operations, lg *logger.SugarLogger) *fungibleHandler {
	d := fungibleHandler{newOperationsHandler(manager, lg)}
	d.StrictSlash(true)
	d.addHandler(constants.FungibleDeploy, d.handleDeploy, http.StatusCreated).Methods(http.MethodPost)
	d.addTypeHandler(constants.FungibleDescribe, d.handleDescribe, http.StatusOK).Methods(http.MethodGet)
	d.addTypeHandler(constants.FungibleMint, d.handleMint, http.StatusOK).Methods(http.MethodPost)
	d.addTypeHandler(constants.FungibleTransfer, d.handleTransfer, http.StatusOK).Methods(http.MethodPost)
	d.addTypeHandler(constants.FungibleConsolidate, d.handleConsolidate, http.StatusOK).Methods(http.MethodPost)
	d.addTypeHandler(constants.FungibleAccounts, d.handleAccounts, http.StatusOK).Methods(http.MethodGet)
	return &d
}

func (d *fungibleHandler) handleDeploy(request *http.Request, _ map[string]string) (interface{}, error) {
	requestBody := types.FungibleDeployRequest{}
	if err := decode(request, &requestBody); err != nil {
		return nil, err
	}
	return d.manager.FungibleDeploy(&requestBody)
}

func (d *fungibleHandler) handleDescribe(_ *http.Request, params map[string]string) (interface{}, error) {
	return d.manager.FungibleDescribe(params[typeIdPlaceholder])
}

func (d *fungibleHandler) handleMint(request *http.Request, params map[string]string) (interface{}, error) {
	requestBody := types.FungibleMintRequest{}
	if err := decode(request, &requestBody); err != nil {
		return nil, err
	}
	return d.manager.FungiblePrepareMint(params[typeIdPlaceholder], &requestBody)
}

func (d *fungibleHandler) handleTransfer(request *http.Request, params map[string]string) (interface{}, error) {
	requestBody := types.FungibleTransferRequest{}
	if err := decode(request, &requestBody); err != nil {
		return nil, err
	}
	return d.manager.FungiblePrepareTransfer(params[typeIdPlaceholder], &requestBody)
}

func (d *fungibleHandler) handleConsolidate(request *http.Request, params map[string]string) (interface{}, error) {
	requestBody := types.FungibleConsolidateRequest{}
	if err := decode(request, &requestBody); err != nil {
		return nil, err
	}
	return d.manager.FungiblePrepareConsolidate(params[typeIdPlaceholder], &requestBody)
}

func (d *fungibleHandler) handleAccounts(_ *http.Request, params map[string]string) (interface{}, error) {
	return d.manager.FungibleAccounts(params[typeIdPlaceholder], params["owner"], params["account"])
}
