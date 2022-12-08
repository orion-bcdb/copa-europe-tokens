// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/copa-europe-tokens/internal/common"
	"github.com/copa-europe-tokens/internal/tokens/mocks"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/stretchr/testify/require"
)

func buildTestOfferUrl(path string, typeId string) string {
	return buildTestUrlWithQuery(common.URLForOffer(path, typeId), url.Values{})
}

func TestHandler_RightsOfferSubmit(t *testing.T) {
	typeId := "aAbBcCdDeEfFgG"
	reqUrl := buildTestUrl(constants.RightsOfferSubmit)
	method := http.MethodPost
	request := types.RightsOfferSubmitRequest{OfferId: typeId}

	t.Run("success", func(t *testing.T) {
		expectedResponse := types.RightsOfferSubmitResponse{OfferId: typeId}

		mockManager := mocks.Operations{}
		mockManager.RightsOfferSubmitTxReturns(&expectedResponse, nil)

		requestHandlerTest(t,
			&mockManager, NewRightsOfferHandler, &request, reqUrl, method,
			http.StatusOK, &expectedResponse, &types.RightsOfferSubmitResponse{},
		)

		calledRequest := mockManager.RightsOfferSubmitTxArgsForCall(0)
		require.Equal(t, &request, calledRequest, "reqUrl: %v", reqUrl)
	})

	requestHandlerErrorsTest(t, NewRightsOfferHandler, func(mockManager *mocks.Operations, err error) {
		mockManager.RightsOfferSubmitTxReturns(nil, err)
	}, request, reqUrl, method, "permission", "invalid", "other")
}

func TestHandler_RightsOfferMint(t *testing.T) {
	typeId := "aAbBcCdDeEfFgG"
	offerId := typeId + ":" + "xYxY"
	reqUrl := buildTestTypeUrl(constants.RightsOfferMint, typeId)
	method := http.MethodPost
	request := types.RightsOfferMintRequest{}

	t.Run("success", func(t *testing.T) {
		expectedResponse := types.RightsOfferMintResponse{
			OfferId: offerId,
		}

		mockManager := mocks.Operations{}
		mockManager.RightsOfferMintReturns(&expectedResponse, nil)

		requestHandlerTest(t,
			&mockManager, NewRightsOfferHandler, &request, reqUrl, method,
			http.StatusOK, &expectedResponse, &types.RightsOfferMintResponse{},
		)

		calledTypeId, calledRequest := mockManager.RightsOfferMintArgsForCall(0)
		require.Equal(t, typeId, calledTypeId, "reqUrl: %v", reqUrl)
		require.Equal(t, &request, calledRequest, "reqUrl: %v", reqUrl)
	})

	requestHandlerErrorsTest(t, NewRightsOfferHandler, func(mockManager *mocks.Operations, err error) {
		mockManager.RightsOfferMintReturns(nil, err)
	}, request, reqUrl, method, "not-found", "permission", "invalid", "other")
}

func TestHandler_RightsOfferUpdate(t *testing.T) {
	typeId := "aAbBcCdDeEfFgG"
	offerId := typeId + ":" + "xYxY"
	reqUrl := buildTestOfferUrl(constants.RightsOfferUpdate, offerId)
	method := http.MethodPost
	request := types.RightsOfferUpdateRequest{}

	t.Run("success", func(t *testing.T) {
		expectedResponse := types.RightsOfferUpdateResponse{
			OfferId: offerId,
		}

		mockManager := mocks.Operations{}
		mockManager.RightsOfferUpdateReturns(&expectedResponse, nil)

		requestHandlerTest(t,
			&mockManager, NewRightsOfferHandler, &request, reqUrl, method,
			http.StatusOK, &expectedResponse, &types.RightsOfferUpdateResponse{},
		)

		calledOfferId, calledRequest := mockManager.RightsOfferUpdateArgsForCall(0)
		require.Equal(t, offerId, calledOfferId, "reqUrl: %v", reqUrl)
		require.Equal(t, &request, calledRequest, "reqUrl: %v", reqUrl)
	})

	requestHandlerErrorsTest(t, NewRightsOfferHandler, func(mockManager *mocks.Operations, err error) {
		mockManager.RightsOfferUpdateReturns(nil, err)
	}, request, reqUrl, method, "not-found", "permission", "invalid", "other")
}

func TestHandler_RightsOfferBuy(t *testing.T) {
	typeId := "aAbBcCdDeEfFgG"
	offerId := typeId + ":" + "xYxY"
	reqUrl := buildTestOfferUrl(constants.RightsOfferBuy, offerId)
	method := http.MethodPost
	request := types.RightsOfferBuyRequest{}

	t.Run("success", func(t *testing.T) {
		expectedResponse := types.RightsOfferBuyResponse{
			OfferId: offerId,
		}

		mockManager := mocks.Operations{}
		mockManager.RightsOfferBuyReturns(&expectedResponse, nil)

		requestHandlerTest(t,
			&mockManager, NewRightsOfferHandler, &request, reqUrl, method,
			http.StatusOK, &expectedResponse, &types.RightsOfferBuyResponse{},
		)

		calledOfferId, calledRequest := mockManager.RightsOfferBuyArgsForCall(0)
		require.Equal(t, offerId, calledOfferId, "reqUrl: %v", reqUrl)
		require.Equal(t, &request, calledRequest, "reqUrl: %v", reqUrl)
	})

	requestHandlerErrorsTest(t, NewRightsOfferHandler, func(mockManager *mocks.Operations, err error) {
		mockManager.RightsOfferBuyReturns(nil, err)
	}, request, reqUrl, method, "not-found", "permission", "invalid", "other")
}

func TestHandler_RightsOfferGet(t *testing.T) {
	typeId := "aAbBcCdDeEfFgG"
	offerId := typeId + ":" + "xYxY"
	reqUrl := buildTestOfferUrl(constants.RightsOfferGet, offerId)
	method := http.MethodGet

	t.Run("success", func(t *testing.T) {
		expectedResponse := types.RightsOfferRecord{
			OfferId: offerId,
		}

		mockManager := mocks.Operations{}
		mockManager.RightsOfferGetReturns(&expectedResponse, nil)

		requestHandlerTest(t,
			&mockManager, NewRightsOfferHandler, nil, reqUrl, method,
			http.StatusOK, &expectedResponse, &types.RightsOfferRecord{},
		)

		calledOfferId := mockManager.RightsOfferGetArgsForCall(0)
		require.Equal(t, offerId, calledOfferId, "reqUrl: %v", reqUrl)
	})

	requestHandlerErrorsTest(t, NewRightsOfferHandler, func(mockManager *mocks.Operations, err error) {
		mockManager.RightsOfferGetReturns(nil, err)
	}, nil, reqUrl, method, "not-found", "permission", "invalid", "other")
}

func TestHandler_RightsOfferQuery(t *testing.T) {
	typeId := "aAbBcCdDeEfFgG"
	offerId := typeId + ":" + "xYxY"
	owner := "user1"
	asset := "asset1"
	path := common.URLForType(constants.RightsOfferQuery, typeId)
	reqQueries := map[string]url.Values{
		"empty": {},
		"owner": {"owner": []string{owner}},
		"asset": {"asset": []string{asset}},
		"all":   {"owner": []string{owner}, "asset": []string{asset}},
	}
	method := http.MethodGet

	for key, query := range reqQueries {
		t.Run(fmt.Sprintf("success:%v", key), func(t *testing.T) {
			expectedResponse := []types.RightsOfferRecord{
				{
					OfferId:  offerId,
					Owner:    owner,
					Asset:    asset,
					Rights:   "rights1",
					Template: "template1",
					Price:    10,
					Currency: "fungible1",
				},
			}

			mockManager := mocks.Operations{}
			mockManager.RightsOfferQueryReturns(expectedResponse, nil)

			reqUrl := buildTestUrlWithQuery(path, query)
			requestHandlerTest(t,
				&mockManager, NewRightsOfferHandler, nil, reqUrl, method,
				http.StatusOK, &expectedResponse, &[]types.RightsOfferRecord{},
			)

			//typeId string, offerId string, owner string, asset string
			calledTypeId, calledOwner, calledAsset := mockManager.RightsOfferQueryArgsForCall(0)
			require.Equal(t, typeId, calledTypeId, "reqUrl: %v", reqUrl)
			require.Equal(t, query.Get("owner"), calledOwner, "reqUrl: %v", reqUrl)
			require.Equal(t, query.Get("asset"), calledAsset, "reqUrl: %v", reqUrl)
		})
	}

	requestHandlerErrorsTest(t, NewRightsOfferHandler, func(mockManager *mocks.Operations, err error) {
		mockManager.RightsOfferQueryReturns(nil, err)
	}, nil, buildTestUrl(path), method, "not-found", "invalid", "other")
}
