// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/copa-europe-tokens/internal/common"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/copa-europe-tokens/internal/tokens/mocks"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func buildTestUrlWithQuery(path string, query url.Values) string {
	reqUrl := &url.URL{
		Scheme:   "http",
		Host:     "server1.example.com:6091",
		Path:     path,
		RawQuery: query.Encode(),
	}
	return reqUrl.String()
}

func buildTestUrl(path string) string {
	return buildTestUrlWithQuery(path, url.Values{})
}

func buildTestTypeUrl(path string, typeId string) string {
	return buildTestUrlWithQuery(common.URLForType(path, typeId), url.Values{})
}

// requireResponse validates the status code and the response fields
func requireResponse(t *testing.T, expectedStatus int, expectedResponse interface{}, resp *httptest.ResponseRecorder, responseBody interface{}) {
	// Read the response body into a buffer, so we could print it in case of an error
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(resp.Body)
	require.NoError(t, err)

	require.Equal(t, expectedStatus, resp.Code, "Status: %d, Response: %s", resp.Code, buf.String())
	// If status code matches, then attempt to validate the response fields
	decoder := json.NewDecoder(buf)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&responseBody)
	require.NoError(t, err, "Status: %d, Response: %s", resp.Code, buf.String())

	require.Equal(t, expectedResponse, responseBody, "Response: %+v", responseBody)
}

func requestHandlerTest(
	t *testing.T, mockManager *mocks.Operations,
	request interface{},
	reqUrl string,
	method string,
	expectedStatus int,
	expectedResponse interface{},
	actualResponseBody interface{},
) {
	h := NewFungibleHandler(mockManager, testLogger(t, "debug"))
	require.NotNil(t, h)

	requestBytes, err := json.Marshal(request)
	require.NoError(t, err)

	txReader := bytes.NewReader(requestBytes)
	require.NotNil(t, txReader)

	responseRecorder := httptest.NewRecorder()
	require.NotNil(t, responseRecorder)

	req, err := http.NewRequest(method, reqUrl, txReader)
	require.NoError(t, err)

	h.ServeHTTP(responseRecorder, req)

	requireResponse(t, expectedStatus, expectedResponse, responseRecorder, actualResponseBody)
}

var ERRORS = map[string]error{
	"exist":      common.NewErrExist("exists"),
	"invalid":    common.NewErrInvalid("invalid"),
	"not-found":  common.NewErrNotFound("not-found"),
	"permission": common.NewErrPermission("permission"),
	"other":      errors.New("other"),
}

var STATUS = map[string]int{
	"exist":      http.StatusConflict,
	"invalid":    http.StatusBadRequest,
	"not-found":  http.StatusNotFound,
	"permission": http.StatusForbidden,
	"other":      http.StatusInternalServerError,
}

func requestHandlerErrorsTest(
	t *testing.T, setMockErrorFunc func(*mocks.Operations, error),
	request interface{},
	reqUrl string,
	method string,
	errors ...string,
) {
	for _, e := range errors {
		t.Run(fmt.Sprintf("error:%v", e), func(t *testing.T) {
			expectedErr := ERRORS[e]
			expectedStatus := STATUS[e]
			expectedResponse := types.HttpResponseErr{ErrMsg: expectedErr.Error()}

			mockManager := mocks.Operations{}
			setMockErrorFunc(&mockManager, expectedErr)

			requestHandlerTest(t,
				&mockManager, &request, reqUrl, method,
				expectedStatus, &expectedResponse, &types.HttpResponseErr{},
			)
		})
	}
}

func TestHandler_FungibleDeploy(t *testing.T) {
	reqUrl := buildTestUrl(constants.FungibleDeploy)
	method := http.MethodPost
	request := types.FungibleDeployRequest{
		Name:         "myNFT",
		Description:  "my NFT is best",
		ReserveOwner: "me",
	}

	t.Run("success", func(t *testing.T) {
		expectedResponse := types.FungibleDeployResponse{
			TypeId:       "aAbBcCdDeEfFgG",
			Name:         request.Name,
			Description:  request.Description,
			Supply:       0,
			ReserveOwner: request.ReserveOwner,
			Url:          "/fungible/aAbBcCdDeEfFgG",
		}

		mockManager := mocks.Operations{}
		mockManager.FungibleDeployReturns(&expectedResponse, nil)

		requestHandlerTest(t,
			&mockManager, &request, reqUrl, method,
			http.StatusCreated, &expectedResponse, &types.FungibleDeployResponse{},
		)

		calledRequest := mockManager.FungibleDeployArgsForCall(0)
		require.Equal(t, &request, calledRequest, "reqUrl: %v", reqUrl)
	})

	requestHandlerErrorsTest(t, func(mockManager *mocks.Operations, err error) {
		mockManager.FungibleDeployReturns(nil, err)
	}, request, reqUrl, method, "exist", "invalid", "other")
}

func TestHandler_FungibleSubmit(t *testing.T) {
	typeId := "aAbBcCdDeEfFgG"
	reqUrl := buildTestUrl(constants.FungibleSubmit)
	method := http.MethodPost
	request := types.FungibleSubmitRequest{TypeId: typeId}

	t.Run("success", func(t *testing.T) {
		expectedResponse := types.FungibleSubmitResponse{TypeId: typeId}

		mockManager := mocks.Operations{}
		mockManager.FungibleSubmitTxReturns(&expectedResponse, nil)

		requestHandlerTest(t,
			&mockManager, &request, reqUrl, method,
			http.StatusOK, &expectedResponse, &types.FungibleSubmitResponse{},
		)

		calledRequest := mockManager.FungibleSubmitTxArgsForCall(0)
		require.Equal(t, &request, calledRequest, "reqUrl: %v", reqUrl)
	})

	requestHandlerErrorsTest(t, func(mockManager *mocks.Operations, err error) {
		mockManager.FungibleSubmitTxReturns(nil, err)
	}, request, reqUrl, method, "permission", "invalid", "other")
}

func TestHandler_FungibleDescribe(t *testing.T) {
	typeId := "aAbBcCdDeEfFgG"
	reqUrl := buildTestTypeUrl(constants.FungibleTypeRoot, typeId)
	method := http.MethodGet
	request := struct{}{}

	t.Run("success", func(t *testing.T) {
		expectedResponse := types.FungibleDescribeResponse{
			TypeId:       typeId,
			Name:         "myNFT",
			Description:  "my NFT is best",
			ReserveOwner: "me",
			Supply:       10,
			Url:          "/fungible/aAbBcCdDeEfFgG",
		}

		mockManager := mocks.Operations{}
		mockManager.FungibleDescribeReturns(&expectedResponse, nil)

		requestHandlerTest(t,
			&mockManager, &request, reqUrl, method,
			http.StatusOK, &expectedResponse, &types.FungibleDescribeResponse{},
		)

		calledTypeId := mockManager.FungibleDescribeArgsForCall(0)
		require.Equal(t, typeId, calledTypeId, "reqUrl: %v", reqUrl)
	})

	requestHandlerErrorsTest(t, func(mockManager *mocks.Operations, err error) {
		mockManager.FungibleDescribeReturns(nil, err)
	}, request, reqUrl, method, "not-found", "invalid", "other")
}

func TestHandler_FungibleMint(t *testing.T) {
	typeId := "aAbBcCdDeEfFgG"
	reqUrl := buildTestTypeUrl(constants.FungibleMint, typeId)
	method := http.MethodPost
	request := types.FungibleMintRequest{}

	t.Run("success", func(t *testing.T) {
		expectedResponse := types.FungibleMintResponse{
			TypeId: typeId,
		}

		mockManager := mocks.Operations{}
		mockManager.FungiblePrepareMintReturns(&expectedResponse, nil)

		requestHandlerTest(t,
			&mockManager, &request, reqUrl, method,
			http.StatusOK, &expectedResponse, &types.FungibleMintResponse{},
		)

		calledTypeId, calledRequest := mockManager.FungiblePrepareMintArgsForCall(0)
		require.Equal(t, typeId, calledTypeId, "reqUrl: %v", reqUrl)
		require.Equal(t, &request, calledRequest, "reqUrl: %v", reqUrl)
	})

	requestHandlerErrorsTest(t, func(mockManager *mocks.Operations, err error) {
		mockManager.FungiblePrepareMintReturns(nil, err)
	}, request, reqUrl, method, "not-found", "permission", "invalid", "other")
}

func TestHandler_FungibleTransfer(t *testing.T) {
	typeId := "aAbBcCdDeEfFgG"
	reqUrl := buildTestTypeUrl(constants.FungibleTransfer, typeId)
	method := http.MethodPost
	request := types.FungibleTransferRequest{
		Owner:    "user1",
		NewOwner: "user2",
		Quantity: 10,
		Comment:  "something",
	}

	t.Run("success", func(t *testing.T) {
		expectedResponse := types.FungibleTransferResponse{
			TypeId:   typeId,
			Owner:    request.Owner,
			NewOwner: request.NewOwner,
		}

		mockManager := mocks.Operations{}
		mockManager.FungiblePrepareTransferReturns(&expectedResponse, nil)

		requestHandlerTest(t,
			&mockManager, &request, reqUrl, method,
			http.StatusOK, &expectedResponse, &types.FungibleTransferResponse{},
		)

		calledTypeId, calledRequest := mockManager.FungiblePrepareTransferArgsForCall(0)
		require.Equal(t, typeId, calledTypeId, "reqUrl: %v", reqUrl)
		require.Equal(t, &request, calledRequest, "reqUrl: %v", reqUrl)
	})

	requestHandlerErrorsTest(t, func(mockManager *mocks.Operations, err error) {
		mockManager.FungiblePrepareTransferReturns(nil, err)
	}, request, reqUrl, method, "not-found", "permission", "invalid", "other")
}

func TestHandler_FungibleConsolidate(t *testing.T) {
	typeId := "aAbBcCdDeEfFgG"
	reqUrl := buildTestTypeUrl(constants.FungibleConsolidate, typeId)
	method := http.MethodPost
	request := types.FungibleConsolidateRequest{
		Owner:    "user1",
		Accounts: []string{"id1", "id2"},
	}

	t.Run("success", func(t *testing.T) {
		expectedResponse := types.FungibleConsolidateResponse{
			TypeId: typeId,
			Owner:  request.Owner,
		}

		mockManager := mocks.Operations{}
		mockManager.FungiblePrepareConsolidateReturns(&expectedResponse, nil)

		requestHandlerTest(t,
			&mockManager, &request, reqUrl, method,
			http.StatusOK, &expectedResponse, &types.FungibleConsolidateResponse{},
		)

		calledTypeId, calledRequest := mockManager.FungiblePrepareConsolidateArgsForCall(0)
		require.Equal(t, typeId, calledTypeId, "reqUrl: %v", reqUrl)
		require.Equal(t, &request, calledRequest, "reqUrl: %v", reqUrl)
	})

	requestHandlerErrorsTest(t, func(mockManager *mocks.Operations, err error) {
		mockManager.FungiblePrepareConsolidateReturns(nil, err)
	}, request, reqUrl, method, "not-found", "permission", "invalid", "other")
}

func TestHandler_FungibleAccounts(t *testing.T) {
	typeId := "aAbBcCdDeEfFgG"
	owner := "user1"
	account := "acc1"
	path := common.URLForType(constants.FungibleAccounts, typeId)
	reqQueries := map[string]url.Values{
		"empty":   {},
		"owner":   {"owner": []string{owner}},
		"account": {"account": []string{account}},
		"both":    {"owner": []string{owner}, "account": []string{account}},
	}
	method := http.MethodGet

	for key, query := range reqQueries {
		t.Run(fmt.Sprintf("success:%v", key), func(t *testing.T) {
			expectedResponse := []types.FungibleAccountRecord{
				{
					Account: account,
					Owner:   owner,
					Balance: 10,
					Comment: "something",
				},
			}

			mockManager := mocks.Operations{}
			mockManager.FungibleAccountsReturns(expectedResponse, nil)

			reqUrl := buildTestUrlWithQuery(path, query)
			requestHandlerTest(t,
				&mockManager, nil, reqUrl, method,
				http.StatusOK, &expectedResponse, &[]types.FungibleAccountRecord{},
			)

			calledTypeId, calledOwner, calledAccount := mockManager.FungibleAccountsArgsForCall(0)
			require.Equal(t, typeId, calledTypeId, "reqUrl: %v", reqUrl)
			require.Equal(t, query.Get("owner"), calledOwner, "reqUrl: %v", reqUrl)
			require.Equal(t, query.Get("account"), calledAccount, "reqUrl: %v", reqUrl)
		})
	}

	requestHandlerErrorsTest(t, func(mockManager *mocks.Operations, err error) {
		mockManager.FungibleAccountsReturns(nil, err)
	}, nil, buildTestUrl(path), method, "not-found", "invalid", "other")
}
