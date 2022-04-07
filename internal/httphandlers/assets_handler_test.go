// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/copa-europe-tokens/internal/tokens"
	"github.com/copa-europe-tokens/internal/tokens/mocks"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestAssetsHandler_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.GetTokenReturns(&types.TokenRecord{
			AssetDataId:   "xXyYzZ",
			Owner:         "bob",
			AssetData:     "my data",
			AssetMetadata: "my metadata",
		}, nil)

		h := NewAssetsHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensAssetsSubTree + "aAbBcCdDeEfFgG.xXyYzZ"}
		req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		resp := &types.TokenRecord{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.TokenRecord{
			AssetDataId:   "xXyYzZ",
			Owner:         "bob",
			AssetData:     "my data",
			AssetMetadata: "my metadata",
		}, resp)
	})

	type testCase struct {
		name           string
		mockFactory    func() *mocks.Operations
		expectedStatus int
		expectedErr    *types.HttpResponseErr
	}
	for _, tt := range []testCase{
		{
			name: "error: invalid",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.GetTokenReturns(nil, &tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.GetTokenReturns(nil, &tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.GetTokenReturns(nil, errors.New("oops internal"))
				return mockManager
			},
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops internal"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAssetsHandler(tt.mockFactory(), testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
				Path: constants.TokensAssetsSubTree + "aAbBcCdDeEfFgG.xXyYzZ"}
			req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
			require.NoError(t, err)

			h.ServeHTTP(rr, req)
			require.Equal(t, tt.expectedStatus, rr.Code)
			resp := &types.HttpResponseErr{}
			err = json.NewDecoder(rr.Body).Decode(resp)
			require.NoError(t, err)
			require.Equal(t, tt.expectedErr, resp)
		})
	}
}

func TestAssetsHandler_Mint(t *testing.T) {
	request := &types.MintRequest{
		Owner:         "bob",
		AssetData:     "bob's data",
		AssetMetadata: "bob's metadata",
	}

	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.PrepareMintReturns(&types.MintResponse{
			TokenId:       "xxx.yyy",
			Owner:         "bob",
			TxEnvelope:    "abcd",
			TxPayloadHash: "efgh",
		}, nil)

		h := NewAssetsHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		requestBytes, err := json.Marshal(request)
		require.NoError(t, err)

		txReader := bytes.NewReader(requestBytes)
		require.NotNil(t, txReader)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensAssetsPrepareMint + "xxx"}
		req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		resp := &types.MintResponse{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.MintResponse{
			TokenId:       "xxx.yyy",
			Owner:         "bob",
			TxEnvelope:    "abcd",
			TxPayloadHash: "efgh",
		}, resp)
	})

	type testCase struct {
		name           string
		mockFactory    func() *mocks.Operations
		expectedStatus int
		expectedErr    *types.HttpResponseErr
	}
	for _, tt := range []testCase{
		{
			name: "error: already exists",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareMintReturns(nil, &tokens.ErrExist{ErrMsg: "oops already exists"})
				return mockManager
			},
			expectedStatus: http.StatusConflict,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops already exists"},
		},
		{
			name: "error: invalid",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareMintReturns(nil, &tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareMintReturns(nil, &tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareMintReturns(nil, errors.New("oops internal"))
				return mockManager
			},
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops internal"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAssetsHandler(tt.mockFactory(), testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			requestBytes, err := json.Marshal(request)
			require.NoError(t, err)

			txReader := bytes.NewReader(requestBytes)
			require.NotNil(t, txReader)

			reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
				Path: constants.TokensAssetsPrepareMint + "xxx"}
			req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
			require.NoError(t, err)

			h.ServeHTTP(rr, req)
			require.Equal(t, tt.expectedStatus, rr.Code)
			resp := &types.HttpResponseErr{}
			err = json.NewDecoder(rr.Body).Decode(resp)
			require.NoError(t, err)
			require.Equal(t, tt.expectedErr, resp)
		})
	}
}

func TestAssetsHandler_Transfer(t *testing.T) {
	request := &types.TransferRequest{
		Owner:    "bob",
		NewOwner: "charlie",
	}

	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.PrepareTransferReturns(&types.TransferResponse{
			TokenId:       "xxx.yyy",
			Owner:         "bob",
			NewOwner:      "charlie",
			TxEnvelope:    "abcd",
			TxPayloadHash: "efgh",
		}, nil)

		h := NewAssetsHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		requestBytes, err := json.Marshal(request)
		require.NoError(t, err)

		txReader := bytes.NewReader(requestBytes)
		require.NotNil(t, txReader)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensAssetsPrepareTransfer + "xxx.yyy"}
		req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		resp := &types.TransferResponse{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.TransferResponse{
			TokenId:       "xxx.yyy",
			Owner:         "bob",
			NewOwner:      "charlie",
			TxEnvelope:    "abcd",
			TxPayloadHash: "efgh",
		}, resp)
	})

	type testCase struct {
		name           string
		mockFactory    func() *mocks.Operations
		expectedStatus int
		expectedErr    *types.HttpResponseErr
	}
	for _, tt := range []testCase{
		{
			name: "error: permission",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareTransferReturns(nil, &tokens.ErrPermission{ErrMsg: "oops permission"})
				return mockManager
			},
			expectedStatus: http.StatusForbidden,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops permission"},
		},
		{
			name: "error: invalid",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareTransferReturns(nil, &tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareTransferReturns(nil, &tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareTransferReturns(nil, errors.New("oops internal"))
				return mockManager
			},
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops internal"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAssetsHandler(tt.mockFactory(), testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			requestBytes, err := json.Marshal(request)
			require.NoError(t, err)

			txReader := bytes.NewReader(requestBytes)
			require.NotNil(t, txReader)

			reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
				Path: constants.TokensAssetsPrepareTransfer + "xxx.yyy"}
			req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
			require.NoError(t, err)

			h.ServeHTTP(rr, req)
			require.Equal(t, tt.expectedStatus, rr.Code)
			resp := &types.HttpResponseErr{}
			err = json.NewDecoder(rr.Body).Decode(resp)
			require.NoError(t, err)
			require.Equal(t, tt.expectedErr, resp)
		})
	}
}

func TestAssetsHandler_Submit(t *testing.T) {
	request := &types.SubmitRequest{
		TokenId:       "xxx.yyy",
		TxEnvelope:    "abcd",
		TxPayloadHash: "efgh",
		Signer:        "bob",
		Signature:     "bogus-sig",
	}

	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.SubmitTxReturns(&types.SubmitResponse{
			TokenId:   "xxx.yyy",
			TxId:      "txid",
			TxReceipt: "xXyYzZ",
		}, nil)

		h := NewAssetsHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		requestBytes, err := json.Marshal(request)
		require.NoError(t, err)

		txReader := bytes.NewReader(requestBytes)
		require.NotNil(t, txReader)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensAssetsSubmit}
		req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		resp := &types.SubmitResponse{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.SubmitResponse{
			TokenId:   "xxx.yyy",
			TxId:      "txid",
			TxReceipt: "xXyYzZ",
		}, resp)
	})

	type testCase struct {
		name           string
		mockFactory    func() *mocks.Operations
		expectedStatus int
		expectedErr    *types.HttpResponseErr
	}
	for _, tt := range []testCase{
		{
			name: "error: already exists",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.SubmitTxReturns(nil, &tokens.ErrExist{ErrMsg: "oops already exists"})
				return mockManager
			},
			expectedStatus: http.StatusConflict,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops already exists"},
		},
		{
			name: "error: invalid",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.SubmitTxReturns(nil, &tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.SubmitTxReturns(nil, &tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: permission",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.SubmitTxReturns(nil, &tokens.ErrPermission{ErrMsg: "oops permission"})
				return mockManager
			},
			expectedStatus: http.StatusForbidden,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops permission"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.SubmitTxReturns(nil, errors.New("oops internal"))
				return mockManager
			},
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops internal"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAssetsHandler(tt.mockFactory(), testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			requestBytes, err := json.Marshal(request)
			require.NoError(t, err)

			txReader := bytes.NewReader(requestBytes)
			require.NotNil(t, txReader)

			reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
				Path: constants.TokensAssetsSubmit}
			req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
			require.NoError(t, err)

			h.ServeHTTP(rr, req)
			require.Equal(t, tt.expectedStatus, rr.Code)
			resp := &types.HttpResponseErr{}
			err = json.NewDecoder(rr.Body).Decode(resp)
			require.NoError(t, err)
			require.Equal(t, tt.expectedErr, resp)
		})
	}

}
