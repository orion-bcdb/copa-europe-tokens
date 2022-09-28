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

func TestAssetsHandler_GetTokensByOwnerLink(t *testing.T) {
	for _, query := range []string{
		"type=abcbdef&owner=bob",
		"type=abAB01_-&owner=the~dude",
		"owner=bob&type=abcbdef",
		"type=abcbdef&owner=bob&link=xxx.yyy",
		"type=abcbdef&link=xxx.yyy",
	} {
		t.Run("success: "+query, func(t *testing.T) {
			mockManager := &mocks.Operations{}
			mockManager.GetTokensByOwnerLinkReturns([]*types.TokenRecord{
				{
					AssetDataId:   "xXyYzZ",
					Owner:         "bob",
					AssetData:     "bob's data",
					AssetMetadata: "metadata",
					Link:          "xxx.yyy",
				},
				{
					AssetDataId:   "uUvVwW",
					Owner:         "charlie",
					AssetData:     "charlie's data",
					AssetMetadata: "metadata",
					Link:          "xxx.yyy",
				},
			}, nil)

			h := NewAssetsHandler(mockManager, testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			reqUrl := &url.URL{
				Scheme:   "http",
				Host:     "server1.example.com:6091",
				Path:     constants.TokensAssetsEndpoint,
				RawQuery: query,
			}
			req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
			require.NoError(t, err)

			h.ServeHTTP(rr, req)
			if http.StatusOK != rr.Code {
				t.Log(rr.Body.String())
			}
			require.Equal(t, http.StatusOK, rr.Code)
			var resp []*types.TokenRecord
			err = json.NewDecoder(rr.Body).Decode(&resp)
			require.NoError(t, err)
			require.Len(t, resp, 2)
			require.Equal(t, &types.TokenRecord{
				AssetDataId:   "xXyYzZ",
				Owner:         "bob",
				AssetData:     "bob's data",
				AssetMetadata: "metadata",
				Link:          "xxx.yyy",
			}, resp[0])
			require.Equal(t, &types.TokenRecord{
				AssetDataId:   "uUvVwW",
				Owner:         "charlie",
				AssetData:     "charlie's data",
				AssetMetadata: "metadata",
				Link:          "xxx.yyy",
			}, resp[1])
		})
	}
	t.Run("error: missing parameter", func(t *testing.T) {
		mockManager := &mocks.Operations{}

		h := NewAssetsHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		for _, query := range []string{"type=abcbdef", "owner=abcbdef", "link=xxx.yyy"} {

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			reqUrl := &url.URL{
				Scheme:   "http",
				Host:     "server1.example.com:6091",
				Path:     constants.TokensAssetsEndpoint,
				RawQuery: query,
			}
			req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
			require.NoError(t, err)

			h.ServeHTTP(rr, req)
			require.Equal(t, http.StatusNotFound, rr.Code)
		}
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
				mockManager.GetTokensByOwnerLinkReturns(nil, &tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.GetTokensByOwnerLinkReturns(nil, &tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.GetTokensByOwnerLinkReturns(nil, errors.New("oops internal"))
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
				Path:     constants.TokensAssetsEndpoint,
				RawQuery: "type=aAbBcCdDeEfFgG&owner=bob",
			}
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

func TestAssetsHandler_Update(t *testing.T) {
	request := &types.UpdateRequest{
		Owner:    "bob",
		AssetMetadata: "new metadata",
	}

	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.PrepareUpdateReturns(&types.UpdateResponse{
			TokenId:       "xxx.yyy",
			Owner:         "bob",
			AssetMetadata: "new metadata",
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
			Path: constants.TokensAssetsPrepareUpdate + "xxx.yyy"}
		req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		resp := &types.UpdateResponse{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.UpdateResponse{
			TokenId:       "xxx.yyy",
			Owner:         "bob",
			AssetMetadata: "new metadata",
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
				mockManager.PrepareUpdateReturns(nil, &tokens.ErrPermission{ErrMsg: "oops permission"})
				return mockManager
			},
			expectedStatus: http.StatusForbidden,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops permission"},
		},
		{
			name: "error: invalid",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareUpdateReturns(nil, &tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareUpdateReturns(nil, &tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareUpdateReturns(nil, errors.New("oops internal"))
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
				Path: constants.TokensAssetsPrepareUpdate + "xxx.yyy"}
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
