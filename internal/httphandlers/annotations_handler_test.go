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
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/pkg/errors"

	"github.com/copa-europe-tokens/internal/tokens/mocks"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/stretchr/testify/require"
)

func TestAnnotationHandler_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.GetAnnotationReturns(&types.AnnotationRecord{
			AnnotationDataId:   "xXyYzZ",
			Owner:              "bob",
			Link:               "xxx.yyy",
			AnnotationData:     "my data",
			AnnotationMetadata: "my metadata",
		}, nil)

		h := NewAnnotationsHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensAnnotationsSubTree + "aAbBcCdDeEfFgG.xXyYzZ"}
		req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		resp := &types.AnnotationRecord{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.AnnotationRecord{
			AnnotationDataId:   "xXyYzZ",
			Owner:              "bob",
			Link:               "xxx.yyy",
			AnnotationData:     "my data",
			AnnotationMetadata: "my metadata",
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
				mockManager.GetAnnotationReturns(nil, &tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.GetAnnotationReturns(nil, &tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.GetAnnotationReturns(nil, errors.New("oops internal"))
				return mockManager
			},
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops internal"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAnnotationsHandler(tt.mockFactory(), testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
				Path: constants.TokensAnnotationsSubTree + "aAbBcCdDeEfFgG.xXyYzZ"}
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

func TestAnnotationHandler_GetTokensBy(t *testing.T) {
	for _, query := range []string{
		"type=abcbdef",
		"type=abcbdef&owner=bob",
		"type=abcbdef&owner=bob&link=xyz.abc",
		"type=abcbdef&owner=bob&reference=ref.link",
		"type=abcbdef&owner=bob&link=xyz.abc&reference=ref.link",
		"type=abcbdef&link=xyz.abc",
		"type=abcbdef&reference=ref.link",
		"type=abcbdef&link=xyz.abc&reference=ref.link",
	} {
		t.Run("success: "+query, func(t *testing.T) {
			mockManager := &mocks.Operations{}
			mockManager.GetAnnotationsByFilterReturns([]*types.AnnotationRecord{
				{
					AnnotationDataId:   "xXyYzZ",
					Owner:              "bob",
					Link:               "xxx.yyy",
					AnnotationData:     "my data X",
					AnnotationMetadata: "my metadata",
				},
				{
					AnnotationDataId:   "aAbBcC",
					Owner:              "charlie",
					Link:               "xxx.yyy",
					AnnotationData:     "my data Y",
					AnnotationMetadata: "my metadata",
				},
			}, nil)

			h := NewAnnotationsHandler(mockManager, testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			reqUrl := &url.URL{
				Scheme:   "http",
				Host:     "server1.example.com:6091",
				Path:     constants.TokensAnnotationsEndpoint,
				RawQuery: query,
			}
			req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
			require.NoError(t, err)

			h.ServeHTTP(rr, req)
			if http.StatusOK != rr.Code {
				t.Log(rr.Body.String())
			}
			require.Equal(t, http.StatusOK, rr.Code)
			var resp []*types.AnnotationRecord
			err = json.NewDecoder(rr.Body).Decode(&resp)
			require.NoError(t, err)
			require.Len(t, resp, 2)
			require.Equal(t, &types.AnnotationRecord{
				AnnotationDataId:   "xXyYzZ",
				Owner:              "bob",
				Link:               "xxx.yyy",
				AnnotationData:     "my data X",
				AnnotationMetadata: "my metadata",
			}, resp[0])
			require.Equal(t, &types.AnnotationRecord{
				AnnotationDataId:   "aAbBcC",
				Owner:              "charlie",
				Link:               "xxx.yyy",
				AnnotationData:     "my data Y",
				AnnotationMetadata: "my metadata",
			}, resp[1])
		})
	}
	t.Run("error: missing parameter", func(t *testing.T) {
		mockManager := &mocks.Operations{}

		h := NewAnnotationsHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		for _, query := range []string{"owner=abcbdef", "link=xxx.yyy", "reference=ref.link", ""} {

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			reqUrl := &url.URL{
				Scheme:   "http",
				Host:     "server1.example.com:6091",
				Path:     constants.TokensAnnotationsEndpoint,
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
				mockManager.GetAnnotationsByFilterReturns(nil, &tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.GetAnnotationsByFilterReturns(nil, &tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.GetAnnotationsByFilterReturns(nil, errors.New("oops internal"))
				return mockManager
			},
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops internal"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAnnotationsHandler(tt.mockFactory(), testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
				Path:     constants.TokensAnnotationsEndpoint,
				RawQuery: "type=aAbBcCdDeEfFgG&owner=bob&link=xxx.yyy",
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

func TestAnnotationsHandler_Register(t *testing.T) {
	request := &types.AnnotationRegisterRequest{
		Owner:              "bob",
		Link:               "xxx.yyy",
		AnnotationData:     "bob's data",
		AnnotationMetadata: "bob's metadata",
	}

	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.PrepareRegisterReturns(&types.AnnotationRegisterResponse{
			AnnotationId:  "xxx.yyy",
			Owner:         "bob",
			Link:          "xxx.yyy",
			TxEnvelope:    "abcd",
			TxPayloadHash: "efgh",
		}, nil)

		h := NewAnnotationsHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		requestBytes, err := json.Marshal(request)
		require.NoError(t, err)

		txReader := bytes.NewReader(requestBytes)
		require.NotNil(t, txReader)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensAnnotationsPrepareRegister + "xxx"}
		req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		resp := &types.AnnotationRegisterResponse{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.AnnotationRegisterResponse{
			AnnotationId:  "xxx.yyy",
			Owner:         "bob",
			Link:          "xxx.yyy",
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
				mockManager.PrepareRegisterReturns(nil, &tokens.ErrExist{ErrMsg: "oops already exists"})
				return mockManager
			},
			expectedStatus: http.StatusConflict,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops already exists"},
		},
		{
			name: "error: invalid",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareRegisterReturns(nil, &tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareRegisterReturns(nil, &tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.PrepareRegisterReturns(nil, errors.New("oops internal"))
				return mockManager
			},
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops internal"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAnnotationsHandler(tt.mockFactory(), testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			requestBytes, err := json.Marshal(request)
			require.NoError(t, err)

			txReader := bytes.NewReader(requestBytes)
			require.NotNil(t, txReader)

			reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
				Path: constants.TokensAnnotationsPrepareRegister + "xxx"}
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

func TestAnnotationsHandler_Submit(t *testing.T) {
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

		h := NewAnnotationsHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		requestBytes, err := json.Marshal(request)
		require.NoError(t, err)

		txReader := bytes.NewReader(requestBytes)
		require.NotNil(t, txReader)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensAnnotationsSubmit}
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
			h := NewAnnotationsHandler(tt.mockFactory(), testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			requestBytes, err := json.Marshal(request)
			require.NoError(t, err)

			txReader := bytes.NewReader(requestBytes)
			require.NotNil(t, txReader)

			reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
				Path: constants.TokensAnnotationsSubmit}
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
