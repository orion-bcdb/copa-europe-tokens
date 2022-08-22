// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/copa-europe-tokens/internal/tokens"
	"github.com/copa-europe-tokens/internal/tokens/mocks"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestDeployHandler_DeployTokenType(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.DeployTokenTypeReturns(
			&types.DeployResponse{
				TypeId:      "aAbBcCdDeEfFgG",
				Name:        "myNFT",
				Description: "it is my NFT",
				Url:         "/tokens/types/aAbBcCdDeEfFgG",
			}, nil)

		h := NewDeployHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		request := &types.DeployRequest{
			Name:        "myNFT",
			Description: "my NFT is best",
		}
		requestBytes, err := json.Marshal(request)
		require.NoError(t, err)

		txReader := bytes.NewReader(requestBytes)
		require.NotNil(t, txReader)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091", Path: constants.TokensTypesEndpoint}
		req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusCreated, rr.Code)
		resp := &types.DeployResponse{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.DeployResponse{
			TypeId:      "aAbBcCdDeEfFgG",
			Name:        "myNFT",
			Description: "it is my NFT",
			Url:         "/tokens/types/aAbBcCdDeEfFgG",
		}, resp)
	})

	t.Run("success: Annotation", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.DeployTokenTypeReturns(
			&types.DeployResponse{
				TypeId:      "aAbBcCdDeEfFgG",
				Name:        "myNFT",
				Description: "it is my Annotation",
				Class:       constants.TokenClass_ANNOTATIONS,
				Url:         "/tokens/types/aAbBcCdDeEfFgG",
			}, nil)

		h := NewDeployHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		request := &types.DeployRequest{
			Name:        "myNFT",
			Description: "my NFT is best",
			Class:       constants.TokenClass_ANNOTATIONS,
		}
		requestBytes, err := json.Marshal(request)
		require.NoError(t, err)

		txReader := bytes.NewReader(requestBytes)
		require.NotNil(t, txReader)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091", Path: constants.TokensTypesEndpoint}
		req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusCreated, rr.Code)
		resp := &types.DeployResponse{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.DeployResponse{
			TypeId:      "aAbBcCdDeEfFgG",
			Name:        "myNFT",
			Description: "it is my Annotation",
			Class:       constants.TokenClass_ANNOTATIONS,
			Url:         "/tokens/types/aAbBcCdDeEfFgG",
		}, resp)
	})

	t.Run("error: exists", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.DeployTokenTypeReturns(nil, &tokens.ErrExist{ErrMsg: "it already exists"})

		h := NewDeployHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		request := &types.DeployRequest{
			Name:        "myNFT",
			Description: "my NFT is best",
		}
		requestBytes, err := json.Marshal(request)
		require.NoError(t, err)

		txReader := bytes.NewReader(requestBytes)
		require.NotNil(t, txReader)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091", Path: constants.TokensTypesEndpoint}
		req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusConflict, rr.Code)
		resp := &types.HttpResponseErr{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.HttpResponseErr{
			ErrMsg: "it already exists",
		}, resp)
	})

	t.Run("error: invalid", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.DeployTokenTypeReturns(nil, &tokens.ErrInvalid{ErrMsg: "some invalid request"})

		h := NewDeployHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		request := &types.DeployRequest{
			Name:        "myNFT",
			Description: "my NFT is best",
		}
		requestBytes, err := json.Marshal(request)
		require.NoError(t, err)

		txReader := bytes.NewReader(requestBytes)
		require.NotNil(t, txReader)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091", Path: constants.TokensTypesEndpoint}
		req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		resp := &types.HttpResponseErr{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.HttpResponseErr{
			ErrMsg: "some invalid request",
		}, resp)
	})

	t.Run("error: internal error", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.DeployTokenTypeReturns(nil, errors.New("oops"))

		h := NewDeployHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		request := &types.DeployRequest{
			Name:        "myNFT",
			Description: "my NFT is best",
		}
		requestBytes, err := json.Marshal(request)
		require.NoError(t, err)

		txReader := bytes.NewReader(requestBytes)
		require.NotNil(t, txReader)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091", Path: constants.TokensTypesEndpoint}
		req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		resp := &types.HttpResponseErr{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.HttpResponseErr{
			ErrMsg: "oops",
		}, resp)
	})

}

func TestDeployHandler_GetTokenType(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.GetTokenTypeReturns(
			&types.TokenDescription{
				TypeId:      "aAbBcCdDeEfFgG",
				Name:        "myNFT",
				Description: "it is my NFT",
				Url:         "/tokens/types/aAbBcCdDeEfFgG",
			}, nil)

		h := NewDeployHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensTypesSubTree + "aAbBcCdDeEfFgG"}
		req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		resp := &types.DeployResponse{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.DeployResponse{
			TypeId:      "aAbBcCdDeEfFgG",
			Name:        "myNFT",
			Description: "it is my NFT",
			Url:         "/tokens/types/aAbBcCdDeEfFgG",
		}, resp)
	})

	t.Run("error: invalid", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.GetTokenTypeReturns(nil, &tokens.ErrInvalid{ErrMsg: "oops"})

		h := NewDeployHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensTypesSubTree + "123."}
		req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		resp := &types.HttpResponseErr{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.HttpResponseErr{
			ErrMsg: "oops",
		}, resp)
	})

	t.Run("error: not found", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.GetTokenTypeReturns(nil, &tokens.ErrNotFound{ErrMsg: "oops"})

		h := NewDeployHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensTypesSubTree + "1234"}
		req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusNotFound, rr.Code)
		resp := &types.HttpResponseErr{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.HttpResponseErr{
			ErrMsg: "oops",
		}, resp)
	})
}

func TestDeployHandler_ListTokenTypes(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectedTypes := []*types.TokenDescription{
			{
				TypeId:      "xXyYzZ09-_",
				Name:        "hisNFT",
				Description: "it is my NFT",
				Url:         "/tokens/types/xXyYzZ09-_",
			},
			{
				TypeId:      "aAbBcCdDeEfFgG",
				Name:        "myNFT",
				Description: "it is my NFT",
				Url:         "/tokens/types/aAbBcCdDeEfFgG",
			},
		}

		mockManager := &mocks.Operations{}
		mockManager.GetTokenTypesReturns(expectedTypes, nil)

		h := NewDeployHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091", Path: constants.TokensTypesEndpoint}
		req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		var tokenTypes []*types.TokenDescription
		err = json.NewDecoder(rr.Body).Decode(&tokenTypes)
		require.NoError(t, err)
		require.Len(t, tokenTypes, 2)

		for _, expectedTT := range expectedTypes {
			found := false
			for _, actualTT := range tokenTypes {
				if reflect.DeepEqual(expectedTT, actualTT) {
					found = true
					break
				}
			}
			require.True(t, found, "exp not found: %v", expectedTT)
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
				mockManager.GetTokenTypesReturns(nil, &tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.GetTokenTypesReturns(nil, &tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.GetTokenTypesReturns(nil, errors.New("oops internal"))
				return mockManager
			},
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops internal"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewDeployHandler(tt.mockFactory(), testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091", Path: constants.TokensTypesEndpoint}
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

func testLogger(t *testing.T, level string) *logger.SugarLogger {
	lg, err := logger.New(&logger.Config{
		Level:         level,
		OutputPath:    []string{"stdout"},
		ErrOutputPath: []string{"stderr"},
		Encoding:      "console",
		Name:          "copa-tokens-test",
	})
	require.NoError(t, err)
	return lg
}
