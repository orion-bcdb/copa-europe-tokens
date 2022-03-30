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
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestDeployHandler_DeployTokenType(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.DeployTokenTypeReturns(
			&types.DeployResponse{
				TypeId: "aAbBcCdDeEfFgG",
				Name:   "myNFT",
				Url:    "/tokens/types/aAbBcCdDeEfFgG",
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

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		resp := &types.DeployResponse{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.DeployResponse{
			TypeId: "aAbBcCdDeEfFgG",
			Name:   "myNFT",
			Url:    "/tokens/types/aAbBcCdDeEfFgG",
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
