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

func TestUserHandler_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.GetUserReturns(&types.UserRecord{
			Identity:    "bob",
			Certificate: "bogus-cert",
			Privilege:   []string{"token1", "token2"},
		}, nil)

		h := NewUserHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensUsersSubTree + "bob"}
		req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		resp := &types.UserRecord{}
		err = json.NewDecoder(rr.Body).Decode(resp)
		require.NoError(t, err)
		require.Equal(t, &types.UserRecord{
			Identity:    "bob",
			Certificate: "bogus-cert",
			Privilege:   []string{"token1", "token2"},
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
				mockManager.GetUserReturns(nil, &tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.GetUserReturns(nil, &tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.GetUserReturns(nil, errors.New("oops internal"))
				return mockManager
			},
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops internal"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewUserHandler(tt.mockFactory(), testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
				Path: constants.TokensUsersSubTree + "bob"}
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

func TestUserHandler_Add(t *testing.T) {
	request := &types.UserRecord{
		Identity:    "bob",
		Certificate: "bogus-cert",
		Privilege:   []string{"token1", "token2"},
	}

	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.AddUserReturns(nil)

		h := NewUserHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		requestBytes, err := json.Marshal(request)
		require.NoError(t, err)

		txReader := bytes.NewReader(requestBytes)
		require.NotNil(t, txReader)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensUsersEndpoint}
		req, err := http.NewRequest(http.MethodPost, reqUrl.String(), txReader)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusCreated, rr.Code)
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
				mockManager.AddUserReturns(&tokens.ErrExist{ErrMsg: "oops already exists"})
				return mockManager
			},
			expectedStatus: http.StatusConflict,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops already exists"},
		},
		{
			name: "error: invalid",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.AddUserReturns(&tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.AddUserReturns(&tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.AddUserReturns(errors.New("oops internal"))
				return mockManager
			},
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops internal"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewUserHandler(tt.mockFactory(), testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			requestBytes, err := json.Marshal(request)
			require.NoError(t, err)

			txReader := bytes.NewReader(requestBytes)
			require.NotNil(t, txReader)

			reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
				Path: constants.TokensUsersEndpoint}
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

func TestUserHandler_Update(t *testing.T) {
	request := &types.UserRecord{
		Identity:    "bob",
		Certificate: "bogus-cert",
		Privilege:   []string{"token1", "token2"},
	}

	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.UpdateUserReturns(nil)

		h := NewUserHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		requestBytes, err := json.Marshal(request)
		require.NoError(t, err)

		txReader := bytes.NewReader(requestBytes)
		require.NotNil(t, txReader)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensUsersSubTree +"bob"}
		req, err := http.NewRequest(http.MethodPut, reqUrl.String(), txReader)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
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
				mockManager.UpdateUserReturns(&tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.UpdateUserReturns(&tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.UpdateUserReturns(errors.New("oops internal"))
				return mockManager
			},
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops internal"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewUserHandler(tt.mockFactory(), testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			requestBytes, err := json.Marshal(request)
			require.NoError(t, err)

			txReader := bytes.NewReader(requestBytes)
			require.NotNil(t, txReader)

			reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
				Path: constants.TokensUsersSubTree +"bob"}
			req, err := http.NewRequest(http.MethodPut, reqUrl.String(), txReader)
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

func TestUserHandler_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockManager := &mocks.Operations{}
		mockManager.RemoveUserReturns(nil)

		h := NewUserHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensUsersSubTree +"bob"}
		req, err := http.NewRequest(http.MethodDelete, reqUrl.String(), nil)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
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
				mockManager.RemoveUserReturns(&tokens.ErrInvalid{ErrMsg: "oops invalid"})
				return mockManager
			},
			expectedStatus: http.StatusBadRequest,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops invalid"},
		},
		{
			name: "error: not found",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.RemoveUserReturns(&tokens.ErrNotFound{ErrMsg: "oops not found"})
				return mockManager
			},
			expectedStatus: http.StatusNotFound,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops not found"},
		},
		{
			name: "error: internal",
			mockFactory: func() *mocks.Operations {
				mockManager := &mocks.Operations{}
				mockManager.RemoveUserReturns(errors.New("oops internal"))
				return mockManager
			},
			expectedStatus: http.StatusInternalServerError,
			expectedErr:    &types.HttpResponseErr{ErrMsg: "oops internal"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := NewUserHandler(tt.mockFactory(), testLogger(t, "debug"))
			require.NotNil(t, h)

			rr := httptest.NewRecorder()
			require.NotNil(t, rr)

			reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
				Path: constants.TokensUsersSubTree +"bob"}
			req, err := http.NewRequest(http.MethodDelete, reqUrl.String(), nil)
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
