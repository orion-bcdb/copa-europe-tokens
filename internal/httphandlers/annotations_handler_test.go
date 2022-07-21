// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/copa-europe-tokens/internal/tokens/mocks"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/stretchr/testify/require"
)

func TestEventsHandler_Get(t *testing.T) {
	t.Run("skeleton", func(t *testing.T) {
		mockManager := &mocks.Operations{}

		h := NewAnnotationsHandler(mockManager, testLogger(t, "debug"))
		require.NotNil(t, h)

		rr := httptest.NewRecorder()
		require.NotNil(t, rr)

		reqUrl := &url.URL{Scheme: "http", Host: "server1.example.com:6091",
			Path: constants.TokensAnnotationsSubTree + "aAbBcCdDeEfFgG.xXyYzZ"}
		req, err := http.NewRequest(http.MethodGet, reqUrl.String(), nil)
		require.NoError(t, err)

		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}
