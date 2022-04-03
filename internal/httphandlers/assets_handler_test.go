// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"testing"

	"github.com/copa-europe-tokens/internal/tokens/mocks"
	"github.com/stretchr/testify/require"
)

func TestNewAssetsHandler(t *testing.T) {
	mockManager := &mocks.Operations{}
	h := NewAssetsHandler(mockManager, testLogger(t, "debug"))
	require.NotNil(t, h)
}
