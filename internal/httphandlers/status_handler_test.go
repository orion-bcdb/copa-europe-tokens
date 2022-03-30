// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httphandlers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewStatusHandler(t *testing.T) {
	h := NewStatusHandler(nil, nil)
	require.NotNil(t, h)
}
