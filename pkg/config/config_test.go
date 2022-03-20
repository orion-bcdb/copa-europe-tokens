package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRead(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		t.Parallel()

		config, err := Read("./testdata")
		require.NoError(t, err)
		require.NotNil(t, config)
	})
}
