package server

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/copa-europe-tokens/pkg/config"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestNewTokensServer(t *testing.T) {
	conf := &config.Configuration{
		Network:  config.NetworkConf{},
		TLS:      config.TLSConf{},
		LogLevel: "debug",
		Orion:    config.OrionConf{},
		Users:    config.UsersConf{},
		Session:  config.SessionConf{},
	}

	lg, err := logger.New(&logger.Config{
		Level:         conf.LogLevel,
		OutputPath:    []string{"stdout"},
		ErrOutputPath: []string{"stderr"},
		Encoding:      "console",
		Name:          "copa-tokens-test",
	})
	require.NoError(t, err)

	tokensServer, err := NewTokensServer(conf, lg)
	require.NoError(t, err)
	require.NotNil(t, tokensServer)
}

func TestTokensServer_Start(t *testing.T) {
	conf := &config.Configuration{
		Network: config.NetworkConf{
			Address: "127.0.0.1",
			Port:    9091,
		},
		TLS:      config.TLSConf{},
		LogLevel: "debug",
		Orion:    config.OrionConf{},
		Users:    config.UsersConf{},
		Session:  config.SessionConf{},
	}

	wg := sync.WaitGroup{}
	startedServingHook := func(entry zapcore.Entry) error {
		if strings.Contains(entry.Message, "Starting to serve requests on: 127.0.0.1:9091") {
			wg.Done()
		}
		return nil
	}
	finishedServingHook := func(entry zapcore.Entry) error {
		if strings.Contains(entry.Message, "Finished serving requests on: 127.0.0.1:9091") {
			wg.Done()
		}
		return nil
	}

	lg, err := logger.New(
		&logger.Config{
			Level:         conf.LogLevel,
			OutputPath:    []string{"stdout"},
			ErrOutputPath: []string{"stderr"},
			Encoding:      "console",
			Name:          "copa-tokens-test",
		},
		zap.Hooks(startedServingHook, finishedServingHook),
	)
	require.NoError(t, err)

	tokensServer, err := NewTokensServer(conf, lg)
	require.NoError(t, err)
	require.NotNil(t, tokensServer)

	wg.Add(1)
	err = tokensServer.Start()
	require.NoError(t, err)
	wg.Wait()
	time.Sleep(1000 * time.Millisecond)

	port, err := tokensServer.Port()
	require.NoError(t, err)
	require.Equal(t, "9091", port)

	wg.Add(1)
	err = tokensServer.Stop()
	require.NoError(t, err)
	wg.Wait()
}
