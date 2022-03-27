package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/copa-europe-tokens/pkg/config"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	sdkconfig "github.com/hyperledger-labs/orion-sdk-go/pkg/config"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/hyperledger-labs/orion-server/pkg/server/testutils"
	"github.com/hyperledger-labs/orion-server/test/setup"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestTokensServer_Start(t *testing.T) {
	dir, err := ioutil.TempDir("", "tokens-server-test")
	require.NoError(t, err)

	nPort := uint32(6581)
	pPort := uint32(6681)
	httpPort := uint32(6781)

	setupConfig := &setup.Config{
		NumberOfServers:     1,
		TestDirAbsolutePath: dir,
		BDBBinaryPath:       "../../bin/bdb",
		CmdTimeout:          10 * time.Second,
		BaseNodePort:        nPort,
		BasePeerPort:        pPort,
	}
	c, err := setup.NewCluster(setupConfig)
	require.NoError(t, err)
	defer c.ShutdownAndCleanup()

	require.NoError(t, c.Start())

	require.Eventually(t, func() bool { return c.AgreedLeader(t, 0) >= 0 }, 30*time.Second, time.Second)

	adminCertPath, adminKeyPath := c.GetUserCertKeyPath("admin")
	aliceCertPath, aliceKeyPath := c.GetUserCertKeyPath("alice")
	conf := &config.Configuration{
		Network: config.NetworkConf{
			Address: "127.0.0.1",
			Port:    httpPort,
		},
		TLS:      config.TLSConf{Enabled: false},
		LogLevel: "debug",
		Orion: config.OrionConf{
			Replicas: []*sdkconfig.Replica{
				{
					ID:       "node-1",
					Endpoint: c.Servers[0].URL(),
				},
			},
			CaConfig: config.CAConf{
				RootCACertsPath: []string{path.Join(setupConfig.TestDirAbsolutePath, "ca", testutils.RootCAFileName+".pem")},
			},
		},
		Users: config.UsersConf{
			Admin: sdkconfig.UserConfig{
				UserID:         "admin",
				CertPath:       adminCertPath,
				PrivateKeyPath: adminKeyPath,
			},
			Custodian: sdkconfig.UserConfig{
				UserID:         "alice",
				CertPath:       aliceCertPath,
				PrivateKeyPath: aliceKeyPath,
			},
		},
		Session: config.SessionConf{
			TxTimeout:    10 * time.Second,
			QueryTimeout: 10 * time.Second,
		},
	}

	wg := sync.WaitGroup{}
	startedServingHook := func(entry zapcore.Entry) error {
		if strings.Contains(entry.Message, fmt.Sprintf("Starting to serve requests on: 127.0.0.1:%d", httpPort)) {
			wg.Done()
		}
		return nil
	}
	finishedServingHook := func(entry zapcore.Entry) error {
		if strings.Contains(entry.Message, fmt.Sprintf("Finished serving requests on: 127.0.0.1:%d", httpPort)) {
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
	require.Equal(t, fmt.Sprintf("%d", httpPort), port)

	// GET /status
	httpClient := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	baseURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", httpPort))
	require.NoError(t, err)
	u := baseURL.ResolveReference(
		&url.URL{
			Path: constants.StatusEndpoint,
		},
	)
	resp, err := httpClient.Get(u.String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	status := &types.StatusResponse{}
	err = json.NewDecoder(resp.Body).Decode(status)
	resp.Body.Close()
	require.NoError(t, err)

	require.True(t, strings.HasPrefix(status.Status, fmt.Sprintf("connected: {Id: node-1, Address: 127.0.0.1, Port: %d", nPort)))

	wg.Add(1)
	err = tokensServer.Stop()
	require.NoError(t, err)
	wg.Wait()
}
