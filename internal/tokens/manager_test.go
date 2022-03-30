package tokens

import (
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"path"
	"testing"
	"time"

	"github.com/copa-europe-tokens/pkg/config"
	sdkconfig "github.com/hyperledger-labs/orion-sdk-go/pkg/config"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/hyperledger-labs/orion-server/pkg/server/testutils"
	"github.com/hyperledger-labs/orion-server/test/setup"
	"github.com/stretchr/testify/require"
)

func TestNewTokensManager(t *testing.T) {
	dir, err := ioutil.TempDir("", "token-manager-test")
	require.NoError(t, err)

	nPort := uint32(7581)
	pPort := uint32(7681)
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
			Port:    6481,
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

	lg, err := logger.New(&logger.Config{
		Level:         conf.LogLevel,
		OutputPath:    []string{"stdout"},
		ErrOutputPath: []string{"stderr"},
		Encoding:      "console",
		Name:          "copa-tokens-test",
	})
	require.NoError(t, err)

	manager, err := NewManager(conf, lg)
	require.NoError(t, err)
	require.NotNil(t, manager)

	stat, err := manager.GetStatus()
	require.NoError(t, err)
	require.Regexp(t, "connected: {Id: node-1, Address: 127.0.0.1, Port: 7581, Cert-hash: [0-9a-fA-F]{8,8}}", stat)
}

func TestTokensManager_Deploy(t *testing.T) {
	dir, err := ioutil.TempDir("", "token-manager-test")
	require.NoError(t, err)

	nPort := uint32(7581)
	pPort := uint32(7681)
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
			Port:    6481,
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

	lg, err := logger.New(&logger.Config{
		Level:         conf.LogLevel,
		OutputPath:    []string{"stdout"},
		ErrOutputPath: []string{"stderr"},
		Encoding:      "console",
		Name:          "copa-tokens-test",
	})
	require.NoError(t, err)

	manager, err := NewManager(conf, lg)
	require.NoError(t, err)
	require.NotNil(t, manager)

	stat, err := manager.GetStatus()
	require.NoError(t, err)
	require.Contains(t, stat, "connected:")

	// deploy successfully
	deployRequest := &types.DeployRequest{
		Name:        "myNFT",
		Description: "my NFT for testing",
	}
	deployResponse, err := manager.DeployTokenType(deployRequest)
	assert.NoError(t, err)
	assert.Equal(t, deployRequest.Name, deployResponse.Name)
	expectedId, _ := NameToID(deployRequest.Name)
	assert.Equal(t, (expectedId), deployResponse.TypeId)
	assert.Equal(t, constants.TokensTypesEndpoint+"/"+(expectedId), deployResponse.Url)

	// deploy successfully
	deployRequest = &types.DeployRequest{
		Name:        "his NFT",
		Description: "", //empty description is fine
	}
	deployResponse, err = manager.DeployTokenType(deployRequest)
	assert.NoError(t, err)
	assert.Equal(t, deployRequest.Name, deployResponse.Name)
	expectedId, _ = NameToID(deployRequest.Name)
	assert.Equal(t, expectedId, deployResponse.TypeId)
	assert.Equal(t, constants.TokensTypesEndpoint+"/"+expectedId, deployResponse.Url)

	// deploy again, will fail
	deployRequest = &types.DeployRequest{
		Name:        "myNFT",
		Description: "description does not matter for uniqueness",
	}
	deployResponse, err = manager.DeployTokenType(deployRequest)
	assert.Error(t, err)
	assert.EqualError(t, err, "token type already exists")
	assert.Nil(t, deployResponse)

	// empty name, will fail
	deployRequest = &types.DeployRequest{
		Name:        "",
		Description: "",
	}
	deployResponse, err = manager.DeployTokenType(deployRequest)
	assert.EqualError(t, err, "token type name is empty")
	assert.Nil(t, deployResponse)
}
