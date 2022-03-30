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

	deployRequestMy := &types.DeployRequest{
		Name:        "my-NFT",
		Description: "my NFT for testing",
	}

	t.Run("success", func(t *testing.T) {
		deployResponseMy, err := manager.DeployTokenType(deployRequestMy)
		assert.NoError(t, err)
		assert.Equal(t, deployRequestMy.Name, deployResponseMy.Name)
		expectedIdMy, _ := NameToID(deployRequestMy.Name)
		assert.Equal(t, expectedIdMy, deployResponseMy.TypeId)
		assert.Equal(t, constants.TokensTypesEndpoint+"/"+expectedIdMy, deployResponseMy.Url)

		deployRequestHis := &types.DeployRequest{
			Name:        "his-NFT",
			Description: "", //empty description is fine
		}
		deployResponseHis, err := manager.DeployTokenType(deployRequestHis)
		assert.NoError(t, err)
		assert.Equal(t, deployRequestHis.Name, deployResponseHis.Name)
		expectedIdHis, _ := NameToID(deployRequestHis.Name)
		assert.Equal(t, expectedIdHis, deployResponseHis.TypeId)
		assert.Equal(t, constants.TokensTypesEndpoint+"/"+expectedIdHis, deployResponseHis.Url)
	})

	t.Run("error: deploy again", func(t *testing.T) {
		deployResponseBad, err := manager.DeployTokenType(deployRequestMy)
		assert.Error(t, err)
		assert.EqualError(t, err, "token type already exists")
		assert.Nil(t, deployResponseBad)
	})

	t.Run("error: empty name", func(t *testing.T) {
		deployRequestEmpty := &types.DeployRequest{
			Name:        "",
			Description: "",
		}
		deployResponseBad, err := manager.DeployTokenType(deployRequestEmpty)
		assert.EqualError(t, err, "token type name is empty")
		assert.Nil(t, deployResponseBad)
	})
}

func TestTokensManager_GetTokenType(t *testing.T) {
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

	deployRequestMy := &types.DeployRequest{
		Name:        "my-NFT",
		Description: "my NFT for testing",
	}

	deployResponseMy, err := manager.DeployTokenType(deployRequestMy)
	assert.NoError(t, err)

	deployRequestHis := &types.DeployRequest{
		Name:        "his-NFT",
		Description: "", //empty description is fine
	}
	deployResponseHis, err := manager.DeployTokenType(deployRequestHis)
	assert.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		deployResponse, err := manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualDeployResponse(t, deployResponseMy, deployResponse)

		deployResponse, err = manager.GetTokenType(deployResponseHis.TypeId)
		assert.NoError(t, err)
		assertEqualDeployResponse(t, deployResponseHis, deployResponse)
	})

	t.Run("error: empty", func(t *testing.T) {
		deployResponse, err := manager.GetTokenType("")
		assert.EqualError(t, err, "token type ID is empty")
		assert.IsType(t, &ErrInvalid{}, err)
		assert.Nil(t, deployResponse)
	})

	t.Run("error: too long", func(t *testing.T) {
		deployResponse, err := manager.GetTokenType("12345678123456781234567812345678")
		assert.EqualError(t, err, "token type ID is too long")
		assert.IsType(t, &ErrInvalid{}, err)
		assert.Nil(t, deployResponse)
	})

	t.Run("error: not base64url", func(t *testing.T) {
		deployResponse, err := manager.GetTokenType("123~")
		assert.EqualError(t, err, "token type ID is not in base64url")
		assert.IsType(t, &ErrInvalid{}, err)
		assert.Nil(t, deployResponse)
	})

	t.Run("error: not found", func(t *testing.T) {
		deployResponse, err := manager.GetTokenType("1234")
		assert.EqualError(t, err, "not found")
		assert.IsType(t, &ErrNotFound{}, err)
		assert.Nil(t, deployResponse)
	})
}

func assertEqualDeployResponse(t *testing.T, expected, actual *types.DeployResponse) {
	assert.Equal(t, expected.Name, actual.Name)
	assert.Equal(t, expected.TypeId, actual.TypeId)
	assert.Equal(t, expected.Description, actual.Description)
	assert.Equal(t, expected.Url, actual.Url)
}
