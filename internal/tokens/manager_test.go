package tokens

import (
	"encoding/base64"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"testing"
	"time"

	"github.com/copa-europe-tokens/pkg/config"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/golang/protobuf/proto"
	sdkconfig "github.com/hyperledger-labs/orion-sdk-go/pkg/config"
	"github.com/hyperledger-labs/orion-server/pkg/crypto"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/hyperledger-labs/orion-server/pkg/server/testutils"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/hyperledger-labs/orion-server/test/setup"
	"github.com/stretchr/testify/assert"
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

func TestTokensManager_MintToken(t *testing.T) {
	env := newTestEnv(t)

	manager, err := NewManager(env.conf, env.lg)
	require.NoError(t, err)
	require.NotNil(t, manager)

	stat, err := manager.GetStatus()
	require.NoError(t, err)
	require.Contains(t, stat, "connected:")

	deployRequest := &types.DeployRequest{
		Name:        "my-NFT",
		Description: "my NFT for testing",
	}

	deployResponseMy, err := manager.DeployTokenType(deployRequest)
	assert.NoError(t, err)

	t.Run("success: owner is custodian", func(t *testing.T) { //TODO should we prevent custodian and admin from owning tokens?
		getResponse, err := manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualDeployResponse(t, deployResponseMy, getResponse)

		mintRequest := &types.MintRequest{
			Owner:         "alice",
			AssetData:     "my asset",
			AssetMetadata: "my asset meta",
		}
		mintResponse, err := manager.PrepareMint(getResponse.TypeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(mintResponse.TxPayload)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		_, keyPath := env.cluster.GetUserCertKeyPath("alice")
		aliceSigner, err := crypto.NewSigner(&crypto.SignerOptions{
			Identity:    "alice",
			KeyFilePath: keyPath,
		})
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, aliceSigner, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       mintResponse.TokenId,
			TxPayload:     mintResponse.TxPayload,
			TxPayloadHash: mintResponse.TxPayloadHash,
			Signer:        "alice",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.NoError(t, err)
		require.NotNil(t, submitResponse)
		require.Equal(t, submitRequest.TokenId, submitResponse.TokenId)
	})

	t.Run("error: token already exists", func(t *testing.T) {
		getResponse, err := manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualDeployResponse(t, deployResponseMy, getResponse)

		mintRequest := &types.MintRequest{
			Owner:         "charlie",
			AssetData:     "my asset",
			AssetMetadata: "my asset meta",
		}
		mintResponse, err := manager.PrepareMint(getResponse.TypeId, mintRequest)
		require.EqualError(t, err, "token already exists")
		require.IsType(t, &ErrExist{}, err)
		require.Nil(t, mintResponse)
	})

	t.Run("error: not a user", func(t *testing.T) {
		getResponse, err := manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualDeployResponse(t, deployResponseMy, getResponse)

		mintRequest := &types.MintRequest{
			Owner:         "charlie",
			AssetData:     "charlie's asset",
			AssetMetadata: "charlie's asset meta",
		}
		mintResponse, err := manager.PrepareMint(getResponse.TypeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(mintResponse.TxPayload)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		_, keyPath := env.cluster.GetUserCertKeyPath("charlie")
		aliceSigner, err := crypto.NewSigner(&crypto.SignerOptions{
			Identity:    "charlie",
			KeyFilePath: keyPath,
		})
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, aliceSigner, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       mintResponse.TokenId,
			TxPayload:     mintResponse.TxPayload,
			TxPayloadHash: mintResponse.TxPayloadHash,
			Signer:        "charlie",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.EqualError(t, err, "failed to submit transaction, server returned: status: 401 Unauthorized, message: signature verification failed")
		require.IsType(t, &ErrPermission{}, err)
		require.Nil(t, submitResponse)
	})

}

func TestManager_Users(t *testing.T) {
	env := newTestEnv(t)

	manager, err := NewManager(env.conf, env.lg)
	require.NoError(t, err)
	require.NotNil(t, manager)

	stat, err := manager.GetStatus()
	require.NoError(t, err)
	require.Contains(t, stat, "connected:")

	deployRequest1 := &types.DeployRequest{
		Name:        "my-1st-NFT",
		Description: "my NFT for testing",
	}
	deployResponse1, err := manager.DeployTokenType(deployRequest1)
	assert.NoError(t, err)
	deployRequest2 := &types.DeployRequest{
		Name:        "my-2nd-NFT",
		Description: "his NFT for testing",
	}
	deployResponse2, err := manager.DeployTokenType(deployRequest2)
	assert.NoError(t, err)
	tokenTypes := []string{deployResponse1.TypeId, deployResponse2.TypeId}
	sort.Strings(tokenTypes)

	// Add a user
	certBob, _ := testutils.LoadTestCrypto(t, env.cluster.GetUserCertDir(), "bob")
	err = manager.AddUser(&types.UserRecord{
		Identity:    "bob",
		Certificate: base64.StdEncoding.EncodeToString(certBob.Raw),
		Privilege:   nil,
	})
	assert.NoError(t, err)

	// Get a user
	userRecord, err := manager.GetUser("bob")
	assert.NoError(t, err)
	assert.Equal(t, "bob", userRecord.Identity)
	sort.Strings(userRecord.Privilege)
	assert.Equal(t, tokenTypes, userRecord.Privilege)
	assert.Equal(t, base64.StdEncoding.EncodeToString(certBob.Raw), userRecord.Certificate)

	// Add same user again
	err = manager.AddUser(&types.UserRecord{
		Identity:    "bob",
		Certificate: base64.StdEncoding.EncodeToString(certBob.Raw),
		Privilege:   nil,
	})
	assert.EqualError(t, err, "user already exists")
	assert.IsType(t, &ErrExist{}, err)

	// Update a user
	certCharlie, _ := testutils.LoadTestCrypto(t, env.cluster.GetUserCertDir(), "charlie")
	err = manager.UpdateUser(&types.UserRecord{
		Identity:    "bob",
		Certificate: base64.StdEncoding.EncodeToString(certCharlie.Raw),
		Privilege:   []string{deployResponse1.TypeId},
	})
	assert.NoError(t, err)

	// Get updated user
	userRecord, err = manager.GetUser("bob")
	assert.NoError(t, err)
	assert.Equal(t, "bob", userRecord.Identity)
	assert.Len(t, userRecord.Privilege, 1)
	assert.Equal(t, deployResponse1.TypeId, userRecord.Privilege[0])
	assert.Equal(t, base64.StdEncoding.EncodeToString(certCharlie.Raw), userRecord.Certificate)

	// Delete user
	err = manager.RemoveUser("bob")
	assert.NoError(t, err)
	userRecord, err = manager.GetUser("bob")
	assert.EqualError(t, err, "user not found: bob")
	assert.IsType(t, &ErrNotFound{}, err)
	err = manager.RemoveUser("bob")
	assert.EqualError(t, err, "user not found: bob")
	assert.IsType(t, &ErrNotFound{}, err)

	// Update a non-existing user
	err = manager.UpdateUser(&types.UserRecord{
		Identity:    "bob",
		Certificate: base64.StdEncoding.EncodeToString(certCharlie.Raw),
		Privilege:   []string{deployResponse1.TypeId},
	})
	assert.EqualError(t, err, "user not found: bob")
	assert.IsType(t, &ErrNotFound{}, err)
}

func assertEqualDeployResponse(t *testing.T, expected, actual *types.DeployResponse) {
	assert.Equal(t, expected.Name, actual.Name)
	assert.Equal(t, expected.TypeId, actual.TypeId)
	assert.Equal(t, expected.Description, actual.Description)
	assert.Equal(t, expected.Url, actual.Url)
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

type testEnv struct {
	dir     string
	cluster *setup.Cluster
	conf    *config.Configuration
	lg      *logger.SugarLogger
}

func newTestEnv(t *testing.T) *testEnv {
	e := &testEnv{}
	t.Cleanup(e.clean)

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
	e.cluster, err = setup.NewCluster(setupConfig)
	require.NoError(t, err)

	err = e.cluster.Start()
	require.NoError(t, err)

	require.Eventually(t, func() bool { return e.cluster.AgreedLeader(t, 0) >= 0 }, 30*time.Second, time.Second)

	adminCertPath, adminKeyPath := e.cluster.GetUserCertKeyPath("admin")
	aliceCertPath, aliceKeyPath := e.cluster.GetUserCertKeyPath("alice")
	e.conf = &config.Configuration{
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
					Endpoint: e.cluster.Servers[0].URL(),
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

	e.lg, err = logger.New(&logger.Config{
		Level:         "debug",
		OutputPath:    []string{"stdout"},
		ErrOutputPath: []string{"stderr"},
		Encoding:      "console",
		Name:          "copa-tokens-test",
	})
	require.NoError(t, err)

	return e
}

func (e *testEnv) clean() {
	if e == nil {
		return
	}
	if e.cluster != nil {
		_ = e.cluster.ShutdownAndCleanup()
	}
	_ = os.RemoveAll(e.dir)
}
