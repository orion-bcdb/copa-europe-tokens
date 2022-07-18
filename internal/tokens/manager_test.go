// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	tokencrypto "github.com/copa-europe-tokens/pkg/crypto"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"reflect"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/copa-europe-tokens/pkg/config"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	sdkconfig "github.com/hyperledger-labs/orion-sdk-go/pkg/config"
	"github.com/hyperledger-labs/orion-server/pkg/crypto"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/hyperledger-labs/orion-server/pkg/server/testutils"
	"github.com/hyperledger-labs/orion-server/test/setup"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTokensManager(t *testing.T) {
	env := newTestEnv(t)
	require.NotNil(t, env)
}

func assertTokenHttpErr(t *testing.T, expectedStatus int, actualResponse interface{}, actualErr error) bool {
	if !assert.Nil(t, actualResponse, "Response %+v, Error: %v", actualResponse, actualErr) {
		return false
	}

	if !assert.Error(t, actualErr) {
		return false
	}

	tknErr, ok := actualErr.(*TokenHttpErr)
	if !ok {
		return assert.Fail(t, fmt.Sprintf("Error expected to implement TokenHttpErr, but was %v.",
			reflect.TypeOf(actualErr)), "Error: %v", actualErr)
	}
	return assert.Equal(t, expectedStatus, tknErr.StatusCode, "Error: %v", actualErr)
}

func assertTokenHttpErrMessage(t *testing.T, expectedStatus int, expectedMessage string, actualResponse interface{}, actualErr error) bool {
	if !assertTokenHttpErr(t, expectedStatus, actualResponse, actualErr) {
		return false
	}

	return assert.EqualError(t, actualErr, expectedMessage)
}

func TestTokensManager_Deploy(t *testing.T) {
	env := newTestEnv(t)

	deployRequestMy := &types.DeployRequest{
		Name:        "my-NFT",
		Description: "my NFT for testing",
	}

	t.Run("success: NFT", func(t *testing.T) {
		deployResponseMy, err := env.manager.DeployTokenType(deployRequestMy)
		assert.NoError(t, err)
		assert.Equal(t, deployRequestMy.Name, deployResponseMy.Name)
		expectedIdMy, _ := NameToID(deployRequestMy.Name)
		assert.Equal(t, expectedIdMy, deployResponseMy.TypeId)
		assert.Equal(t, constants.TokensTypesSubTree+expectedIdMy, deployResponseMy.Url)

		deployRequestHis := &types.DeployRequest{
			Name:        "his-NFT",
			Description: "", //empty description is fine
			Class:       constants.TokenClass_NFT,
		}
		deployResponseHis, err := env.manager.DeployTokenType(deployRequestHis)
		assert.NoError(t, err)
		assert.Equal(t, deployRequestHis.Name, deployResponseHis.Name)
		expectedIdHis, _ := NameToID(deployRequestHis.Name)
		assert.Equal(t, expectedIdHis, deployResponseHis.TypeId)
		assert.Equal(t, constants.TokensTypesSubTree+expectedIdHis, deployResponseHis.Url)
	})

	t.Run("success: ANNOTATIONS", func(t *testing.T) {
		deployRequestAnnt := &types.DeployRequest{
			Name:        "my-annotations",
			Description: "annotations aon my NFTs",
			Class:       constants.TokenClass_ANNOTATIONS,
		}
		deployResponseAnnt, err := env.manager.DeployTokenType(deployRequestAnnt)
		assert.NoError(t, err)
		assert.Equal(t, deployRequestAnnt.Name, deployResponseAnnt.Name)
		expectedIdHis, _ := NameToID(deployRequestAnnt.Name)
		assert.Equal(t, expectedIdHis, deployResponseAnnt.TypeId)
		assert.Equal(t, constants.TokensTypesSubTree+expectedIdHis, deployResponseAnnt.Url)
	})

	t.Run("error: deploy again", func(t *testing.T) {
		deployResponseBad, err := env.manager.DeployTokenType(deployRequestMy)
		assert.Error(t, err)
		assert.EqualError(t, err, "token type already exists")
		assert.Nil(t, deployResponseBad)
	})

	t.Run("error: empty name", func(t *testing.T) {
		deployRequestEmpty := &types.DeployRequest{
			Name:        "",
			Description: "",
		}
		deployResponseBad, err := env.manager.DeployTokenType(deployRequestEmpty)
		assert.EqualError(t, err, "token type name is empty")
		assert.Nil(t, deployResponseBad)
	})

	t.Run("error: wrong class", func(t *testing.T) {
		deployRequestEmpty := &types.DeployRequest{
			Name:  "wrong class",
			Class: "no-such-class",
		}
		deployResponseBad, err := env.manager.DeployTokenType(deployRequestEmpty)
		assert.EqualError(t, err, "unsupported token class: no-such-class")
		assert.Nil(t, deployResponseBad)
	})

	t.Run("error: not supported class", func(t *testing.T) {
		deployRequestEmpty := &types.DeployRequest{
			Name:  "wrong class",
			Class: constants.TokenClass_FUNGIBLE,
		}
		deployResponseBad, err := env.manager.DeployTokenType(deployRequestEmpty)
		assertTokenHttpErr(t, http.StatusBadRequest, deployResponseBad, err)
	})
}

func TestTokensManager_GetTokenType(t *testing.T) {
	env := newTestEnv(t)

	deployRequestMy := &types.DeployRequest{
		Name:        "my-NFT",
		Description: "my NFT for testing",
	}

	deployResponseMy, err := env.manager.DeployTokenType(deployRequestMy)
	assert.NoError(t, err)

	deployRequestHis := &types.DeployRequest{
		Name:        "his-NFT",
		Description: "", //empty description is fine
	}
	deployResponseHis, err := env.manager.DeployTokenType(deployRequestHis)
	assert.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		deployResponse, err := env.manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualGetTokenType(t, deployResponseMy, deployResponse)

		deployResponse, err = env.manager.GetTokenType(deployResponseHis.TypeId)
		assert.NoError(t, err)
		assertEqualGetTokenType(t, deployResponseHis, deployResponse)
	})

	t.Run("error: empty", func(t *testing.T) {
		deployResponse, err := env.manager.GetTokenType("")
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "token type ID is empty", deployResponse, err)
	})

	t.Run("error: too long", func(t *testing.T) {
		deployResponse, err := env.manager.GetTokenType("12345678123456781234567812345678")
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "token type ID is too long", deployResponse, err)
	})

	t.Run("error: not base64url", func(t *testing.T) {
		deployResponse, err := env.manager.GetTokenType("123~")
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "token type ID is not in base64url", deployResponse, err)
	})

	t.Run("error: not found", func(t *testing.T) {
		deployResponse, err := env.manager.GetTokenType("1234")
		assertTokenHttpErr(t, http.StatusNotFound, deployResponse, err)
	})

}

func TestTokensManager_GetTokenTypes(t *testing.T) {
	env := newTestEnv(t)

	tokenTypes, err := env.manager.GetTokenTypes()
	require.NoError(t, err)
	require.Len(t, tokenTypes, 0)

	deployRequestMy := &types.DeployRequest{
		Name:        "my-NFT",
		Description: "my NFT for testing",
	}

	deployResponseMy, err := env.manager.DeployTokenType(deployRequestMy)
	t.Logf("my %s", deployResponseMy.TypeId)
	assert.NoError(t, err)

	deployRequestHis := &types.DeployRequest{
		Name:        "his-NFT",
		Description: "", //empty description is fine
	}
	deployResponseHis, err := env.manager.DeployTokenType(deployRequestHis)
	assert.NoError(t, err)
	t.Logf("his %s", deployResponseHis.TypeId)

	deployResponse, err := env.manager.GetTokenType(deployResponseMy.TypeId)
	assert.NoError(t, err)
	assertEqualGetTokenType(t, deployResponseMy, deployResponse)

	deployResponse, err = env.manager.GetTokenType(deployResponseHis.TypeId)
	assert.NoError(t, err)
	assertEqualGetTokenType(t, deployResponseHis, deployResponse)

	tokenTypes, err = env.manager.GetTokenTypes()
	require.NoError(t, err)
	t.Logf("%v", tokenTypes)
	require.Len(t, tokenTypes, 2)

	for _, dy := range tokenTypes {
		found := false
		for _, dx := range []*types.DeployResponse{deployResponseMy, deployResponseHis} {
			if dx.Name == dy["name"] {
				assertEqualGetTokenType(t, dx, dy)
				found = true
			}
		}
		require.True(t, found)
	}
}

func TestTokensManager_MintToken(t *testing.T) {
	env := newTestEnv(t)

	deployRequest := &types.DeployRequest{
		Name:        "my-NFT",
		Description: "my NFT for testing",
	}

	deployResponseMy, err := env.manager.DeployTokenType(deployRequest)
	assert.NoError(t, err)

	env.updateUsers()

	t.Run("success: owner is user bob", func(t *testing.T) {
		getResponse, err := env.manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualGetTokenType(t, deployResponseMy, getResponse)

		mintRequest := &types.MintRequest{
			Owner:         "bob",
			AssetData:     "bob's asset",
			AssetMetadata: "bob's asset meta",
		}
		mintResponse, err := env.manager.PrepareMint(getResponse["typeId"], mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse := env.requireSignAndSubmit("bob", mintResponse)
		require.Equal(t, mintResponse.TokenId, submitResponse.TxContext)

		// Get this token
		tokenRecord, err := env.manager.GetToken(mintResponse.TokenId)
		require.NoError(t, err)
		require.Equal(t, mintRequest.Owner, tokenRecord.Owner)
		require.Equal(t, mintRequest.AssetData, tokenRecord.AssetData)
		require.Equal(t, mintRequest.AssetMetadata, tokenRecord.AssetMetadata)
		h, err := ComputeMD5Hash([]byte(tokenRecord.AssetData))
		require.NoError(t, err)
		require.Equal(t, base64.RawURLEncoding.EncodeToString(h), tokenRecord.AssetDataId)
	})

	t.Run("error: owner is custodian or admin", func(t *testing.T) {
		getResponse, err := env.manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualGetTokenType(t, deployResponseMy, getResponse)

		mintRequest := &types.MintRequest{
			Owner:         "alice",
			AssetData:     "my asset",
			AssetMetadata: "my asset meta",
		}
		mintResponse, err := env.manager.PrepareMint(getResponse["typeId"], mintRequest)
		assertTokenHttpErr(t, http.StatusBadRequest, mintResponse, err)

		mintRequest = &types.MintRequest{
			Owner:         "admin",
			AssetData:     "my asset",
			AssetMetadata: "my asset meta",
		}
		mintResponse, err = env.manager.PrepareMint(getResponse["typeId"], mintRequest)
		assertTokenHttpErr(t, http.StatusBadRequest, mintResponse, err)
	})

	t.Run("error: token already exists", func(t *testing.T) {
		getResponse, err := env.manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualGetTokenType(t, deployResponseMy, getResponse)

		mintRequest := &types.MintRequest{
			Owner:         "charlie",
			AssetData:     "bob's asset",
			AssetMetadata: "bob's asset meta",
		}
		mintResponse, err := env.manager.PrepareMint(getResponse["typeId"], mintRequest)
		assertTokenHttpErrMessage(t, http.StatusConflict, "token already exists", mintResponse, err)
	})

	t.Run("error: not a user", func(t *testing.T) {
		getResponse, err := env.manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualGetTokenType(t, deployResponseMy, getResponse)

		mintRequest := &types.MintRequest{
			Owner:         "dave",
			AssetData:     "dave's asset",
			AssetMetadata: "dave's asset meta",
		}
		mintResponse, err := env.manager.PrepareMint(getResponse["typeId"], mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		err = env.manager.RemoveUser("dave")
		require.Nil(t, err)

		submitResponse, err := env.signAndSubmit("dave", mintResponse)
		assertTokenHttpErrMessage(t, http.StatusForbidden,
			"failed to submit transaction, server returned: status: 401 Unauthorized, message: signature verification failed",
			submitResponse, err)
	})

	t.Run("error: get parameters", func(t *testing.T) {
		tokenRecord, err := env.manager.GetToken("")
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "invalid tokenId", tokenRecord, err)

		tokenRecord, err = env.manager.GetToken("xxx")
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "invalid tokenId", tokenRecord, err)

		tokenRecord, err = env.manager.GetToken("xxx.yyy.zzz")
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "invalid tokenId", tokenRecord, err)

		tokenRecord, err = env.manager.GetToken("token-not-deployed.xxx")
		assertTokenHttpErrMessage(t, http.StatusNotFound, "token type not found: token-not-deployed", tokenRecord, err)
	})
}

func TestTokensManager_TransferToken(t *testing.T) {
	env := newTestEnv(t)

	deployRequest := &types.DeployRequest{
		Name:        "my-NFT",
		Description: "my NFT for testing",
	}

	deployResponse, err := env.manager.DeployTokenType(deployRequest)
	assert.NoError(t, err)

	env.updateUsers()

	var tokenIDs []string
	for i := 1; i <= 5; i++ {
		mintRequest := &types.MintRequest{
			Owner:         "bob",
			AssetData:     fmt.Sprintf("bob's asset %d", i),
			AssetMetadata: "bob's asset metadata",
		}
		mintResponse, err := env.manager.PrepareMint(deployResponse.TypeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse := env.requireSignAndSubmit("bob", mintResponse)
		tokenIDs = append(tokenIDs, submitResponse.TxContext)
	}

	t.Run("success: bob to charlie", func(t *testing.T) {
		transferRequest := &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "charlie",
		}
		transferResponse, err := env.manager.PrepareTransfer(tokenIDs[0], transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)

		env.requireSignAndSubmit("bob", transferResponse)

		// Get this token
		tokenRecord, err := env.manager.GetToken(tokenIDs[0])
		require.NoError(t, err)
		require.Equal(t, transferRequest.NewOwner, tokenRecord.Owner)
	})

	t.Run("error: new-owner is custodian or admin", func(t *testing.T) {
		transferRequest := &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "alice", //custodian
		}
		transferResponse, err := env.manager.PrepareTransfer(tokenIDs[1], transferRequest)
		assertTokenHttpErr(t, http.StatusBadRequest, transferResponse, err)

		transferRequest = &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "admin", //admin
		}
		transferResponse, err = env.manager.PrepareTransfer(tokenIDs[1], transferRequest)
		assertTokenHttpErr(t, http.StatusBadRequest, transferResponse, err)

		transferRequest = &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "admin", //admin
		}
		transferResponse, err = env.manager.PrepareTransfer(tokenIDs[1], transferRequest)
		assertTokenHttpErr(t, http.StatusBadRequest, transferResponse, err)
	})

	t.Run("error: token type does not exists", func(t *testing.T) {
		transferRequest := &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "charlie",
		}
		transferResponse, err := env.manager.PrepareTransfer("aaaaabbbbbcccccdddddee.uuuuuvvvvvwwwwwxxxxxzz", transferRequest)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "token type not found: aaaaabbbbbcccccdddddee", transferResponse, err)

	})

	t.Run("error: token does not exists", func(t *testing.T) {
		transferRequest := &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "charlie",
		}
		transferResponse, err := env.manager.PrepareTransfer(deployResponse.TypeId+".uuuuuvvvvvwwwwwxxxxxzz", transferRequest)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "token not found: "+deployResponse.TypeId+".uuuuuvvvvvwwwwwxxxxxzz", transferResponse, err)
	})

	t.Run("error: new owner not a user", func(t *testing.T) {
		transferRequest := &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "david",
		}
		transferResponse, err := env.manager.PrepareTransfer(tokenIDs[1], transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)

		submitResponse, err := env.signAndSubmit("bob", transferResponse)
		if assertTokenHttpErr(t, http.StatusBadRequest, submitResponse, err) {
			assert.Contains(t, err.Error(), "is not valid, flag: INVALID_INCORRECT_ENTRIES, reason: the user [david] defined in the access control for the key [gm8Ndnh5x9firTQ2FLrIcQ] does not exist")
		}
	})

	t.Run("error: wrong signature", func(t *testing.T) {
		transferRequest := &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "charlie",
		}
		transferResponse, err := env.manager.PrepareTransfer(tokenIDs[2], transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)

		submitRequest := &types.SubmitRequest{
			TxContext:     transferResponse.TokenId,
			TxEnvelope:    transferResponse.TxEnvelope,
			TxPayloadHash: transferResponse.TxPayloadHash,
			Signer:        "bob",
			Signature:     base64.StdEncoding.EncodeToString([]byte("bogus-sig")),
		}

		submitResponse, err := env.manager.SubmitTx(submitRequest)
		assert.Regexp(t, regexp.MustCompile(".*is not valid, flag: INVALID_NO_PERMISSION, reason: not all required (signers|users) in \\[alice,bob] have signed the transaction to write/delete key \\[sVnBPZovzX2wvtnOxxg1Sg] present in the database \\[ttid\\.kdcFXEExc8FvQTDDumKyUw].*"), err.Error())
		require.Nil(t, submitResponse)
	})
}

func TestTokensManager_GetTokensByOwner(t *testing.T) {
	env := newTestEnv(t)

	deployRequest := &types.DeployRequest{
		Name:        "my-NFT",
		Description: "my NFT for testing",
	}

	deployResponse, err := env.manager.DeployTokenType(deployRequest)
	assert.NoError(t, err)

	env.updateUsers()

	var tokenIDs []string
	for i := 1; i <= 5; i++ {
		mintRequest := &types.MintRequest{
			Owner:         "bob",
			AssetData:     fmt.Sprintf("bob's asset %d", i),
			AssetMetadata: "bob's asset metadata",
		}
		mintResponse, err := env.manager.PrepareMint(deployResponse.TypeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse := env.requireSignAndSubmit("bob", mintResponse)
		tokenIDs = append(tokenIDs, submitResponse.TxContext)
	}

	for i := 1; i <= 6; i++ {
		mintRequest := &types.MintRequest{
			Owner:         "charlie",
			AssetData:     fmt.Sprintf("charlie's asset %d", i),
			AssetMetadata: "charlie's asset metadata",
		}
		mintResponse, err := env.manager.PrepareMint(deployResponse.TypeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse := env.requireSignAndSubmit("charlie", mintResponse)
		tokenIDs = append(tokenIDs, submitResponse.TxContext)
	}

	t.Run("success", func(t *testing.T) {
		records, err := env.manager.GetTokensByOwner(deployResponse.TypeId, "bob")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 5)

		records, err = env.manager.GetTokensByOwner(deployResponse.TypeId, "charlie")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 6)
	})

	t.Run("success: manager restart", func(t *testing.T) {
		err = env.manager.Close()
		require.NoError(t, err)
		env.manager, err = NewManager(env.conf, env.lg)
		require.NoError(t, err)
		require.NotNil(t, env.manager)

		records, err := env.manager.GetTokensByOwner(deployResponse.TypeId, "bob")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 5)

		records, err = env.manager.GetTokensByOwner(deployResponse.TypeId, "charlie")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 6)
	})

}

func TestManager_Users(t *testing.T) {
	env := newTestEnv(t)

	deployRequest1 := &types.DeployRequest{
		Name:        "my-1st-NFT",
		Description: "my NFT for testing",
	}
	deployResponse1, err := env.manager.DeployTokenType(deployRequest1)
	assert.NoError(t, err)
	deployRequest2 := &types.DeployRequest{
		Name:        "my-2nd-NFT",
		Description: "his NFT for testing",
	}
	deployResponse2, err := env.manager.DeployTokenType(deployRequest2)
	assert.NoError(t, err)
	tokenTypes := []string{deployResponse1.TypeId, deployResponse2.TypeId}
	sort.Strings(tokenTypes)

	// Update users
	env.updateUsers()

	// Get a user
	userRecord, err := env.manager.GetUser("bob")
	assert.NoError(t, err)
	assert.Equal(t, "bob", userRecord.Identity)
	sort.Strings(userRecord.Privilege)
	assert.Equal(t, tokenTypes, userRecord.Privilege)
	assert.Equal(t, base64.StdEncoding.EncodeToString(env.certs["bob"].Raw), userRecord.Certificate)

	// Add same user again
	err = env.manager.AddUser(&types.UserRecord{
		Identity:    "bob",
		Certificate: base64.StdEncoding.EncodeToString(env.certs["bob"].Raw),
		Privilege:   nil,
	})
	assertTokenHttpErrMessage(t, http.StatusConflict, "user already exists: bob", nil, err)

	// Update a user
	certCharlie, _ := testutils.LoadTestCrypto(t, env.cluster.GetUserCertDir(), "charlie")
	err = env.manager.UpdateUser(&types.UserRecord{
		Identity:    "bob",
		Certificate: base64.StdEncoding.EncodeToString(certCharlie.Raw),
		Privilege:   []string{deployResponse1.TypeId},
	})
	assert.NoError(t, err)

	// Get updated user
	userRecord, err = env.manager.GetUser("bob")
	assert.NoError(t, err)
	assert.Equal(t, "bob", userRecord.Identity)
	assert.Len(t, userRecord.Privilege, 1)
	assert.Equal(t, deployResponse1.TypeId, userRecord.Privilege[0])
	assert.Equal(t, base64.StdEncoding.EncodeToString(certCharlie.Raw), userRecord.Certificate)

	// Delete user
	err = env.manager.RemoveUser("bob")
	assert.NoError(t, err)
	userRecord, err = env.manager.GetUser("bob")
	assertTokenHttpErrMessage(t, http.StatusNotFound, "user not found: bob", userRecord, err)

	err = env.manager.RemoveUser("bob")
	assertTokenHttpErrMessage(t, http.StatusNotFound, "user not found: bob", nil, err)

	// Update a non-existing user
	err = env.manager.UpdateUser(&types.UserRecord{
		Identity:    "bob",
		Certificate: base64.StdEncoding.EncodeToString(certCharlie.Raw),
		Privilege:   []string{deployResponse1.TypeId},
	})
	assertTokenHttpErrMessage(t, http.StatusNotFound, "user not found: bob", nil, err)
}

func assertEqualGetTokenType(t *testing.T, expected *types.DeployResponse, actual map[string]string) {
	assert.Equal(t, expected.Name, actual["name"])
	assert.Equal(t, expected.TypeId, actual["typeId"])
	assert.Equal(t, expected.Description, actual["description"])
	assert.Equal(t, expected.Url, actual["url"])
}

type testEnv struct {
	t           *testing.T
	dir         string
	cluster     *setup.Cluster
	conf        *config.Configuration
	lg          *logger.SugarLogger
	manager     Operations
	userRecords map[string]*types.UserRecord
	certs       map[string]*x509.Certificate
	signers     map[string]crypto.Signer
}

func newTestEnv(t *testing.T) *testEnv {
	e := &testEnv{
		t:           t,
		userRecords: map[string]*types.UserRecord{},
		certs:       map[string]*x509.Certificate{},
		signers:     map[string]crypto.Signer{},
	}
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

	e.manager, err = NewManager(e.conf, e.lg)
	require.NoError(t, err)
	require.NotNil(t, e.manager)

	stat, err := e.manager.GetStatus()
	require.NoError(t, err)
	require.Contains(t, stat, "connected:")

	keyPair, err := e.cluster.GetX509KeyPair()
	require.NoError(t, err)
	require.NoError(t, e.cluster.CreateUserCerts("dave", keyPair))

	for _, user := range []string{"alice", "admin"} {
		e.certs[user], e.signers[user] = testutils.LoadTestCrypto(t, e.cluster.GetUserCertDir(), user)
	}

	e.addUser("bob")
	e.addUser("charlie")
	e.addUser("dave")

	return e
}

func (e *testEnv) addUser(user string) {
	cert, signer := testutils.LoadTestCrypto(e.t, e.cluster.GetUserCertDir(), user)
	record := &types.UserRecord{
		Identity:    user,
		Certificate: base64.StdEncoding.EncodeToString(cert.Raw),
		Privilege:   nil,
	}
	err := e.manager.AddUser(record)
	require.NoError(e.t, err)
	e.userRecords[user] = record
	e.certs[user] = cert
	e.signers[user] = signer
}

func (e *testEnv) updateUsers() {
	for _, record := range e.userRecords {
		err := e.manager.UpdateUser(record)
		require.NoError(e.t, err)
	}
}

func (e *testEnv) signAndSubmit(user string, response tokencrypto.SignatureRequester) (*types.SubmitResponse, error) {
	submitRequest, err := tokencrypto.SignTransactionResponse(e.signers[user], response)
	require.NoError(e.t, err)
	return e.manager.SubmitTx(submitRequest)
}

func (e *testEnv) requireSignAndSubmit(user string, response tokencrypto.SignatureRequester) *types.SubmitResponse {
	submitResponse, err := e.signAndSubmit(user, response)
	require.NoError(e.t, err)
	require.NotNil(e.t, submitResponse)
	return submitResponse
}

func (e *testEnv) wrongSignAndSubmit(user string, response tokencrypto.SignatureRequester) (*types.SubmitResponse, error) {
	submitRequest := response.PrepareSubmit()
	submitRequest.Signer = user
	submitRequest.Signature = base64.StdEncoding.EncodeToString([]byte("bogus-sig"))
	return e.manager.SubmitTx(submitRequest)
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
