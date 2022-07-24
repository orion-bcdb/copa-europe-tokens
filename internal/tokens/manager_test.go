// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"encoding/base64"
	"fmt"
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
	env := newTestEnv(t)

	manager, err := NewManager(env.conf, env.lg)
	require.NoError(t, err)
	require.NotNil(t, manager)

	stat, err := manager.GetStatus()
	require.NoError(t, err)
	require.Regexp(t, "connected: {Id: node-1, Address: 127.0.0.1, Port: 7581, Cert-hash: [0-9a-fA-F]+", stat)
}

func TestTokensManager_Deploy(t *testing.T) {
	env := newTestEnv(t)

	manager, err := NewManager(env.conf, env.lg)
	require.NoError(t, err)
	require.NotNil(t, manager)

	stat, err := manager.GetStatus()
	require.NoError(t, err)
	require.Contains(t, stat, "connected:")

	deployRequestMy := &types.DeployRequest{
		Name:        "my-NFT",
		Description: "my NFT for testing",
	}

	t.Run("success: NFT", func(t *testing.T) {
		deployResponseMy, err := manager.DeployTokenType(deployRequestMy)
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
		deployResponseHis, err := manager.DeployTokenType(deployRequestHis)
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
		deployResponseAnnt, err := manager.DeployTokenType(deployRequestAnnt)
		assert.NoError(t, err)
		assert.Equal(t, deployRequestAnnt.Name, deployResponseAnnt.Name)
		expectedIdHis, _ := NameToID(deployRequestAnnt.Name)
		assert.Equal(t, expectedIdHis, deployResponseAnnt.TypeId)
		assert.Equal(t, constants.TokensTypesSubTree+expectedIdHis, deployResponseAnnt.Url)
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

	t.Run("error: wrong class", func(t *testing.T) {
		deployRequestEmpty := &types.DeployRequest{
			Name:  "wrong class",
			Class: "no-such-class",
		}
		deployResponseBad, err := manager.DeployTokenType(deployRequestEmpty)
		assert.EqualError(t, err, "unsupported token class: no-such-class")
		assert.Nil(t, deployResponseBad)
	})
}

func TestTokensManager_GetTokenType(t *testing.T) {
	env := newTestEnv(t)

	manager, err := NewManager(env.conf, env.lg)
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

func TestTokensManager_GetTokenTypes(t *testing.T) {
	env := newTestEnv(t)

	manager, err := NewManager(env.conf, env.lg)
	require.NoError(t, err)
	require.NotNil(t, manager)

	stat, err := manager.GetStatus()
	require.NoError(t, err)
	require.Contains(t, stat, "connected:")

	tokenTypes, err := manager.GetTokenTypes()
	require.NoError(t, err)
	require.Len(t, tokenTypes, 0)

	deployRequestMy := &types.DeployRequest{
		Name:        "my-NFT",
		Description: "my NFT for testing",
	}

	deployResponseMy, err := manager.DeployTokenType(deployRequestMy)
	t.Logf("my %s", deployResponseMy.TypeId)
	assert.NoError(t, err)

	deployRequestHis := &types.DeployRequest{
		Name:        "his-NFT",
		Description: "", //empty description is fine
	}
	deployResponseHis, err := manager.DeployTokenType(deployRequestHis)
	assert.NoError(t, err)
	t.Logf("his %s", deployResponseHis.TypeId)

	deployResponse, err := manager.GetTokenType(deployResponseMy.TypeId)
	assert.NoError(t, err)
	assertEqualDeployResponse(t, deployResponseMy, deployResponse)

	deployResponse, err = manager.GetTokenType(deployResponseHis.TypeId)
	assert.NoError(t, err)
	assertEqualDeployResponse(t, deployResponseHis, deployResponse)

	tokenTypes, err = manager.GetTokenTypes()
	require.NoError(t, err)
	t.Logf("%v", tokenTypes)
	require.Len(t, tokenTypes, 2)

	for _, dy := range tokenTypes {
		found := false
		for _, dx := range []*types.DeployResponse{deployResponseMy, deployResponseHis} {
			if dx.Name == dy.Name {
				assertEqualDeployResponse(t, dx, dy)
				found = true
			}
		}
		require.True(t, found)
	}
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

	t.Run("success: owner is user bob", func(t *testing.T) {
		getResponse, err := manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualDeployResponse(t, deployResponseMy, getResponse)

		certBob, signerBob := testutils.LoadTestCrypto(t, env.cluster.GetUserCertDir(), "bob")
		err = manager.AddUser(&types.UserRecord{
			Identity:    "bob",
			Certificate: base64.StdEncoding.EncodeToString(certBob.Raw),
			Privilege:   nil,
		})
		assert.NoError(t, err)

		mintRequest := &types.MintRequest{
			Owner:         "bob",
			AssetData:     "bob's asset",
			AssetMetadata: "bob's asset meta",
		}
		mintResponse, err := manager.PrepareMint(getResponse.TypeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(mintResponse.TxEnvelope)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, signerBob, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       mintResponse.TokenId,
			TxEnvelope:    mintResponse.TxEnvelope,
			TxPayloadHash: mintResponse.TxPayloadHash,
			Signer:        "bob",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.NoError(t, err)
		require.NotNil(t, submitResponse)
		require.Equal(t, submitRequest.TokenId, submitResponse.TokenId)

		// Get this token
		tokenRecord, err := manager.GetToken(mintResponse.TokenId)
		require.NoError(t, err)
		require.Equal(t, mintRequest.Owner, tokenRecord.Owner)
		require.Equal(t, mintRequest.AssetData, tokenRecord.AssetData)
		require.Equal(t, mintRequest.AssetMetadata, tokenRecord.AssetMetadata)
		h, err := ComputeMD5Hash([]byte(tokenRecord.AssetData))
		require.NoError(t, err)
		require.Equal(t, base64.RawURLEncoding.EncodeToString(h), tokenRecord.AssetDataId)
	})

	t.Run("error: owner is custodian or admin", func(t *testing.T) {
		getResponse, err := manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualDeployResponse(t, deployResponseMy, getResponse)

		mintRequest := &types.MintRequest{
			Owner:         "alice",
			AssetData:     "my asset",
			AssetMetadata: "my asset meta",
		}
		mintResponse, err := manager.PrepareMint(getResponse.TypeId, mintRequest)
		require.EqualError(t, err, "owner cannot be the custodian: alice")
		require.IsType(t, &ErrInvalid{}, err)
		require.Nil(t, mintResponse)

		mintRequest = &types.MintRequest{
			Owner:         "admin",
			AssetData:     "my asset",
			AssetMetadata: "my asset meta",
		}
		mintResponse, err = manager.PrepareMint(getResponse.TypeId, mintRequest)
		require.EqualError(t, err, "owner cannot be the admin: admin")
		require.IsType(t, &ErrInvalid{}, err)
		require.Nil(t, mintResponse)
	})

	t.Run("error: token already exists", func(t *testing.T) {
		getResponse, err := manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualDeployResponse(t, deployResponseMy, getResponse)

		mintRequest := &types.MintRequest{
			Owner:         "charlie",
			AssetData:     "bob's asset",
			AssetMetadata: "bob's asset meta",
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

		txEnvBytes, err := base64.StdEncoding.DecodeString(mintResponse.TxEnvelope)
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
			TxEnvelope:    mintResponse.TxEnvelope,
			TxPayloadHash: mintResponse.TxPayloadHash,
			Signer:        "charlie",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.EqualError(t, err, "failed to submit transaction, server returned: status: 401 Unauthorized, message: signature verification failed")
		require.IsType(t, &ErrPermission{}, err)
		require.Nil(t, submitResponse)
	})

	t.Run("error: get parameters", func(t *testing.T) {
		tokenRecord, err := manager.GetToken("")
		require.EqualError(t, err, "invalid tokenId")
		require.IsType(t, &ErrInvalid{}, err)
		require.Nil(t, tokenRecord)

		tokenRecord, err = manager.GetToken("xxx")
		require.EqualError(t, err, "invalid tokenId")
		require.IsType(t, &ErrInvalid{}, err)
		require.Nil(t, tokenRecord)

		tokenRecord, err = manager.GetToken("xxx.yyy.zzz")
		require.EqualError(t, err, "invalid tokenId")
		require.IsType(t, &ErrInvalid{}, err)
		require.Nil(t, tokenRecord)

		tokenRecord, err = manager.GetToken("token-not-deployed.xxx")
		require.EqualError(t, err, "token type not found: token-not-deployed")
		require.IsType(t, &ErrNotFound{}, err)
		require.Nil(t, tokenRecord)
	})
}

func TestTokensManager_TransferToken(t *testing.T) {
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

	deployResponse, err := manager.DeployTokenType(deployRequest)
	assert.NoError(t, err)

	certBob, signerBob := testutils.LoadTestCrypto(t, env.cluster.GetUserCertDir(), "bob")
	err = manager.AddUser(&types.UserRecord{
		Identity:    "bob",
		Certificate: base64.StdEncoding.EncodeToString(certBob.Raw),
		Privilege:   nil,
	})
	assert.NoError(t, err)

	certCharlie, signerCharlie := testutils.LoadTestCrypto(t, env.cluster.GetUserCertDir(), "charlie")
	err = manager.AddUser(&types.UserRecord{
		Identity:    "charlie",
		Certificate: base64.StdEncoding.EncodeToString(certCharlie.Raw),
		Privilege:   nil,
	})
	assert.NoError(t, err)

	var tokenIDs []string
	for i := 1; i <= 5; i++ {
		mintRequest := &types.MintRequest{
			Owner:         "bob",
			AssetData:     fmt.Sprintf("bob's asset %d", i),
			AssetMetadata: "bob's asset metadata",
		}
		mintResponse, err := manager.PrepareMint(deployResponse.TypeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(mintResponse.TxEnvelope)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, signerBob, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       mintResponse.TokenId,
			TxEnvelope:    mintResponse.TxEnvelope,
			TxPayloadHash: mintResponse.TxPayloadHash,
			Signer:        "bob",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.NoError(t, err)
		tokenIDs = append(tokenIDs, submitResponse.TokenId)
	}

	t.Run("success: bob to charlie", func(t *testing.T) {
		transferRequest := &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "charlie",
		}
		transferResponse, err := manager.PrepareTransfer(tokenIDs[0], transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(transferResponse.TxEnvelope)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, signerBob, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       transferResponse.TokenId,
			TxEnvelope:    transferResponse.TxEnvelope,
			TxPayloadHash: transferResponse.TxPayloadHash,
			Signer:        "bob",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.NoError(t, err)
		require.NotNil(t, submitResponse)

		// Get this token
		tokenRecord, err := manager.GetToken(tokenIDs[0])
		require.NoError(t, err)
		require.Equal(t, transferRequest.NewOwner, tokenRecord.Owner)
	})

	t.Run("error: new-owner is custodian or admin", func(t *testing.T) {
		transferRequest := &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "alice", //custodian
		}
		transferResponse, err := manager.PrepareTransfer(tokenIDs[1], transferRequest)
		require.EqualError(t, err, "new owner cannot be the custodian: alice")
		require.Nil(t, transferResponse)

		transferRequest = &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "admin", //admin
		}
		transferResponse, err = manager.PrepareTransfer(tokenIDs[1], transferRequest)
		require.EqualError(t, err, "new owner cannot be the admin: admin")
		require.Nil(t, transferResponse)

		transferRequest = &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "admin", //admin
		}
		transferResponse, err = manager.PrepareTransfer(tokenIDs[1], transferRequest)
		require.EqualError(t, err, "new owner cannot be the admin: admin")
		require.Nil(t, transferResponse)
	})

	t.Run("error: token type does not exists", func(t *testing.T) {
		transferRequest := &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "charlie",
		}
		transferResponse, err := manager.PrepareTransfer("aaaaabbbbbcccccdddddee.uuuuuvvvvvwwwwwxxxxxzz", transferRequest)
		require.EqualError(t, err, "token type not found: aaaaabbbbbcccccdddddee")
		require.IsType(t, &ErrNotFound{}, err)
		require.Nil(t, transferResponse)
	})

	t.Run("error: token does not exists", func(t *testing.T) {
		transferRequest := &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "charlie",
		}
		transferResponse, err := manager.PrepareTransfer(deployResponse.TypeId+".uuuuuvvvvvwwwwwxxxxxzz", transferRequest)
		require.EqualError(t, err, "token not found: "+deployResponse.TypeId+".uuuuuvvvvvwwwwwxxxxxzz")
		require.IsType(t, &ErrNotFound{}, err)
		require.Nil(t, transferResponse)
	})

	t.Run("error: new owner not a user", func(t *testing.T) {
		transferRequest := &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "david",
		}
		transferResponse, err := manager.PrepareTransfer(tokenIDs[1], transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(transferResponse.TxEnvelope)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, signerBob, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       transferResponse.TokenId,
			TxEnvelope:    transferResponse.TxEnvelope,
			TxPayloadHash: transferResponse.TxPayloadHash,
			Signer:        "bob",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		assert.Contains(t, err.Error(), "is not valid, flag: INVALID_INCORRECT_ENTRIES, reason: the user [david] defined in the access control for the key [gm8Ndnh5x9firTQ2FLrIcQ] does not exist")
		assert.IsType(t, &ErrInvalid{}, err)
		require.Nil(t, submitResponse)
	})

	t.Run("error: wrong signature", func(t *testing.T) {
		transferRequest := &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "charlie",
		}
		transferResponse, err := manager.PrepareTransfer(tokenIDs[2], transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(transferResponse.TxEnvelope)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, signerCharlie, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       transferResponse.TokenId,
			TxEnvelope:    transferResponse.TxEnvelope,
			TxPayloadHash: transferResponse.TxPayloadHash,
			Signer:        "bob",
			Signature:     base64.StdEncoding.EncodeToString([]byte("bogus-sig")),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		assert.Contains(t, err.Error(), "is not valid, flag: INVALID_NO_PERMISSION, reason: not all required users in [alice,bob] have signed the transaction to write/delete key [sVnBPZovzX2wvtnOxxg1Sg] present in the database [ttid.kdcFXEExc8FvQTDDumKyUw]")
		require.Nil(t, submitResponse)
	})
}

func TestTokensManager_GetTokensByOwner(t *testing.T) {
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

	deployResponse, err := manager.DeployTokenType(deployRequest)
	assert.NoError(t, err)

	certBob, signerBob := testutils.LoadTestCrypto(t, env.cluster.GetUserCertDir(), "bob")
	err = manager.AddUser(&types.UserRecord{
		Identity:    "bob",
		Certificate: base64.StdEncoding.EncodeToString(certBob.Raw),
		Privilege:   nil,
	})
	assert.NoError(t, err)

	certCharlie, signerCharlie := testutils.LoadTestCrypto(t, env.cluster.GetUserCertDir(), "charlie")
	err = manager.AddUser(&types.UserRecord{
		Identity:    "charlie",
		Certificate: base64.StdEncoding.EncodeToString(certCharlie.Raw),
		Privilege:   nil,
	})
	assert.NoError(t, err)

	var tokenIDs []string
	for i := 1; i <= 5; i++ {
		mintRequest := &types.MintRequest{
			Owner:         "bob",
			AssetData:     fmt.Sprintf("bob's asset %d", i),
			AssetMetadata: "bob's asset metadata",
		}
		mintResponse, err := manager.PrepareMint(deployResponse.TypeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(mintResponse.TxEnvelope)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, signerBob, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       mintResponse.TokenId,
			TxEnvelope:    mintResponse.TxEnvelope,
			TxPayloadHash: mintResponse.TxPayloadHash,
			Signer:        "bob",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.NoError(t, err)
		tokenIDs = append(tokenIDs, submitResponse.TokenId)
	}

	for i := 1; i <= 6; i++ {
		mintRequest := &types.MintRequest{
			Owner:         "charlie",
			AssetData:     fmt.Sprintf("charlie's asset %d", i),
			AssetMetadata: "charlie's asset metadata",
		}
		mintResponse, err := manager.PrepareMint(deployResponse.TypeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(mintResponse.TxEnvelope)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, signerCharlie, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       mintResponse.TokenId,
			TxEnvelope:    mintResponse.TxEnvelope,
			TxPayloadHash: mintResponse.TxPayloadHash,
			Signer:        "charlie",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.NoError(t, err)
		tokenIDs = append(tokenIDs, submitResponse.TokenId)
	}

	t.Run("success", func(t *testing.T) {
		records, err := manager.GetTokensByOwner(deployResponse.TypeId, "bob")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 5)

		records, err = manager.GetTokensByOwner(deployResponse.TypeId, "charlie")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 6)
	})

	t.Run("success: manager restart", func(t *testing.T) {
		err = manager.Close()
		require.NoError(t, err)
		manager, err = NewManager(env.conf, env.lg)
		require.NoError(t, err)
		require.NotNil(t, manager)

		records, err := manager.GetTokensByOwner(deployResponse.TypeId, "bob")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 5)

		records, err = manager.GetTokensByOwner(deployResponse.TypeId, "charlie")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 6)
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
