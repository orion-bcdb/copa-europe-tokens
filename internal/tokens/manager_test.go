// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"reflect"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/copa-europe-tokens/internal/common"
	"github.com/copa-europe-tokens/pkg/config"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	sdkconfig "github.com/hyperledger-labs/orion-sdk-go/pkg/config"
	"github.com/hyperledger-labs/orion-server/pkg/crypto"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/hyperledger-labs/orion-server/pkg/server/testutils"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/hyperledger-labs/orion-server/test/setup"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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
		assert.EqualError(t, err, "Token type already exists")
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

	certBob, signerBob := testutils.LoadTestCrypto(t, env.cluster.GetUserCertDir(), "bob")
	err = manager.AddUser(&types.UserRecord{
		Identity:    "bob",
		Certificate: base64.StdEncoding.EncodeToString(certBob.Raw),
		Privilege:   nil,
	})
	assert.NoError(t, err)

	getResponse, err := manager.GetTokenType(deployResponseMy.TypeId)
	assert.NoError(t, err)
	assertEqualDeployResponse(t, deployResponseMy, getResponse)

	t.Run("success: owner is user bob", func(t *testing.T) {
		mintRequest := &types.MintRequest{
			Owner:         "bob",
			AssetData:     "bob's asset",
			AssetMetadata: "bob's asset meta",
		}
		mintResponse, err := manager.PrepareMint(deployResponseMy.TypeId, mintRequest)
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
		require.Equal(t, "", tokenRecord.Link)
		h, err := ComputeMD5Hash([]byte(tokenRecord.AssetData))
		require.NoError(t, err)
		require.Equal(t, base64.RawURLEncoding.EncodeToString(h), tokenRecord.AssetDataId)
	})

	t.Run("success: with link", func(t *testing.T) {
		mintRequest := &types.MintRequest{
			Owner:         "bob",
			AssetData:     "bob's asset with link",
			AssetMetadata: "bob's asset meta",
			Link:          "xxx.yyy",
		}
		mintResponse, err := manager.PrepareMint(deployResponseMy.TypeId, mintRequest)
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
		require.Equal(t, mintRequest.Link, tokenRecord.Link)
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
		require.Error(t, err)
		require.Contains(t, err.Error(), "Invalid user ID")
		require.IsType(t, &ErrInvalid{}, err)
		require.Nil(t, mintResponse)

		mintRequest = &types.MintRequest{
			Owner:         "admin",
			AssetData:     "my asset",
			AssetMetadata: "my asset meta",
		}
		mintResponse, err = manager.PrepareMint(getResponse.TypeId, mintRequest)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Invalid user ID")
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
		charlieSigner, err := crypto.NewSigner(&crypto.SignerOptions{
			Identity:    "charlie",
			KeyFilePath: keyPath,
		})
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, charlieSigner, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       mintResponse.TokenId,
			TxEnvelope:    mintResponse.TxEnvelope,
			TxPayloadHash: mintResponse.TxPayloadHash,
			Signer:        "charlie",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature verification failed")
		require.IsType(t, &ErrPermission{}, err, "Error: %v", err)
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
		assert.Contains(t, err.Error(), "the user [david] defined in the access control for the key [gm8Ndnh5x9firTQ2FLrIcQ] does not exist")
		assert.IsType(t, &ErrNotFound{}, err, "Error: %v", err)
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

func TestTokensManager_UpdateToken(t *testing.T) {
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

	t.Run("success: bob updates metadata", func(t *testing.T) {
		updateRequest := &types.UpdateRequest{
			Owner:         "bob",
			AssetMetadata: "A new version of the metadata",
		}
		updateResponse, err := manager.PrepareUpdate(tokenIDs[0], updateRequest)
		require.NoError(t, err)
		require.NotNil(t, updateResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(updateResponse.TxEnvelope)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, signerBob, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       updateResponse.TokenId,
			TxEnvelope:    updateResponse.TxEnvelope,
			TxPayloadHash: updateResponse.TxPayloadHash,
			Signer:        "bob",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.NoError(t, err)
		require.NotNil(t, submitResponse)

		// Get this token
		tokenRecord, err := manager.GetToken(tokenIDs[0])
		require.NoError(t, err)
		require.Equal(t, updateRequest.AssetMetadata, tokenRecord.AssetMetadata)
	})

	t.Run("error: token type does not exists", func(t *testing.T) {
		updateRequest := &types.UpdateRequest{
			Owner:         "bob",
			AssetMetadata: "A new version of the metadata",
		}

		updateResponse, err := manager.PrepareUpdate("aaaaabbbbbcccccdddddee.uuuuuvvvvvwwwwwxxxxxzz", updateRequest)
		require.EqualError(t, err, "token type not found: aaaaabbbbbcccccdddddee")
		require.IsType(t, &ErrNotFound{}, err)
		require.Nil(t, updateResponse)
	})

	t.Run("error: token does not exists", func(t *testing.T) {
		updateRequest := &types.UpdateRequest{
			Owner:         "bob",
			AssetMetadata: "A new version of the metadata",
		}
		updateResponse, err := manager.PrepareUpdate(deployResponse.TypeId+".uuuuuvvvvvwwwwwxxxxxzz", updateRequest)
		require.EqualError(t, err, "token not found: "+deployResponse.TypeId+".uuuuuvvvvvwwwwwxxxxxzz")
		require.IsType(t, &ErrNotFound{}, err)
		require.Nil(t, updateResponse)
	})

	t.Run("error: requester not the owner", func(t *testing.T) {
		updateRequest := &types.UpdateRequest{
			Owner:         "charlie",
			AssetMetadata: "A new version of the metadata",
		}
		updateResponse, err := manager.PrepareUpdate(tokenIDs[1], updateRequest)
		require.EqualError(t, err, "not owner: charlie")
		require.IsType(t, &ErrPermission{}, err)
		require.Nil(t, updateResponse)
	})

	t.Run("error: wrong signature", func(t *testing.T) {
		updateRequest := &types.UpdateRequest{
			Owner:         "bob",
			AssetMetadata: "A new version of the metadata",
		}
		updateResponse, err := manager.PrepareUpdate(tokenIDs[1], updateRequest)
		require.NoError(t, err)
		require.NotNil(t, updateResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(updateResponse.TxEnvelope)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, signerCharlie, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       updateResponse.TokenId,
			TxEnvelope:    updateResponse.TxEnvelope,
			TxPayloadHash: updateResponse.TxPayloadHash,
			Signer:        "bob",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not valid, flag: INVALID_NO_PERMISSION, reason: not all required users in [alice,bob] have signed the transaction to write/delete key")
		require.IsType(t, &ErrPermission{}, err)
		require.Nil(t, submitResponse)
	})
}

func TestTokensManager_GetTokensByOwnerLink(t *testing.T) {
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
			Link:          fmt.Sprintf("link-%d", i%2),
			Reference:     fmt.Sprintf("ref-%d", i%2),
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
			Link:          "link-0",
			Reference:     "ref-0",
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

	t.Run("success: by owner", func(t *testing.T) {
		records, err := manager.GetTokensByFilter(deployResponse.TypeId, "bob", "", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 5)

		records, err = manager.GetTokensByFilter(deployResponse.TypeId, "charlie", "", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 6)
	})

	t.Run("success: by link", func(t *testing.T) {
		records, err := manager.GetTokensByFilter(deployResponse.TypeId, "", "link-0", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 8)

		records, err = manager.GetTokensByFilter(deployResponse.TypeId, "", "link-1", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 3)
	})

	t.Run("success: by ref", func(t *testing.T) {
		records, err := manager.GetTokensByFilter(deployResponse.TypeId, "", "", "ref-0")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 8)

		records, err = manager.GetTokensByFilter(deployResponse.TypeId, "", "", "ref-1")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 3)
	})

	t.Run("success: by link & owner", func(t *testing.T) {
		records, err := manager.GetTokensByFilter(deployResponse.TypeId, "charlie", "link-0", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 6)

		records, err = manager.GetTokensByFilter(deployResponse.TypeId, "charlie", "link-1", "")
		require.NoError(t, err)
		require.Len(t, records, 0)
	})

	t.Run("success: by ref & owner", func(t *testing.T) {
		records, err := manager.GetTokensByFilter(deployResponse.TypeId, "charlie", "", "ref-0")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 6)

		records, err = manager.GetTokensByFilter(deployResponse.TypeId, "charlie", "", "ref-1")
		require.NoError(t, err)
		require.Len(t, records, 0)
	})

	t.Run("success: manager restart", func(t *testing.T) {
		err = manager.Close()
		require.NoError(t, err)
		manager, err = NewManager(env.conf, env.lg)
		require.NoError(t, err)
		require.NotNil(t, manager)

		records, err := manager.GetTokensByFilter(deployResponse.TypeId, "bob", "", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 5)

		records, err = manager.GetTokensByFilter(deployResponse.TypeId, "charlie", "", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 6)
	})

	t.Run("invalid", func(t *testing.T) {
		_, err = manager.GetTokensByFilter(deployResponse.TypeId, "", "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "query must contain at least one qualifier")
		require.IsType(t, &ErrInvalid{}, err)
	})

}

func TestTokensManager_RegisterAnnotation(t *testing.T) {
	env := newTestEnv(t)

	manager, err := NewManager(env.conf, env.lg)
	require.NoError(t, err)
	require.NotNil(t, manager)

	stat, err := manager.GetStatus()
	require.NoError(t, err)
	require.Contains(t, stat, "connected:")

	deployRequest := &types.DeployRequest{
		Name:        "my-Annot",
		Description: "my Annotations for testing",
		Class:       constants.TokenClass_ANNOTATIONS,
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

		regRequest := &types.AnnotationRegisterRequest{
			Owner:              "bob",
			Link:               "xyx.abc",
			AnnotationData:     "bob's annotation",
			AnnotationMetadata: "bob's metadata",
		}
		regResponse, err := manager.PrepareRegister(getResponse.TypeId, regRequest)
		require.NoError(t, err)
		require.NotNil(t, regResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(regResponse.TxEnvelope)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, signerBob, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       regResponse.AnnotationId,
			TxEnvelope:    regResponse.TxEnvelope,
			TxPayloadHash: regResponse.TxPayloadHash,
			Signer:        "bob",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.NoError(t, err)
		require.NotNil(t, submitResponse)
		require.Equal(t, submitRequest.TokenId, submitResponse.TokenId)

		// Get this annotation
		annotRecord, err := manager.GetAnnotation(regResponse.AnnotationId)
		require.NoError(t, err)
		require.Equal(t, regRequest.Owner, annotRecord.Owner)
		require.Equal(t, regRequest.AnnotationData, annotRecord.AnnotationData)
		require.Equal(t, regRequest.AnnotationMetadata, annotRecord.AnnotationMetadata)
		h, err := ComputeMD5Hash([]byte(annotRecord.AnnotationData))
		require.NoError(t, err)
		require.Equal(t, base64.RawURLEncoding.EncodeToString(h), annotRecord.AnnotationDataId)
	})

	t.Run("error: owner is custodian or admin", func(t *testing.T) {
		getResponse, err := manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualDeployResponse(t, deployResponseMy, getResponse)

		regRequest := &types.AnnotationRegisterRequest{
			Owner:              "alice",
			Link:               "xyx.abc",
			AnnotationData:     "my annotation on xyz.abc",
			AnnotationMetadata: "my metadata",
		}
		regResponse, err := manager.PrepareRegister(getResponse.TypeId, regRequest)

		require.EqualError(t, err, "owner cannot be the custodian: alice")
		require.IsType(t, &ErrInvalid{}, err)
		require.Nil(t, regResponse)

		regRequest = &types.AnnotationRegisterRequest{
			Owner:              "admin",
			Link:               "xyx.abc",
			AnnotationData:     "my annotation on xyz.abc",
			AnnotationMetadata: "my metadata",
		}
		regResponse, err = manager.PrepareRegister(getResponse.TypeId, regRequest)
		require.EqualError(t, err, "owner cannot be the admin: admin")
		require.IsType(t, &ErrInvalid{}, err)
		require.Nil(t, regResponse)
	})

	t.Run("error: annotation already exists", func(t *testing.T) {
		getResponse, err := manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualDeployResponse(t, deployResponseMy, getResponse)

		regRequest := &types.AnnotationRegisterRequest{
			Owner:              "charlie",
			Link:               "xyz.abc",
			AnnotationData:     "bob's annotation",
			AnnotationMetadata: "bob's asset meta",
		}
		regResponse, err := manager.PrepareRegister(getResponse.TypeId, regRequest)
		require.EqualError(t, err, "token already exists")
		require.IsType(t, &ErrExist{}, err)
		require.Nil(t, regResponse)
	})

	t.Run("error: not a user", func(t *testing.T) {
		getResponse, err := manager.GetTokenType(deployResponseMy.TypeId)
		assert.NoError(t, err)
		assertEqualDeployResponse(t, deployResponseMy, getResponse)

		regRequest := &types.AnnotationRegisterRequest{
			Owner:              "charlie",
			Link:               "xyz.abc",
			AnnotationData:     "charlie's asset",
			AnnotationMetadata: "charlie's asset meta",
		}
		regResponse, err := manager.PrepareRegister(getResponse.TypeId, regRequest)
		require.NoError(t, err)
		require.NotNil(t, regResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(regResponse.TxEnvelope)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		_, keyPath := env.cluster.GetUserCertKeyPath("charlie")
		charlieSigner, err := crypto.NewSigner(&crypto.SignerOptions{
			Identity:    "charlie",
			KeyFilePath: keyPath,
		})
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, charlieSigner, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       regResponse.AnnotationId,
			TxEnvelope:    regResponse.TxEnvelope,
			TxPayloadHash: regResponse.TxPayloadHash,
			Signer:        "charlie",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature verification failed")
		require.IsType(t, &ErrPermission{}, err, "Error: %v", err)
		require.Nil(t, submitResponse)
	})

	t.Run("error: get parameters", func(t *testing.T) {
		annotRecord, err := manager.GetAnnotation("")
		require.EqualError(t, err, "invalid tokenId")
		require.IsType(t, &ErrInvalid{}, err)
		require.Nil(t, annotRecord)

		annotRecord, err = manager.GetAnnotation("xxx")
		require.EqualError(t, err, "invalid tokenId")
		require.IsType(t, &ErrInvalid{}, err)
		require.Nil(t, annotRecord)

		annotRecord, err = manager.GetAnnotation("xxx.yyy.zzz")
		require.EqualError(t, err, "invalid tokenId")
		require.IsType(t, &ErrInvalid{}, err)
		require.Nil(t, annotRecord)

		annotRecord, err = manager.GetAnnotation("token-not-deployed.xxx")
		require.EqualError(t, err, "token type not found: token-not-deployed")
		require.IsType(t, &ErrNotFound{}, err)
		require.Nil(t, annotRecord)
	})
}

func TestTokensManager_GetAnnotationsBy(t *testing.T) {
	env := newTestEnv(t)

	manager, err := NewManager(env.conf, env.lg)
	require.NoError(t, err)
	require.NotNil(t, manager)

	stat, err := manager.GetStatus()
	require.NoError(t, err)
	require.Contains(t, stat, "connected:")

	deployRequest := &types.DeployRequest{
		Name:        "my-Annot",
		Description: "my Annotations for testing",
		Class:       constants.TokenClass_ANNOTATIONS,
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
	for i := 1; i <= 6; i++ {
		regRequest := &types.AnnotationRegisterRequest{
			Owner:              "bob",
			Link:               fmt.Sprintf("xyz.abc%d", i%2),
			Reference:          fmt.Sprintf("ref-%d", i%2),
			AnnotationData:     fmt.Sprintf("bob's annot %d", i),
			AnnotationMetadata: "bob's metadata",
		}
		regResponse, err := manager.PrepareRegister(deployResponse.TypeId, regRequest)
		require.NoError(t, err)
		require.NotNil(t, regResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(regResponse.TxEnvelope)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, signerBob, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       regResponse.AnnotationId,
			TxEnvelope:    regResponse.TxEnvelope,
			TxPayloadHash: regResponse.TxPayloadHash,
			Signer:        "bob",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.NoError(t, err)
		tokenIDs = append(tokenIDs, submitResponse.TokenId)
	}

	for i := 1; i <= 8; i++ {
		regRequest := &types.AnnotationRegisterRequest{
			Owner:              "charlie",
			Link:               fmt.Sprintf("xyz.abc%d", i%2),
			Reference:          fmt.Sprintf("ref-%d", i%2),
			AnnotationData:     fmt.Sprintf("charlies's annot %d", i),
			AnnotationMetadata: "charlie's metadata",
		}
		regResponse, err := manager.PrepareRegister(deployResponse.TypeId, regRequest)
		require.NoError(t, err)
		require.NotNil(t, regResponse)

		txEnvBytes, err := base64.StdEncoding.DecodeString(regResponse.TxEnvelope)
		require.NoError(t, err)
		txEnv := &oriontypes.DataTxEnvelope{}
		err = proto.Unmarshal(txEnvBytes, txEnv)
		require.NoError(t, err)

		sig := testutils.SignatureFromTx(t, signerCharlie, txEnv.Payload)
		require.NotNil(t, sig)

		submitRequest := &types.SubmitRequest{
			TokenId:       regResponse.AnnotationId,
			TxEnvelope:    regResponse.TxEnvelope,
			TxPayloadHash: regResponse.TxPayloadHash,
			Signer:        "charlie",
			Signature:     base64.StdEncoding.EncodeToString(sig),
		}

		submitResponse, err := manager.SubmitTx(submitRequest)
		require.NoError(t, err)
		tokenIDs = append(tokenIDs, submitResponse.TokenId)
	}

	t.Run("success", func(t *testing.T) {
		records, err := manager.GetAnnotationsByFilter(deployResponse.TypeId, "bob", "", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 6)

		records, err = manager.GetAnnotationsByFilter(deployResponse.TypeId, "charlie", "", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 8)

		records, err = manager.GetAnnotationsByFilter(deployResponse.TypeId, "", "xyz.abc0", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 7)

		records, err = manager.GetAnnotationsByFilter(deployResponse.TypeId, "", "", "ref-0")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 7)

		records, err = manager.GetAnnotationsByFilter(deployResponse.TypeId, "charlie", "", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 8)

		records, err = manager.GetAnnotationsByFilter(deployResponse.TypeId, "bob", "xyz.abc0", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 3)

		records, err = manager.GetAnnotationsByFilter(deployResponse.TypeId, "bob", "", "ref-0")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 3)

		records, err = manager.GetAnnotationsByFilter(deployResponse.TypeId, "charlie", "xyz.abc1", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 4)

		records, err = manager.GetAnnotationsByFilter(deployResponse.TypeId, "charlie", "", "ref-1")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 4)
	})

	t.Run("success: manager restart", func(t *testing.T) {
		err = manager.Close()
		require.NoError(t, err)
		manager, err = NewManager(env.conf, env.lg)
		require.NoError(t, err)
		require.NotNil(t, manager)

		records, err := manager.GetAnnotationsByFilter(deployResponse.TypeId, "bob", "xyz.abc0", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 3)

		records, err = manager.GetAnnotationsByFilter(deployResponse.TypeId, "charlie", "xyz.abc0", "")
		require.NoError(t, err)
		require.NotNil(t, records)
		require.Len(t, records, 4)
	})

	t.Run("invalid: ", func(t *testing.T) {
		err = manager.Close()
		require.NoError(t, err)
		manager, err = NewManager(env.conf, env.lg)
		require.NoError(t, err)
		require.NotNil(t, manager)

		records, err := manager.GetAnnotationsByFilter("xxx", "charlie", "xyz.abc0", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not exist")
		require.Nil(t, records)

		records, err = manager.GetAnnotationsByFilter(deployResponse.TypeId, "", "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "query must contain at least one qualifier")
		require.IsType(t, &ErrInvalid{}, err)
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

	// Update user with non-existing type
	fakeType, err := NameToID("bogus-type")
	require.NoError(t, err)
	err = manager.UpdateUser(&types.UserRecord{
		Identity:    "bob",
		Certificate: base64.StdEncoding.EncodeToString(certCharlie.Raw),
		Privilege:   []string{fakeType},
	})
	assert.Error(t, err)
	assert.IsType(t, &ErrInvalid{}, err, "Error: %v", err)

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

// ============================================================
// Test helpers
// ============================================================

func assertEqualDeployResponse(t *testing.T, expected *types.DeployResponse, actual *types.TokenDescription) {
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

// A new test environment.
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

// ============================================================
// Fungible test helpers
// ============================================================

func assertTokenHttpErr(t *testing.T, expectedStatus int, actualResponse interface{}, actualErr error) bool {
	if !assert.Nil(t, actualResponse, "Response %+v, Error: %v", actualResponse, actualErr) {
		return false
	}

	if !assert.Error(t, actualErr) {
		return false
	}

	tknErr, ok := actualErr.(*common.TokenHttpErr)
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

	return assert.Regexp(t, regexp.MustCompile(fmt.Sprintf("(?i)%s", expectedMessage)), actualErr)
}

type extendedTestEnv struct {
	testEnv
	manager     *Manager
	users       []string
	userRecords map[string]*types.UserRecord
	certs       map[string]*x509.Certificate
	signers     map[string]crypto.Signer
}

func newExtendedTestEnv(t *testing.T) *extendedTestEnv {
	e := &extendedTestEnv{
		testEnv:     *newTestEnv(t),
		userRecords: map[string]*types.UserRecord{},
		certs:       map[string]*x509.Certificate{},
		signers:     map[string]crypto.Signer{},
	}

	manager, err := NewManager(e.conf, e.lg)
	require.NoError(t, err)
	require.NotNil(t, manager)
	e.manager = manager

	stat, err := e.manager.GetStatus()
	require.NoError(t, err)
	require.Contains(t, stat, "connected:")

	keyPair, err := e.cluster.GetX509KeyPair()
	require.NoError(t, err)
	require.NoError(t, e.cluster.CreateUserCerts("dave", keyPair))

	for _, user := range []string{"alice", "admin"} {
		e.certs[user], e.signers[user] = testutils.LoadTestCrypto(t, e.cluster.GetUserCertDir(), user)
	}

	e.addUser(t, "bob")
	e.addUser(t, "charlie")
	e.addUser(t, "dave")

	return e
}

func (e *extendedTestEnv) addUser(t *testing.T, user string) {
	cert, signer := testutils.LoadTestCrypto(t, e.cluster.GetUserCertDir(), user)
	record := &types.UserRecord{
		Identity:    user,
		Certificate: base64.StdEncoding.EncodeToString(cert.Raw),
		Privilege:   nil,
	}
	err := e.manager.AddUser(record)
	require.NoError(t, err)
	e.userRecords[user] = record
	e.certs[user] = cert
	e.signers[user] = signer
	e.users = append(e.users, user)
}

func (e *extendedTestEnv) updateUsers(t *testing.T) {
	for _, record := range e.userRecords {
		err := e.manager.UpdateUser(record)
		require.NoError(t, err)
	}
}

func (e *extendedTestEnv) sign(t *testing.T, user string, response SignatureRequester) *SubmitContext {
	submitCtx, err := SignTransactionResponse(e.signers[user], response)
	require.NoError(t, err, "failed to sign response for user %s", user)
	return submitCtx
}

func (e *extendedTestEnv) badSign(user string, response SignatureRequester) *SubmitContext {
	submitCtx := response.PrepareSubmit()
	submitCtx.Signer = user
	submitCtx.Signature = base64.StdEncoding.EncodeToString([]byte("bogus-sig"))
	return submitCtx
}

func (e *extendedTestEnv) nftSignAndSubmit(t *testing.T, user string, response SignatureRequester) (*types.SubmitResponse, error) {
	return e.manager.SubmitTx(e.sign(t, user, response).ToNFTRequest())
}

func (e *extendedTestEnv) nftRequireSignAndSubmit(t *testing.T, user string, response SignatureRequester) *types.SubmitResponse {
	submitResponse, err := e.nftSignAndSubmit(t, user, response)
	require.NoError(t, err, "failed to submit")
	require.NotNil(t, submitResponse, "no submit response")
	return submitResponse
}

func (e *extendedTestEnv) fungibleSignAndSubmit(t *testing.T, user string, response SignatureRequester) (*types.FungibleSubmitResponse, error) {
	return e.manager.FungibleSubmitTx(e.sign(t, user, response).ToFungibleRequest())
}

func (e *extendedTestEnv) fungibleRequireSignAndSubmit(t *testing.T, user string, response SignatureRequester) *types.FungibleSubmitResponse {
	submitResponse, err := e.fungibleSignAndSubmit(t, user, response)
	require.NoError(t, err)
	require.NotNil(t, submitResponse)
	return submitResponse
}

func (e *extendedTestEnv) fungibleWrongSignAndSubmit(user string, response SignatureRequester) (*types.FungibleSubmitResponse, error) {
	return e.manager.FungibleSubmitTx(e.badSign(user, response).ToFungibleRequest())
}

func (e *extendedTestEnv) offerSignAndSubmit(t *testing.T, user string, response SignatureRequester) (*types.RightsOfferSubmitResponse, error) {
	return e.manager.RightsOfferSubmitTx(e.sign(t, user, response).ToRightsRequest())
}

func (e *extendedTestEnv) offerRequireSignAndSubmit(t *testing.T, user string, response SignatureRequester) *types.RightsOfferSubmitResponse {
	submitResponse, err := e.offerSignAndSubmit(t, user, response)
	require.NoError(t, err)
	require.NotNil(t, submitResponse)
	return submitResponse
}

func (e *extendedTestEnv) offerWrongSignAndSubmit(user string, response SignatureRequester) (*types.RightsOfferSubmitResponse, error) {
	return e.manager.RightsOfferSubmitTx(e.badSign(user, response).ToRightsRequest())
}

// ============================================================
// Fungible
// ============================================================

func getFungibleDeployRequest(owner string, index int) *types.FungibleDeployRequest {
	return &types.FungibleDeployRequest{
		Name:         fmt.Sprintf("%v's Fungible #%v", owner, index),
		Description:  fmt.Sprintf("%v's  Test Fungible #%v", owner, index),
		ReserveOwner: owner,
	}
}

func getFungibleDeployRequests(owner string, num int) []*types.FungibleDeployRequest {
	var requests []*types.FungibleDeployRequest
	for i := 0; i < num; i++ {
		requests = append(requests, getFungibleDeployRequest(owner, i))
	}
	return requests
}

func assertRecordEqual(t *testing.T, expected types.FungibleAccountRecord, actual types.FungibleAccountRecord) bool {
	if expected.Account == "" {
		expected.Account = mainAccount
	}

	if expected.Comment == "__ignore__" || (expected.Owner == reserveAccountUser && expected.Account == mainAccount) {
		expected.Comment = ""
		actual.Comment = ""
	}

	return assert.Equal(t, expected, actual)
}

func TestTokensManager_FungibleDeploy(t *testing.T) {
	env := newExtendedTestEnv(t)

	const messageCount = 3

	t.Run("success: deploy fungible and describe", func(t *testing.T) {
		for user := range env.userRecords {
			requests := getFungibleDeployRequests(user, messageCount)

			for _, request := range requests {
				deployResponse, err := env.manager.FungibleDeploy(request)
				require.NoError(t, err)
				require.NotNil(t, deployResponse)

				expectedIdMy, _ := NameToID(request.Name)
				expectedDescribe := types.FungibleDescribeResponse{
					TypeId:       expectedIdMy,
					Name:         request.Name,
					Description:  request.Description,
					Supply:       0,
					ReserveOwner: request.ReserveOwner,
					Url:          common.URLForType(constants.FungibleTypeRoot, expectedIdMy),
				}
				assert.Equal(t, (*types.FungibleDeployResponse)(&expectedDescribe), deployResponse)

				describeResponse, err := env.manager.FungibleDescribe(expectedIdMy)
				require.NoError(t, err)
				require.NotNil(t, deployResponse)
				assert.Equal(t, &expectedDescribe, describeResponse)
			}
		}

		allTypes, err := env.manager.GetTokenTypes()
		assert.NoError(t, err)
		assert.Equal(t, messageCount*len(env.userRecords), len(allTypes))
	})

	t.Run("error: deploy again", func(t *testing.T) {
		deployResponseBad, err := env.manager.FungibleDeploy(getFungibleDeployRequest("bob", 0))
		assertTokenHttpErrMessage(t, http.StatusConflict, "token type already exists", deployResponseBad, err)
	})

	t.Run("error: empty name", func(t *testing.T) {
		deployRequestEmpty := &types.FungibleDeployRequest{
			Name:         "",
			Description:  "",
			ReserveOwner: "bob",
		}
		deployResponseBad, err := env.manager.FungibleDeploy(deployRequestEmpty)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "name is empty", deployResponseBad, err)
	})

	t.Run("error: empty owner", func(t *testing.T) {
		deployRequestEmpty := &types.FungibleDeployRequest{
			Name:        "new-name",
			Description: "some description",
		}
		deployResponseBad, err := env.manager.FungibleDeploy(deployRequestEmpty)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "Invalid user ID: empty", deployResponseBad, err)
	})

	t.Run("error: invalid owner", func(t *testing.T) {
		deployRequestEmpty := &types.FungibleDeployRequest{
			Name:         "new-name",
			Description:  "some description",
			ReserveOwner: "nonuser",
		}
		deployResponseBad, err := env.manager.FungibleDeploy(deployRequestEmpty)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "user not found", deployResponseBad, err)
	})

	t.Run("error: admin/custodian owner", func(t *testing.T) {
		for _, user := range []string{"admin", "alice"} {
			deployRequestEmpty := &types.FungibleDeployRequest{
				Name:         "new-name",
				Description:  "some description",
				ReserveOwner: user,
			}
			deployResponseBad, err := env.manager.FungibleDeploy(deployRequestEmpty)
			assertTokenHttpErrMessage(t, http.StatusBadRequest, "cannot participate in token activities", deployResponseBad, err)
		}
	})
}

func TestTokensManager_FungibleMintToken(t *testing.T) {
	env := newExtendedTestEnv(t)

	response, err := env.manager.FungibleDeploy(getFungibleDeployRequest("bob", 0))
	require.NoError(t, err)
	typeId := response.TypeId

	t.Run("error: wrong signature (before mint)", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 5}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse, err := env.fungibleWrongSignAndSubmit("bob", (*FungibleMintResponse)(mintResponse))
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: wrong signer (before mint)", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 5}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse, err := env.fungibleSignAndSubmit(t, "charlie", (*FungibleMintResponse)(mintResponse))
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("success: signed by owner", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 5}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse := env.fungibleRequireSignAndSubmit(t, "bob", (*FungibleMintResponse)(mintResponse))
		require.Equal(t, typeId, submitResponse.TypeId)

		desc, err := env.manager.FungibleDescribe(typeId)
		assert.NoError(t, err)
		assert.Equal(t, uint64(5), desc.Supply)
	})

	t.Run("success: second mint", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 5}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse := env.fungibleRequireSignAndSubmit(t, "bob", (*FungibleMintResponse)(mintResponse))
		require.Equal(t, typeId, submitResponse.TypeId)

		desc, err := env.manager.FungibleDescribe(typeId)
		require.NoError(t, err)
		require.Equal(t, uint64(10), desc.Supply)
	})

	t.Run("error: wrong signature (after mint)", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 5}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse, err := env.fungibleWrongSignAndSubmit("bob", (*FungibleMintResponse)(mintResponse))
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: wrong signer (after mint)", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 5}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse, err := env.fungibleSignAndSubmit(t, "charlie", (*FungibleMintResponse)(mintResponse))
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: zero supply", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 0}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "must be a positive", mintResponse, err)
	})

	t.Run("error: type does not exists", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 1}
		tokenTypeIDBase64, _ := NameToID("FakeToken")
		response, err := env.manager.FungiblePrepareMint(tokenTypeIDBase64, mintRequest)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "db '.*' doesn't exist", response, err)
	})

	t.Run("error: invalid type", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 1}
		response, err := env.manager.FungiblePrepareMint("a", mintRequest)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "invalid type id", response, err)
	})
}

func TestTokensManager_FungibleTransferToken(t *testing.T) {
	env := newExtendedTestEnv(t)

	deployResponse, err := env.manager.FungibleDeploy(getFungibleDeployRequest("bob", 0))
	require.NoError(t, err)
	typeId := deployResponse.TypeId

	mintRequest := &types.FungibleMintRequest{Supply: 10}
	mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
	require.NoError(t, err)
	require.NotNil(t, mintResponse)

	env.fungibleRequireSignAndSubmit(t, "bob", (*FungibleMintResponse)(mintResponse))

	t.Run("success: reserve to bob", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    reserveAccountUser,
			Account:  mainAccount,
			NewOwner: "bob",
			Quantity: 2,
			Comment:  "tip",
		}
		transferResponse, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)
		assert.Equal(t, typeId, transferResponse.TypeId)
		assert.Equal(t, reserveAccountUser, transferResponse.Owner)
		assert.Equal(t, mainAccount, transferResponse.Account)
		assert.Equal(t, "bob", transferResponse.NewOwner)
		assert.NotEmpty(t, transferResponse.NewAccount)

		env.fungibleRequireSignAndSubmit(t, "bob", (*FungibleTransferResponse)(transferResponse))

		desc, err := env.manager.FungibleDescribe(typeId)
		assert.NoError(t, err)
		assert.Equal(t, uint64(10), desc.Supply)

		accList, err := env.manager.FungibleAccounts(typeId, reserveAccountUser, mainAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Owner:   reserveAccountUser,
			Account: mainAccount,
			Balance: 8,
		}, accList[0])

		accList, err = env.manager.FungibleAccounts(typeId, "bob", transferResponse.NewAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: transferResponse.NewAccount,
			Owner:   "bob",
			Balance: 2,
			Comment: transferRequest.Comment,
		}, accList[0])
	})

	t.Run("success: reserve to charlie", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    reserveAccountUser,
			Account:  mainAccount,
			NewOwner: "charlie",
			Quantity: 2,
			Comment:  "tip",
		}
		transferResponse, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)
		assert.Equal(t, typeId, transferResponse.TypeId)
		assert.Equal(t, reserveAccountUser, transferResponse.Owner)
		assert.Equal(t, mainAccount, transferResponse.Account)
		assert.Equal(t, "charlie", transferResponse.NewOwner)
		assert.NotEmpty(t, transferResponse.NewAccount)

		env.fungibleRequireSignAndSubmit(t, "bob", (*FungibleTransferResponse)(transferResponse))

		desc, err := env.manager.FungibleDescribe(typeId)
		assert.NoError(t, err)
		assert.Equal(t, uint64(10), desc.Supply)

		accList, err := env.manager.FungibleAccounts(typeId, reserveAccountUser, mainAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: mainAccount,
			Owner:   reserveAccountUser,
			Balance: 6,
		}, accList[0])

		accList, err = env.manager.FungibleAccounts(typeId, "charlie", "")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: transferResponse.NewAccount,
			Owner:   "charlie",
			Balance: 2,
			Comment: transferRequest.Comment,
		}, accList[0])
	})

	var charlieTxAccount string
	t.Run("success: reserve to charlie (implicit account)", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    reserveAccountUser,
			NewOwner: "charlie",
			Quantity: 2,
			Comment:  "tip",
		}
		transferResponse, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)
		assert.Equal(t, typeId, transferResponse.TypeId)
		assert.Equal(t, reserveAccountUser, transferResponse.Owner)
		assert.Equal(t, mainAccount, transferResponse.Account)
		assert.Equal(t, "charlie", transferResponse.NewOwner)
		assert.NotEmpty(t, transferResponse.NewAccount)
		charlieTxAccount = transferResponse.NewAccount

		env.fungibleRequireSignAndSubmit(t, "bob", (*FungibleTransferResponse)(transferResponse))

		desc, err := env.manager.FungibleDescribe(typeId)
		assert.NoError(t, err)
		assert.Equal(t, uint64(10), desc.Supply)

		accList, err := env.manager.FungibleAccounts(typeId, reserveAccountUser, mainAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: mainAccount,
			Owner:   reserveAccountUser,
			Balance: 4,
		}, accList[0])

		accList, err = env.manager.FungibleAccounts(typeId, "charlie", charlieTxAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: charlieTxAccount,
			Owner:   "charlie",
			Balance: 2,
			Comment: transferRequest.Comment,
		}, accList[0])
	})

	t.Run("success: charlie to reserve", func(t *testing.T) {
		// Make sure charlie has permissions

		env.updateUsers(t)
		require.NotNil(t, charlieTxAccount)

		transferRequest := &types.FungibleTransferRequest{
			Owner:    "charlie",
			Account:  charlieTxAccount,
			NewOwner: reserveAccountUser,
			Quantity: 1,
			Comment:  "return",
		}
		transferResponse, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)
		assert.Equal(t, typeId, transferResponse.TypeId)
		assert.Equal(t, "charlie", transferResponse.Owner)
		assert.Equal(t, charlieTxAccount, transferResponse.Account)
		assert.Equal(t, reserveAccountUser, transferResponse.NewOwner)
		assert.NotEmpty(t, transferResponse.NewAccount)

		env.fungibleRequireSignAndSubmit(t, "charlie", (*FungibleTransferResponse)(transferResponse))

		desc, err := env.manager.FungibleDescribe(typeId)
		assert.NoError(t, err)
		assert.Equal(t, uint64(10), desc.Supply)

		accList, err := env.manager.FungibleAccounts(typeId, reserveAccountUser, transferResponse.NewAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: transferResponse.NewAccount,
			Owner:   reserveAccountUser,
			Comment: transferRequest.Comment,
			Balance: 1,
		}, accList[0])

		accList, err = env.manager.FungibleAccounts(typeId, "charlie", charlieTxAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: charlieTxAccount,
			Owner:   "charlie",
			Balance: 1,
			Comment: "__ignore__",
		}, accList[0])
	})

	t.Run("error: insufficient funds", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    reserveAccountUser,
			NewOwner: "charlie",
			Quantity: 10,
		}
		response, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "insufficient funds", response, err)
	})

	t.Run("error: owner==new-owner", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    "charlie",
			NewOwner: "charlie",
			Quantity: 10,
		}
		response, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "must be different", response, err)
	})

	for _, user := range []string{"admin", "alice"} {
		t.Run(fmt.Sprintf("error: transfer to %v", user), func(t *testing.T) {
			transferRequest := &types.FungibleTransferRequest{
				Owner:    reserveAccountUser,
				NewOwner: user,
				Quantity: 1,
			}
			response, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
			assertTokenHttpErrMessage(t, http.StatusBadRequest, "cannot participate in token activities", response, err)
		})
	}

	t.Run("error: account does not exists", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    "bob",
			Account:  "fake",
			NewOwner: "charlie",
			Quantity: 1,
		}
		response, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "account does not exists", response, err)
	})

	t.Run("error: owner does not exists", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    "nonuser",
			NewOwner: "bob",
			Quantity: 1,
		}
		response, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "account does not exists", response, err)
	})

	t.Run("error: new owner does not exists", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    reserveAccountUser,
			NewOwner: "nonuser",
			Quantity: 1,
		}
		transferResponse, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)

		response, err := env.fungibleSignAndSubmit(t, "bob", (*FungibleTransferResponse)(transferResponse))
		assertTokenHttpErrMessage(t, http.StatusNotFound, "the user .* does not exist", response, err)
	})

	t.Run("error: wrong signature", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    reserveAccountUser,
			NewOwner: "charlie",
			Quantity: 1,
		}
		response, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		require.NoError(t, err)
		require.NotNil(t, response)

		submitResponse, err := env.fungibleWrongSignAndSubmit("bob", (*FungibleTransferResponse)(response))
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: wrong signer", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    reserveAccountUser,
			NewOwner: "charlie",
			Quantity: 1,
		}
		response, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		require.NoError(t, err)
		require.NotNil(t, response)

		submitResponse, err := env.fungibleSignAndSubmit(t, "dave", (*FungibleTransferResponse)(response))
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: type does not exists", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    reserveAccountUser,
			NewOwner: "charlie",
			Quantity: 1,
		}

		tokenTypeIDBase64, _ := NameToID("FakeToken")
		response, err := env.manager.FungiblePrepareTransfer(tokenTypeIDBase64, transferRequest)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "db '.*' doesn't exist", response, err)
	})

	t.Run("error: invalid type", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    reserveAccountUser,
			NewOwner: "charlie",
			Quantity: 1,
		}
		response, err := env.manager.FungiblePrepareTransfer("a", transferRequest)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "invalid type id", response, err)
	})
}

func TestTokensManager_FungibleConsolidateToken(t *testing.T) {
	env := newExtendedTestEnv(t)

	deployResponse, err := env.manager.FungibleDeploy(getFungibleDeployRequest("bob", 0))
	assert.NoError(t, err)
	typeId := deployResponse.TypeId

	env.updateUsers(t)

	mintResponse, err := env.manager.FungiblePrepareMint(typeId, &types.FungibleMintRequest{Supply: 100})
	require.NoError(t, err)
	require.NotNil(t, mintResponse)

	env.fungibleRequireSignAndSubmit(t, "bob", (*FungibleMintResponse)(mintResponse))

	nUsers := len(env.users)
	accounts := map[string][]string{}
	for _, user := range env.users {
		// All users get 5 tokens from the reserve
		for i := 0; i < 5; i++ {
			transferResponse, err := env.manager.FungiblePrepareTransfer(typeId, &types.FungibleTransferRequest{
				Owner:    reserveAccountUser,
				NewOwner: user,
				Quantity: 1,
			})
			require.NoError(t, err)
			require.NotNil(t, transferResponse)

			env.fungibleRequireSignAndSubmit(t, "bob", (*FungibleTransferResponse)(transferResponse))

			accounts[user] = append(accounts[user], transferResponse.NewAccount)
		}

		// Then each use transfer one token back to the reserve account
		transferResponse, err := env.manager.FungiblePrepareTransfer(typeId, &types.FungibleTransferRequest{
			Owner:    user,
			Account:  accounts[user][0],
			NewOwner: reserveAccountUser,
			Quantity: 1,
		})

		require.NoError(t, err)
		require.NotNil(t, transferResponse)

		env.fungibleRequireSignAndSubmit(t, user, (*FungibleTransferResponse)(transferResponse))
		accounts[reserveAccountUser] = append(accounts[reserveAccountUser], transferResponse.NewAccount)
	}

	t.Run("success: all reserve (implicit)", func(t *testing.T) {
		accList, err := env.manager.FungibleAccounts(typeId, reserveAccountUser, "")
		assert.NoError(t, err)
		assert.Equal(t, nUsers+1, len(accList))

		accList, err = env.manager.FungibleAccounts(typeId, reserveAccountUser, mainAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		reserveAccount := accList[0]

		request := &types.FungibleConsolidateRequest{Owner: reserveAccountUser}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, typeId, response.TypeId)
		assert.Equal(t, reserveAccountUser, response.Owner)

		env.fungibleRequireSignAndSubmit(t, "bob", (*FungibleConsolidateResponse)(response))

		accList, err = env.manager.FungibleAccounts(typeId, reserveAccountUser, "")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: mainAccount,
			Owner:   reserveAccountUser,
			Balance: reserveAccount.Balance + uint64(nUsers),
		}, accList[0])
	})

	t.Run("success: all bob (implicit)", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{Owner: "bob"}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, typeId, response.TypeId)
		assert.Equal(t, "bob", response.Owner)

		env.fungibleRequireSignAndSubmit(t, "bob", (*FungibleConsolidateResponse)(response))

		accList, err := env.manager.FungibleAccounts(typeId, "bob", mainAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: mainAccount,
			Owner:   "bob",
			Balance: 4,
			Comment: mainAccount,
		}, accList[0])
	})

	t.Run("success: all charlie (explicit)", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{
			Owner:    "charlie",
			Accounts: accounts["charlie"],
		}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, typeId, response.TypeId)
		assert.Equal(t, "charlie", response.Owner)

		env.fungibleRequireSignAndSubmit(t, "charlie", (*FungibleConsolidateResponse)(response))

		accList, err := env.manager.FungibleAccounts(typeId, "charlie", mainAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: mainAccount,
			Owner:   "charlie",
			Balance: 4,
			Comment: mainAccount,
		}, accList[0])

		accList, err = env.manager.FungibleAccounts(typeId, "charlie", "")
		require.NoError(t, err)
		assert.Equal(t, 1, len(accList))
	})

	t.Run("success: 3 dave", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{
			Owner:    "dave",
			Accounts: accounts["dave"][:3],
		}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, typeId, response.TypeId)
		assert.Equal(t, "dave", response.Owner)

		env.fungibleRequireSignAndSubmit(t, "dave", (*FungibleConsolidateResponse)(response))

		accList, err := env.manager.FungibleAccounts(typeId, "dave", mainAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: mainAccount,
			Owner:   "dave",
			Balance: 2,
			Comment: mainAccount,
		}, accList[0])

		accList, err = env.manager.FungibleAccounts(typeId, "dave", "")
		require.NoError(t, err)
		assert.Equal(t, 3, len(accList))
		expectedAccounts := append(accounts["dave"][3:], "main")
		actualAccount := make([]string, len(accList))
		for i, acc := range accList {
			actualAccount[i] = acc.Account
		}
		assert.ElementsMatch(t, expectedAccounts, actualAccount)
	})

	t.Run("success: 1 additional dave account", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{
			Owner:    "dave",
			Accounts: accounts["dave"][3:4],
		}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, typeId, response.TypeId)
		assert.Equal(t, "dave", response.Owner)

		env.fungibleRequireSignAndSubmit(t, "dave", (*FungibleConsolidateResponse)(response))

		accList, err := env.manager.FungibleAccounts(typeId, "dave", mainAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: mainAccount,
			Owner:   "dave",
			Balance: 3,
			Comment: mainAccount,
		}, accList[0])

		accList, err = env.manager.FungibleAccounts(typeId, "dave", "")
		require.NoError(t, err)
		assert.Equal(t, 2, len(accList))
		expectedAccounts := append(accounts["dave"][4:], "main")
		actualAccount := make([]string, len(accList))
		for i, acc := range accList {
			actualAccount[i] = acc.Account
		}
		assert.ElementsMatch(t, expectedAccounts, actualAccount)
	})

	t.Run("error: no accounts to consolidate", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{
			Owner: "bob",
		}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "did not found accounts", response, err)
	})

	t.Run("error: empty account list", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{
			Owner:    "dave",
			Accounts: []string{},
		}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "must have at least one account", response, err)
	})

	t.Run("error: include 'main' in list", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{
			Owner:    "dave",
			Accounts: []string{"main"},
		}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "account cannot be consolidated", response, err)
	})

	t.Run("error: account does not exist", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{
			Owner:    "dave",
			Accounts: []string{"fake-account"},
		}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "account does not exists", response, err)
	})

	t.Run("error: owner does not exists", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{Owner: "non-user"}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "did not found accounts", response, err)
	})

	t.Run("error: wrong signature", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{Owner: "dave"}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		require.NoError(t, err)
		require.NotNil(t, response)

		submitResponse, err := env.fungibleWrongSignAndSubmit("dave", (*FungibleConsolidateResponse)(response))
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: wrong signer", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{Owner: "dave"}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		require.NoError(t, err)
		require.NotNil(t, response)

		submitResponse, err := env.fungibleSignAndSubmit(t, "charlie", (*FungibleConsolidateResponse)(response))
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: type does not exists", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{Owner: "dave"}
		tokenTypeIDBase64, _ := NameToID("FakeToken")
		response, err := env.manager.FungiblePrepareConsolidate(tokenTypeIDBase64, request)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "'.*' does not exist", response, err)

		request.Accounts = []string{"fake-account"}
		response, err = env.manager.FungiblePrepareConsolidate(tokenTypeIDBase64, request)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "db '.*' doesn't exist", response, err)
	})

	t.Run("error: invalid type", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{Owner: "dave"}
		response, err := env.manager.FungiblePrepareConsolidate("a", request)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "invalid type id", response, err)
	})
}

// ============================================================
// Rights Offer
// ============================================================

type offerTestEnv struct {
	extendedTestEnv
	typeIds       map[string]string
	assetIds      map[string][]string
	annotationIds map[string][]string
	assetOffers   map[string]map[string]types.RightsOfferRecord
}

func (e *offerTestEnv) offerMintRequest(name, owner, asset string, price uint64) *types.RightsOfferMintRequest {
	return &types.RightsOfferMintRequest{
		Name:     name,
		Owner:    owner,
		Asset:    asset,
		Rights:   e.typeIds["rights"],
		Template: fmt.Sprintf("Template of %s", asset),
		Price:    price,
		Currency: e.typeIds["fung"],
	}
}

func (e *offerTestEnv) offer(name, owner, asset string, price uint64) (*RightsOfferResponse, error) {
	offerResp, err := e.manager.RightsOfferMint(
		e.typeIds["offers"],
		e.offerMintRequest(name, owner, asset, price),
	)
	if offerResp != nil {
		return (*RightsOfferResponse)(offerResp), err
	} else {
		return nil, err
	}
}

func (e *offerTestEnv) requireOffer(t *testing.T, name, owner, asset string, price uint64) *RightsOfferResponse {
	offerResp, err := e.offer(name, owner, asset, price)
	require.NoError(t, err, "failed to mint offer for: %s", name)
	require.NotNil(t, offerResp, "failed to mint offer for: %s", name)
	return offerResp
}

func fakeToken(t *testing.T, name string) string {
	tokenTypeIDBase64, err := NameToID(name)
	require.NoError(t, err)
	return tokenTypeIDBase64
}

func (e *offerTestEnv) buy(offer, buyer, meta string) (*RightsOfferBuyResponse, error) {
	buyResp, err := e.manager.RightsOfferBuy(
		offer,
		&types.RightsOfferBuyRequest{
			BuyerId:  buyer,
			Metadata: meta,
		},
	)
	if buyResp != nil {
		return (*RightsOfferBuyResponse)(buyResp), err
	} else {
		return nil, err
	}
}

func (e *offerTestEnv) requireBuy(t *testing.T, offer, buyer, meta string) *RightsOfferBuyResponse {
	offerResp, err := e.buy(offer, buyer, meta)
	require.NoError(t, err, "failed to buy offer: %s", offer)
	require.NotNil(t, offerResp, "failed to buy offer: %s", offer)
	return offerResp
}

func (e *offerTestEnv) update(offer string, enable bool) (*RightsOfferResponse, error) {
	resp, err := e.manager.RightsOfferUpdate(
		offer,
		&types.RightsOfferUpdateRequest{Enable: enable},
	)
	if resp != nil {
		return (*RightsOfferResponse)(resp), err
	} else {
		return nil, err
	}
}

func (e *offerTestEnv) requireUpdate(t *testing.T, offer string, enable bool) *RightsOfferResponse {
	resp, err := e.update(offer, enable)
	require.NoError(t, err, "failed to update offer: %s", offer)
	require.NotNil(t, resp, "failed to update offer: %s", offer)
	return resp
}

func (e *offerTestEnv) mainBalance(t *testing.T, user string) uint64 {
	accounts, err := e.manager.FungibleAccounts(e.typeIds["fung"], user, "")
	require.NoError(t, err, "failed getting %s balance", user)
	for _, acc := range accounts {
		if acc.Comment == mainAccount {
			return acc.Balance
		}
	}
	return 0
}

func (e *offerTestEnv) balance(t *testing.T, user string) uint64 {
	accounts, err := e.manager.FungibleAccounts(e.typeIds["fung"], user, "")
	require.NoError(t, err, "failed getting %s balance", user)
	balance := uint64(0)
	for _, acc := range accounts {
		balance += acc.Balance
	}
	return balance
}

func (e *offerTestEnv) getOffers(owner string) (string, string) {
	var testOfferId string
	var freeOfferId string
	for _, offers := range e.assetOffers {
		for offerId, record := range offers {
			if record.Owner != owner {
				continue
			}
			if record.Price > 0 {
				testOfferId = offerId
			} else {
				freeOfferId = offerId
			}
			if testOfferId != "" && freeOfferId != "" {
				return testOfferId, freeOfferId
			}
		}
	}
	return testOfferId, freeOfferId
}

func newOfferTestEnv(t *testing.T) *offerTestEnv {
	env := &offerTestEnv{
		extendedTestEnv: *newExtendedTestEnv(t),
		typeIds:         map[string]string{},
		assetIds:        map[string][]string{},
		annotationIds:   map[string][]string{},
		assetOffers:     map[string]map[string]types.RightsOfferRecord{},
	}
	deploys := []*types.DeployRequest{{
		Name:  "assets",
		Class: constants.TokenClass_NFT,
	}, {
		Name:  "rights",
		Class: constants.TokenClass_NFT,
	}, {
		Name:  "offers",
		Class: constants.TokenClass_RIGHTS_OFFER,
	}, {
		Name:  "annot",
		Class: constants.TokenClass_ANNOTATIONS,
	}}
	for _, d := range deploys {
		r, err := env.manager.DeployTokenType(d)
		require.NoError(t, err, "failed to deploy: %s", d.Name)
		env.typeIds[d.Name] = r.TypeId
	}

	fungDeployResp, err := env.manager.FungibleDeploy(&types.FungibleDeployRequest{
		Name:         "fung",
		ReserveOwner: "bob",
	})
	require.NoError(t, err, "failed to deploy: fungible")
	env.typeIds["fung"] = fungDeployResp.TypeId

	env.updateUsers(t)

	fungMintResp, err := env.manager.FungiblePrepareMint(env.typeIds["fung"], &types.FungibleMintRequest{Supply: 1_000_000})
	require.NoError(t, err, "failed to mint: fungible")
	env.fungibleRequireSignAndSubmit(t, "bob", (*FungibleMintResponse)(fungMintResp))

	for _, u := range env.users {
		transResp, err := env.manager.FungiblePrepareTransfer(env.typeIds["fung"], &types.FungibleTransferRequest{
			Owner:    reserveAccountUser,
			NewOwner: u,
			Quantity: 10_000,
		})
		require.NoError(t, err, "failed to transfer fungible to: %s", u)
		env.fungibleRequireSignAndSubmit(t, "bob", (*FungibleTransferResponse)(transResp))

		consResp, err := env.manager.FungiblePrepareConsolidate(env.typeIds["fung"], &types.FungibleConsolidateRequest{
			Owner: u,
		})
		require.NoError(t, err, "failed to consolidate fungible for: %s", u)
		env.fungibleRequireSignAndSubmit(t, u, (*FungibleConsolidateResponse)(consResp))
	}

	// Each user (3) have 3 assets, each with 3 offers
	for dIdx, d := range []string{"movie1", "movie2", "movie3"} {
		for uIdx, u := range env.users {
			assetName := fmt.Sprintf("%s by %s", d, u)
			assetResp, err := env.manager.PrepareMint(env.typeIds["assets"], &types.MintRequest{
				Owner:     u,
				AssetData: assetName,
			})
			require.NoError(t, err, "failed to mint asset: %s", assetName)
			env.nftRequireSignAndSubmit(t, u, (*MintResponse)(assetResp))
			env.assetIds[u] = append(env.assetIds[u], assetResp.TokenId)

			annotName := fmt.Sprintf("Annotation for: %s", assetName)
			annotResp, err := env.manager.PrepareRegister(env.typeIds["annot"], &types.AnnotationRegisterRequest{
				Owner:          u,
				Link:           assetResp.TokenId,
				AnnotationData: annotName,
			})
			require.NoError(t, err, "failed to register annotation: %s", annotName)
			env.nftRequireSignAndSubmit(t, u, (*AnnotationRegisterResponse)(annotResp))
			env.annotationIds[u] = append(env.annotationIds[u], annotResp.AnnotationId)

			tokenRecords := map[string]types.RightsOfferRecord{}
			for i := 0; i < 3; i++ {
				price := uint64(i + dIdx*10 + uIdx*100)
				name := fmt.Sprintf("Offer %d for asset %s", i, assetName)
				offerResp := env.requireOffer(t, name, u, assetResp.TokenId, price)
				env.offerRequireSignAndSubmit(t, u, offerResp)
				tokenRecords[offerResp.OfferId] = types.RightsOfferRecord{
					OfferId:  offerResp.OfferId,
					Name:     name,
					Owner:    u,
					Asset:    assetResp.TokenId,
					Rights:   env.typeIds["rights"],
					Template: fmt.Sprintf("Template of %s", assetResp.TokenId),
					Price:    price,
					Currency: env.typeIds["fung"],
					Enabled:  true,
				}
			}
			env.assetOffers[assetResp.TokenId] = tokenRecords
		}
	}

	return env
}

func TestTokensManager_OfferGet(t *testing.T) {
	env := newOfferTestEnv(t)

	t.Run("success: get everything", func(t *testing.T) {
		for user, assets := range env.assetIds {
			for _, assetId := range assets {
				for offerId, expectedRecord := range env.assetOffers[assetId] {
					record, err := env.manager.RightsOfferGet(offerId)
					require.NoError(t, err)
					require.NotNil(t, record)
					assert.Equal(t, offerId, record.OfferId)
					assert.Equal(t, user, record.Owner)
					assert.Equal(t, assetId, record.Asset)
					assert.Equal(t, env.typeIds["rights"], record.Rights)
					assert.Equal(t, expectedRecord.Price, record.Price)
					assert.Equal(t, env.typeIds["fung"], record.Currency)
					assert.Equal(t, true, record.Enabled)
				}
			}
		}
	})

	t.Run("error: get invalid offer", func(t *testing.T) {
		record, err := env.manager.RightsOfferGet("fake-asset")
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "invalid tokenId", record, err)
	})

	t.Run("error: get offer type does not exists", func(t *testing.T) {
		record, err := env.manager.RightsOfferGet(fakeToken(t, "FakeToken") + ".fake")
		assertTokenHttpErrMessage(t, http.StatusNotFound, "token type not found", record, err)
	})

	t.Run("error: get offer does not exists", func(t *testing.T) {
		record, err := env.manager.RightsOfferGet(env.typeIds["offers"] + ".fake")
		assertTokenHttpErrMessage(t, http.StatusNotFound, `offer \[.*\] was not found`, record, err)
	})

	t.Run("error: get offer wrong type", func(t *testing.T) {
		record, err := env.manager.RightsOfferGet(env.annotationIds["bob"][0])
		assertTokenHttpErrMessage(t, http.StatusBadRequest, `must be rights_offer`, record, err)
	})
}

func TestTokensManager_OfferMint(t *testing.T) {
	env := newOfferTestEnv(t)

	t.Run("error: wrong signature", func(t *testing.T) {
		offerResp := env.requireOffer(t, "wrongSig", "bob", env.assetIds["bob"][0], 100)
		submitResponse, err := env.offerWrongSignAndSubmit("bob", offerResp)
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: wrong signer", func(t *testing.T) {
		offerResp := env.requireOffer(t, "wrongSig", "bob", env.assetIds["bob"][0], 100)
		submitResponse, err := env.offerSignAndSubmit(t, "charlie", offerResp)
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: invalid asset", func(t *testing.T) {
		offerResp, err := env.offer("invalidAsset", "bob", "fake-asset", 100)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "invalid tokenId", offerResp, err)
	})

	t.Run("error: asset type does not exists", func(t *testing.T) {
		tokenType, _ := NameToID("FakeToken")
		offerResp, err := env.offer("badAssetType", "bob", tokenType+".fake", 100)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "db '.*' doesn't exist", offerResp, err)
	})

	t.Run("error: asset does not exists", func(t *testing.T) {
		offerResp, err := env.offer("badAsset", "bob", env.typeIds["assets"]+".fake", 100)
		assertTokenHttpErrMessage(t, http.StatusNotFound, `key \[.*\] was not found`, offerResp, err)
	})

	t.Run("error: asset wrong type", func(t *testing.T) {
		offerResp, err := env.offer("badAsset", "bob", env.annotationIds["bob"][0], 100)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, `must be nft`, offerResp, err)
	})

	t.Run("error: rights type does not exist", func(t *testing.T) {
		offerResp, err := env.manager.RightsOfferMint(env.typeIds["offers"], &types.RightsOfferMintRequest{
			Name:     "invalidRights",
			Owner:    "bob",
			Asset:    env.assetIds["bob"][0],
			Rights:   "fake-rights",
			Template: "Template",
			Price:    100,
			Currency: env.typeIds["fung"],
		})
		assertTokenHttpErrMessage(t, http.StatusNotFound, "token type not found", offerResp, err)
	})

	t.Run("error: rights wrong type", func(t *testing.T) {
		offerResp, err := env.manager.RightsOfferMint(env.typeIds["offers"], &types.RightsOfferMintRequest{
			Name:     "invalidRights",
			Owner:    "bob",
			Asset:    env.assetIds["bob"][0],
			Rights:   env.typeIds["annot"],
			Template: "Template",
			Price:    100,
			Currency: env.typeIds["fung"],
		})
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "token type must be nft", offerResp, err)
	})

	t.Run("error: invalid currency type", func(t *testing.T) {
		offerResp, err := env.manager.RightsOfferMint(env.typeIds["offers"], &types.RightsOfferMintRequest{
			Name:     "invalidRights",
			Owner:    "bob",
			Asset:    env.assetIds["bob"][0],
			Rights:   env.typeIds["rights"],
			Template: "Template",
			Price:    100,
			Currency: "fake-type",
		})
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "invalid type id", offerResp, err)
	})

	t.Run("error: currency type does not exist", func(t *testing.T) {
		offerResp, err := env.manager.RightsOfferMint(env.typeIds["offers"], &types.RightsOfferMintRequest{
			Name:     "invalidRights",
			Owner:    "bob",
			Asset:    env.assetIds["bob"][0],
			Rights:   env.typeIds["rights"],
			Template: "Template",
			Price:    100,
			Currency: fakeToken(t, "fake-type"),
		})
		assertTokenHttpErrMessage(t, http.StatusNotFound, "token type not found", offerResp, err)
	})

	t.Run("error: currency wrong type", func(t *testing.T) {
		offerResp, err := env.manager.RightsOfferMint(env.typeIds["offers"], &types.RightsOfferMintRequest{
			Name:     "invalidRights",
			Owner:    "bob",
			Asset:    env.assetIds["bob"][0],
			Rights:   env.typeIds["rights"],
			Template: "Template",
			Price:    100,
			Currency: env.typeIds["annot"],
		})
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "token type must be fungible", offerResp, err)
	})

	t.Run("error: wrong owner", func(t *testing.T) {
		offerResp, err := env.offer("wrongOwner", "charlie", env.assetIds["bob"][0], 100)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "owner must own the asset", offerResp, err)
	})
}

func TestTokensManager_OfferBuy(t *testing.T) {
	env := newOfferTestEnv(t)

	meta := "meta"
	t.Run("success: everyone is buying everything (3 times)", func(t *testing.T) {
		for _, u := range env.users {
			balance := env.balance(t, u)
			for assetOwner, assets := range env.assetIds {
				for _, assetId := range assets {
					for offerId, offerRecord := range env.assetOffers[assetId] {
						price := offerRecord.Price
						for i := 0; i < 3; i++ {
							b := env.requireBuy(t, offerId, u, meta)
							require.NotNil(t, env.offerRequireSignAndSubmit(t, u, b))
							if u == assetOwner {
								price = 0
							}
							newBalance := env.balance(t, u)
							assert.Equal(t, int(balance-price), int(newBalance))
							balance = newBalance

							record, err := env.manager.GetToken(b.TokenId)
							require.NoError(t, err)
							require.NotNil(t, record)
							assert.Equal(t, u, record.Owner)
							assert.Equal(t, meta, record.AssetMetadata)
							assert.Equal(t, b.TokenId[len(offerRecord.Rights)+1:], record.AssetDataId)
							assert.Equal(t, assetId, record.Link)
							assert.Equal(t, offerId, record.Reference)

							rightsRecord := &types.RightsRecord{}
							require.NoError(t, json.Unmarshal([]byte(record.AssetData), rightsRecord))
							require.NotEmpty(t, rightsRecord.RightsId)
							// This is a random number, there is nothing to validate
							rightsRecord.RightsId = ""
							assert.Equal(t, &types.RightsRecord{
								OfferId:  offerId,
								RightsId: "",
								Asset:    assetId,
								Template: offerRecord.Template,
							}, rightsRecord)
						}
					}
				}
			}
		}
	})

	testOfferId, freeOfferId := env.getOffers("bob")

	t.Run("error: wrong signature", func(t *testing.T) {
		buyResp := env.requireBuy(t, testOfferId, "bob", meta)
		submitResponse, err := env.offerWrongSignAndSubmit("bob", buyResp)
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: wrong signer", func(t *testing.T) {
		buyResp := env.requireBuy(t, testOfferId, "bob", meta)
		submitResponse, err := env.offerSignAndSubmit(t, "charlie", buyResp)
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: invalid offer", func(t *testing.T) {
		resp, err := env.buy("fake-offer", "bob", meta)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "invalid tokenId", resp, err)
	})

	t.Run("error: offer type does not exists", func(t *testing.T) {
		tokenType, _ := NameToID("FakeToken")
		offerResp, err := env.buy(tokenType+".fake", "bob", meta)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "token type not found", offerResp, err)
	})

	t.Run("error: offer does not exists", func(t *testing.T) {
		offerResp, err := env.buy(env.typeIds["offers"]+".fake", "bob", meta)
		assertTokenHttpErrMessage(t, http.StatusNotFound, `offer \[.*\] was not found`, offerResp, err)
	})

	t.Run("error: offer wrong type", func(t *testing.T) {
		offerResp, err := env.buy(env.annotationIds["bob"][0], "bob", meta)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, `must be rights_offer`, offerResp, err)
	})

	t.Run("error: invalid user", func(t *testing.T) {
		offerResp, err := env.buy(testOfferId, "fake", meta)
		assertTokenHttpErrMessage(t, http.StatusNotFound, `does not exist`, offerResp, err)
	})

	transResp, err := env.manager.FungiblePrepareTransfer(env.typeIds["fung"], &types.FungibleTransferRequest{
		Owner:    "dave",
		NewOwner: "charlie",
		Quantity: env.mainBalance(t, "dave"),
	})
	require.NoError(t, err, "failed to transfer fungible from dave to charlie")
	env.fungibleRequireSignAndSubmit(t, "dave", (*FungibleTransferResponse)(transResp))

	t.Run("error: no funds", func(t *testing.T) {
		offerResp, err := env.buy(testOfferId, "dave", meta)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "insufficient funds", offerResp, err)
	})

	t.Run("success: no funds", func(t *testing.T) {
		env.offerRequireSignAndSubmit(t, "dave", env.requireBuy(t, freeOfferId, "dave", meta))
	})
}

func TestTokensManager_OfferUpdate(t *testing.T) {
	env := newOfferTestEnv(t)

	meta := "meta"
	t.Run("success: everyone is trying to buy", func(t *testing.T) {
		for assetOwner, assets := range env.assetIds {
			for _, assetId := range assets {
				for offerId := range env.assetOffers[assetId] {
					require.NotNil(t, env.offerRequireSignAndSubmit(t, assetOwner, env.requireUpdate(t, offerId, false)))
					for _, u := range env.users {
						buyResp, err := env.buy(offerId, u, meta)
						assertTokenHttpErrMessage(t, http.StatusBadRequest, "disabled", buyResp, err)
					}

					require.NotNil(t, env.offerRequireSignAndSubmit(t, assetOwner, env.requireUpdate(t, offerId, true)))
					for _, u := range env.users {
						buyResp := env.requireBuy(t, offerId, u, meta)
						require.NotNil(t, env.offerRequireSignAndSubmit(t, u, buyResp))
					}
				}
			}
		}
	})

	testOfferId, _ := env.getOffers("bob")

	t.Run("error: wrong signature", func(t *testing.T) {
		submitResponse, err := env.offerWrongSignAndSubmit("bob", env.requireUpdate(t, testOfferId, false))
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: wrong signer", func(t *testing.T) {
		submitResponse, err := env.offerSignAndSubmit(t, "charlie", env.requireUpdate(t, testOfferId, false))
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: invalid offer", func(t *testing.T) {
		resp, err := env.update("fake-offer", false)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "invalid tokenId", resp, err)
	})

	t.Run("error: offer type does not exists", func(t *testing.T) {
		tokenType, _ := NameToID("FakeToken")
		resp, err := env.update(tokenType+".fake", false)
		assertTokenHttpErrMessage(t, http.StatusNotFound, "token type not found", resp, err)
	})

	t.Run("error: offer does not exists", func(t *testing.T) {
		resp, err := env.update(env.typeIds["offers"]+".fake", false)
		assertTokenHttpErrMessage(t, http.StatusNotFound, `offer \[.*\] was not found`, resp, err)
	})

	t.Run("error: offer wrong type", func(t *testing.T) {
		resp, err := env.update(env.annotationIds["bob"][0], false)
		assertTokenHttpErrMessage(t, http.StatusBadRequest, `must be rights_offer`, resp, err)
	})
}

func sortOffers(offers []types.RightsOfferRecord) {
	sort.Slice(offers, func(i, j int) bool {
		return offers[i].OfferId < offers[j].OfferId
	})
}

func TestTokensManager_OfferQuery(t *testing.T) {
	env := newOfferTestEnv(t)

	t.Run("success: query by owner", func(t *testing.T) {
		for assetOwner, assets := range env.assetIds {
			var offers []types.RightsOfferRecord
			for _, assetId := range assets {
				for _, offerRecord := range env.assetOffers[assetId] {
					offers = append(offers, offerRecord)
				}
			}
			sortOffers(offers)

			records, err := env.manager.RightsOfferQuery(env.typeIds["offers"], assetOwner, "")
			require.NoError(t, err)
			require.Len(t, records, len(offers))

			sortOffers(records)
			require.EqualValues(t, offers, records)
		}
	})

	t.Run("success: query by asset", func(t *testing.T) {
		for _, assets := range env.assetIds {
			for _, assetId := range assets {
				var offers []types.RightsOfferRecord
				for _, offerRecord := range env.assetOffers[assetId] {
					offers = append(offers, offerRecord)
				}
				sortOffers(offers)

				records, err := env.manager.RightsOfferQuery(env.typeIds["offers"], "", assetId)
				require.NoError(t, err)
				require.Len(t, records, len(offers))

				sortOffers(records)
				require.EqualValues(t, offers, records)
			}
		}
	})

	t.Run("success: query by owner and asset", func(t *testing.T) {
		for assetOwner, assets := range env.assetIds {
			for _, assetId := range assets {
				var offers []types.RightsOfferRecord
				for _, offerRecord := range env.assetOffers[assetId] {
					offers = append(offers, offerRecord)
				}
				sortOffers(offers)

				records, err := env.manager.RightsOfferQuery(env.typeIds["offers"], assetOwner, assetId)
				require.NoError(t, err)
				require.Len(t, records, len(offers))

				sortOffers(records)
				require.EqualValues(t, offers, records)
			}
		}
	})

	t.Run("error: no qualifiers", func(t *testing.T) {
		resp, err := env.manager.RightsOfferQuery(env.typeIds["offers"], "", "")
		assertTokenHttpErrMessage(t, http.StatusBadRequest, "must contain at least one qualifier", resp, err)
	})

	t.Run("error: offer type does not exists", func(t *testing.T) {
		tokenType, _ := NameToID("FakeToken")
		resp, err := env.manager.RightsOfferQuery(tokenType, "", "")
		assertTokenHttpErrMessage(t, http.StatusNotFound, "token type not found", resp, err)
	})

	t.Run("error: offer wrong type", func(t *testing.T) {
		resp, err := env.manager.RightsOfferQuery(env.typeIds["annot"], "", "")
		assertTokenHttpErrMessage(t, http.StatusBadRequest, `must be rights_offer`, resp, err)
	})
}
