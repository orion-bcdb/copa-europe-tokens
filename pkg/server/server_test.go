package server

import (
	"bytes"
	"encoding/base64"
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
	tokenscrypto "github.com/copa-europe-tokens/pkg/crypto"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/golang/protobuf/proto"
	sdkconfig "github.com/hyperledger-labs/orion-sdk-go/pkg/config"
	"github.com/hyperledger-labs/orion-server/pkg/crypto"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/hyperledger-labs/orion-server/pkg/server/testutils"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/hyperledger-labs/orion-server/test/setup"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestTokensServer_MainFlow(t *testing.T) {
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

	httpClient := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
	baseURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", httpPort))
	require.NoError(t, err)

	// GET /status
	// make sure the token server is connected to Orion cluster
	u := baseURL.ResolveReference(&url.URL{Path: constants.StatusEndpoint})
	resp, err := httpClient.Get(u.String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	status := &types.StatusResponse{}
	err = json.NewDecoder(resp.Body).Decode(status)
	resp.Body.Close()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(status.Status, fmt.Sprintf("connected: {Id: node-1, Address: 127.0.0.1, Port: %d", nPort)))

	// Deploy two token types, one annotation
	deployReq1 := &types.DeployRequest{
		Name:        "original content",
		Description: "represents copyright ownership of original content",
	}
	deployResp1 := deployTokenType(t, httpClient, baseURL, deployReq1)
	t.Logf("Deployed token-type: %+v", deployResp1)

	deployReq2 := &types.DeployRequest{
		Name:        "leasing rights",
		Description: "represents the right to watch the content for a limited time",
		Class:       constants.TokenClass_NFT,
	}
	deployResp2 := deployTokenType(t, httpClient, baseURL, deployReq2)
	t.Logf("Deployed token-type: %+v", deployResp2)

	deployReq3 := &types.DeployRequest{
		Name:        "production",
		Description: "represents the production supply chain",
		Class:       constants.TokenClass_ANNOTATIONS,
	}
	deployResp3 := deployTokenType(t, httpClient, baseURL, deployReq3)
	t.Logf("Deployed token-type: %+v", deployResp3)

	// Get the token types one by one
	for _, typeIdUrl := range []string{deployResp1.Url, deployResp2.Url, deployResp3.Url} {
		u = baseURL.ResolveReference(&url.URL{Path: typeIdUrl})
		resp, err = httpClient.Get(u.String())
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		deployResp := &types.DeployResponse{}
		err = json.NewDecoder(resp.Body).Decode(deployResp)
		require.NoError(t, err)
		t.Logf("token-type: %+v", deployResp)
		require.Equal(t, typeIdUrl, constants.TokensTypesSubTree+deployResp.TypeId)
	}

	// Get all token types
	u = baseURL.ResolveReference(&url.URL{Path: constants.TokensTypesEndpoint})
	resp, err = httpClient.Get(u.String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var tokenTypes []*types.DeployResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenTypes)
	require.NoError(t, err)
	require.Len(t, tokenTypes, 3)
	for _, expectedTT := range []*types.DeployResponse{deployResp1, deployResp2, deployResp3} {
		found := false
		for _, actualTT := range tokenTypes {
			if *expectedTT == *actualTT {
				found = true
				break
			}
		}
		require.True(t, found, "exp not found: %v", expectedTT)
	}

	// Add 2 users
	// The test environment prepares crypto material for: server, admin, alice, bob, and charlie; alice is the custodian.
	u = baseURL.ResolveReference(&url.URL{Path: constants.TokensUsersEndpoint})

	// Add "bob"
	certBob, signerBob := testutils.LoadTestCrypto(t, c.GetUserCertDir(), "bob")
	userRecordBob := &types.UserRecord{
		Identity:    "bob",
		Certificate: base64.StdEncoding.EncodeToString(certBob.Raw),
		Privilege:   nil, // empty means all token types, can own copyright and lease
	}
	requestBytes, err := json.Marshal(userRecordBob)
	require.NoError(t, err)
	reader := bytes.NewReader(requestBytes)
	require.NotNil(t, reader)
	resp, err = httpClient.Post(u.String(), "application/json", reader)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Add "charlie"
	certCharlie, signerCharlie := testutils.LoadTestCrypto(t, c.GetUserCertDir(), "charlie")
	userRecordCharlie := &types.UserRecord{
		Identity:    "charlie",
		Certificate: base64.StdEncoding.EncodeToString(certCharlie.Raw),
		Privilege:   []string{deployResp2.TypeId}, // can only own token 2, i.e. only lease
	}
	requestBytes, err = json.Marshal(userRecordCharlie)
	require.NoError(t, err)
	reader = bytes.NewReader(requestBytes)
	require.NotNil(t, reader)
	resp, err = httpClient.Post(u.String(), "application/json", reader)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Mint some content tokens
	_, bobKeyPath := c.GetUserCertKeyPath("bob")
	hashSignerBob, err := tokenscrypto.NewSigner("bob", bobKeyPath)
	require.NoError(t, err)
	mintRequest1 := &types.MintRequest{
		Owner:         "bob",
		AssetData:     "Title: game 1",
		AssetMetadata: "Ravens vs. Chargers",
	}
	submitResponse1 := mintToken(t, httpClient, baseURL, deployResp1.TypeId, mintRequest1, hashSignerBob)
	t.Logf("Minted: tokenId: %s, txId: %s", submitResponse1.TokenId, submitResponse1.TxId)

	mintRequest2 := &types.MintRequest{
		Owner:         "bob",
		AssetData:     "Title: game 2",
		AssetMetadata: "Patriots vs. Steelers",
	}
	submitResponse2 := mintToken(t, httpClient, baseURL, deployResp1.TypeId, mintRequest2, hashSignerBob)
	t.Logf("Minted: tokenId: %s, txId: %s", submitResponse2.TokenId, submitResponse2.TxId)

	mintRequest3 := &types.MintRequest{
		Owner:         "bob",
		AssetData:     "Title: game 3",
		AssetMetadata: "Jets vs. Browns",
	}
	submitResponse3 := mintToken(t, httpClient, baseURL, deployResp1.TypeId, mintRequest3, hashSignerBob)
	t.Logf("Minted: tokenId: %s, txId: %s", submitResponse3.TokenId, submitResponse3.TxId)

	// Mint some rights tokens
	_, charlieKeyPath := c.GetUserCertKeyPath("charlie")
	hashSignerCharlie, err := tokenscrypto.NewSigner("charlie", charlieKeyPath)
	require.NoError(t, err)
	mintRequest4 := &types.MintRequest{
		Owner:         "charlie",
		AssetData:     "Lease: No. 1: " + submitResponse1.TokenId,
		AssetMetadata: "Expire: 28/12/2023",
	}
	submitResponse4 := mintToken(t, httpClient, baseURL, deployResp2.TypeId, mintRequest4, hashSignerCharlie)
	t.Logf("Minted: tokenId: %s, txId: %s", submitResponse4.TokenId, submitResponse4.TxId)

	mintRequest5 := &types.MintRequest{
		Owner:         "charlie",
		AssetData:     "Lease: No. 2: " + submitResponse2.TokenId,
		AssetMetadata: "Expire: 28/12/2024",
	}
	submitResponse5 := mintToken(t, httpClient, baseURL, deployResp2.TypeId, mintRequest5, hashSignerCharlie)
	t.Logf("Minted: tokenId: %s, txId: %s", submitResponse5.TokenId, submitResponse5.TxId)

	// Get the tokens
	for _, tokenId := range []string{submitResponse1.TokenId, submitResponse2.TokenId, submitResponse3.TokenId, submitResponse4.TokenId, submitResponse5.TokenId} {
		u = baseURL.ResolveReference(&url.URL{Path: constants.TokensAssetsSubTree + tokenId})
		resp, err = httpClient.Get(u.String())
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		tokenRecord := &types.TokenRecord{}
		err = json.NewDecoder(resp.Body).Decode(tokenRecord)
		require.NoError(t, err)
		t.Logf("TokenId: %s", tokenId)
		t.Logf("Token: %+v", tokenRecord)
	}

	// Transfer the tokens
	for _, tokenId := range []string{submitResponse1.TokenId, submitResponse2.TokenId, submitResponse3.TokenId} {
		request := &types.TransferRequest{
			Owner:    "bob",
			NewOwner: "charlie",
		}
		resp := transferToken(t, httpClient, baseURL, tokenId, request, signerBob)
		require.Equal(t, tokenId, resp.TokenId)
	}

	// Transfer the tokens
	for _, tokenId := range []string{submitResponse4.TokenId, submitResponse5.TokenId} {
		request := &types.TransferRequest{
			Owner:    "charlie",
			NewOwner: "bob",
		}
		resp := transferToken(t, httpClient, baseURL, tokenId, request, signerCharlie)
		require.Equal(t, tokenId, resp.TokenId)
	}

	// Get the tokens
	for _, tokenId := range []string{submitResponse1.TokenId, submitResponse2.TokenId, submitResponse3.TokenId} {
		u = baseURL.ResolveReference(&url.URL{Path: constants.TokensAssetsSubTree + tokenId})
		resp, err = httpClient.Get(u.String())
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		tokenRecord := &types.TokenRecord{}
		err = json.NewDecoder(resp.Body).Decode(tokenRecord)
		require.NoError(t, err)
		require.Equal(t, "charlie", tokenRecord.Owner)
	}

	// Get the tokens
	for _, tokenId := range []string{submitResponse4.TokenId, submitResponse5.TokenId} {
		u = baseURL.ResolveReference(&url.URL{Path: constants.TokensAssetsSubTree + tokenId})
		resp, err = httpClient.Get(u.String())
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		tokenRecord := &types.TokenRecord{}
		err = json.NewDecoder(resp.Body).Decode(tokenRecord)
		require.NoError(t, err)
		require.Equal(t, "bob", tokenRecord.Owner)
	}

	// Get tokens by owner
	u = baseURL.ResolveReference(&url.URL{
		Path:     constants.TokensAssetsEndpoint,
		RawQuery: "owner=bob&type=" + deployResp2.TypeId,
	})
	resp, err = httpClient.Get(u.String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tokenRecords := []*types.TokenRecord{}
	err = json.NewDecoder(resp.Body).Decode(&tokenRecords)
	require.NoError(t, err)
	require.Len(t, tokenRecords, 2)
	for _, tr := range tokenRecords {
		require.Equal(t, "bob", tr.Owner)
	}

	// Get tokens by owner
	u = baseURL.ResolveReference(&url.URL{
		Path:     constants.TokensAssetsEndpoint,
		RawQuery: "owner=charlie&type=" + deployResp1.TypeId,
	})
	resp, err = httpClient.Get(u.String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tokenRecords = []*types.TokenRecord{}
	err = json.NewDecoder(resp.Body).Decode(&tokenRecords)
	require.NoError(t, err)
	require.Len(t, tokenRecords, 3)
	for _, tr := range tokenRecords {
		require.Equal(t, "charlie", tr.Owner)
	}

	// Get tokens by owner
	u = baseURL.ResolveReference(&url.URL{
		Path:     constants.TokensAssetsEndpoint,
		RawQuery: "owner=bob&type=" + deployResp1.TypeId,
	})
	resp, err = httpClient.Get(u.String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tokenRecords = []*types.TokenRecord{}
	err = json.NewDecoder(resp.Body).Decode(&tokenRecords)
	require.NoError(t, err)
	require.Len(t, tokenRecords, 0)

	wg.Add(1)
	err = tokensServer.Stop()
	require.NoError(t, err)
	wg.Wait()
}

func deployTokenType(t *testing.T, httpClient *http.Client, baseURL *url.URL, deployReq2 *types.DeployRequest) *types.DeployResponse {
	u := baseURL.ResolveReference(&url.URL{Path: constants.TokensTypesEndpoint})

	requestBytes, err := json.Marshal(deployReq2)
	require.NoError(t, err)
	reader := bytes.NewReader(requestBytes)
	require.NotNil(t, reader)
	resp, err := httpClient.Post(u.String(), "application/json", reader)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	deployResp2 := &types.DeployResponse{}
	err = json.NewDecoder(resp.Body).Decode(deployResp2)
	require.NoError(t, err)
	return deployResp2
}

func mintToken(t *testing.T, httpClient *http.Client, baseURL *url.URL, typeId string, mintRequest *types.MintRequest, hashSigner tokenscrypto.Signer) *types.SubmitResponse {
	// 1. Mint prepare
	u := baseURL.ResolveReference(&url.URL{Path: constants.TokensAssetsPrepareMint + typeId})
	requestBytes, err := json.Marshal(mintRequest)
	require.NoError(t, err)
	reader := bytes.NewReader(requestBytes)
	require.NotNil(t, reader)
	resp, err := httpClient.Post(u.String(), "application/json", reader)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	mintResponse := &types.MintResponse{}
	err = json.NewDecoder(resp.Body).Decode(mintResponse)
	require.NoError(t, err)

	// 2. Sign by owner, using a Hash signer service that does not know Orion types
	hashBytes, err := base64.StdEncoding.DecodeString(mintResponse.TxPayloadHash)
	require.NoError(t, err)
	sig, err := hashSigner.SignHash(hashBytes)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// 3. Submit
	u = baseURL.ResolveReference(&url.URL{Path: constants.TokensAssetsSubmit})
	submitRequest := &types.SubmitRequest{
		TokenId:       mintResponse.TokenId,
		TxEnvelope:    mintResponse.TxEnvelope,
		TxPayloadHash: mintResponse.TxPayloadHash,
		Signer:        mintResponse.Owner,
		Signature:     base64.StdEncoding.EncodeToString(sig),
	}
	requestBytes, err = json.Marshal(submitRequest)
	require.NoError(t, err)
	reader = bytes.NewReader(requestBytes)
	require.NotNil(t, reader)
	resp, err = httpClient.Post(u.String(), "application/json", reader)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	submitResponse := &types.SubmitResponse{}
	err = json.NewDecoder(resp.Body).Decode(submitResponse)
	require.NoError(t, err)
	return submitResponse
}

func transferToken(t *testing.T, httpClient *http.Client, baseURL *url.URL, tokenId string, transferRequest *types.TransferRequest, signer crypto.Signer) *types.SubmitResponse {
	// 1. Transfer prepare
	u := baseURL.ResolveReference(&url.URL{Path: constants.TokensAssetsPrepareTransfer + tokenId})
	requestBytes, err := json.Marshal(transferRequest)
	require.NoError(t, err)
	reader := bytes.NewReader(requestBytes)
	require.NotNil(t, reader)
	resp, err := httpClient.Post(u.String(), "application/json", reader)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	transferResponse := &types.TransferResponse{}
	err = json.NewDecoder(resp.Body).Decode(transferResponse)
	require.NoError(t, err)

	// 2. Sign by owner
	txEnvBytes, err := base64.StdEncoding.DecodeString(transferResponse.TxEnvelope)
	require.NoError(t, err)
	txEnv := &oriontypes.DataTxEnvelope{}
	err = proto.Unmarshal(txEnvBytes, txEnv)
	require.NoError(t, err)
	sig := testutils.SignatureFromTx(t, signer, txEnv.Payload)
	require.NotNil(t, sig)

	// 3. Submit
	u = baseURL.ResolveReference(&url.URL{Path: constants.TokensAssetsSubmit})
	submitRequest := &types.SubmitRequest{
		TokenId:       transferResponse.TokenId,
		TxEnvelope:    transferResponse.TxEnvelope,
		TxPayloadHash: transferResponse.TxPayloadHash,
		Signer:        transferResponse.Owner,
		Signature:     base64.StdEncoding.EncodeToString(sig),
	}
	requestBytes, err = json.Marshal(submitRequest)
	require.NoError(t, err)
	reader = bytes.NewReader(requestBytes)
	require.NotNil(t, reader)
	resp, err = httpClient.Post(u.String(), "application/json", reader)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	submitResponse := &types.SubmitResponse{}
	err = json.NewDecoder(resp.Body).Decode(submitResponse)
	require.NoError(t, err)
	return submitResponse
}
