package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
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
	sdkconfig "github.com/hyperledger-labs/orion-sdk-go/pkg/config"
	"github.com/hyperledger-labs/orion-server/pkg/crypto"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/hyperledger-labs/orion-server/pkg/server/testutils"
	"github.com/hyperledger-labs/orion-server/test/setup"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type serverTestEnv struct {
	httpClient *http.Client
	baseURL    *url.URL
}

func (e *serverTestEnv) resolveUrl(ref *url.URL) string {
	return e.baseURL.ResolveReference(ref).String()
}

func (e *serverTestEnv) resolvePath(path string) string {
	return e.baseURL.ResolveReference(&url.URL{Path: path}).String()
}

func (e *serverTestEnv) marshal(t *testing.T, body interface{}) io.Reader {
	requestBytes, err := json.Marshal(&body)
	require.NoError(t, err)
	reader := bytes.NewReader(requestBytes)
	require.NotNil(t, reader)
	return reader
}

func (e *serverTestEnv) Get(t *testing.T, path string) *http.Response {
	resp, err := e.httpClient.Get(e.resolvePath(path))
	require.NoError(t, err)
	return resp
}

func (e *serverTestEnv) GetWithQuery(t *testing.T, path string, query string) *http.Response {
	resp, err := e.httpClient.Get(e.resolveUrl(&url.URL{Path: path, RawQuery: query}))
	require.NoError(t, err)
	return resp
}

func (e *serverTestEnv) Post(t *testing.T, path string, body interface{}) *http.Response {
	resp, err := e.httpClient.Post(e.resolvePath(path), "application/json", e.marshal(t, body))
	require.NoError(t, err)
	return resp
}

func (e *serverTestEnv) Put(t *testing.T, path string, body interface{}) *http.Response {
	req, err := http.NewRequest("PUT", e.resolvePath(path), e.marshal(t, body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient.Do(req)
	require.NoError(t, err)
	return resp
}

func TestTokensServer(t *testing.T) {
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

	env := serverTestEnv{
		httpClient: httpClient,
		baseURL:    baseURL,
	}

	certBob, signerBob := testutils.LoadTestCrypto(t, c.GetUserCertDir(), "bob")
	_, bobKeyPath := c.GetUserCertKeyPath("bob")
	hashSignerBob, err := tokenscrypto.NewSigner("bob", bobKeyPath)

	certCharlie, signerCharlie := testutils.LoadTestCrypto(t, c.GetUserCertDir(), "charlie")
	_, charlieKeyPath := c.GetUserCertKeyPath("charlie")
	hashSignerCharlie, err := tokenscrypto.NewSigner("charlie", charlieKeyPath)

	// Add 2 users
	// The test environment prepares crypto material for: server, admin, alice, bob, and charlie; alice is the custodian.

	// Add "bob"
	userRecordBob := &types.UserRecord{
		Identity:    "bob",
		Certificate: base64.StdEncoding.EncodeToString(certBob.Raw),
		Privilege:   nil,
	}
	resp := env.Post(t, constants.TokensUsersEndpoint, userRecordBob)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Add "charlie"
	userRecordCharlie := &types.UserRecord{
		Identity:    "charlie",
		Certificate: base64.StdEncoding.EncodeToString(certCharlie.Raw),
		Privilege:   nil,
	}
	resp = env.Post(t, constants.TokensUsersEndpoint, userRecordCharlie)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	t.Run("NFT+Annotations", func(t *testing.T) {
		// GET /status
		// make sure the token server is connected to Orion cluster
		statusResponse := &types.StatusResponse{}
		env.testGetRequest(
			t,
			"status",
			constants.StatusEndpoint,
			statusResponse,
		)
		require.True(t, strings.HasPrefix(statusResponse.Status, fmt.Sprintf("connected: {Id: node-1, Address: 127.0.0.1, Port: %d", nPort)))

		deployResponses := make([]*types.DeployResponse, 3)

		t.Run("deploy", func(t *testing.T) {
			// Deploy two token types, one annotation
			deployResponses[0] = env.deployTokenType(t, &types.DeployRequest{
				Name:        "original content",
				Description: "represents copyright ownership of original content",
			})
			t.Logf("Deployed token-type: %+v", deployResponses[0])

			deployResponses[1] = env.deployTokenType(t, &types.DeployRequest{
				Name:        "leasing rights",
				Description: "represents the right to watch the content for a limited time",
				Class:       constants.TokenClass_NFT,
			})
			t.Logf("Deployed token-type: %+v", deployResponses[1])

			deployResponses[2] = env.deployTokenType(t, &types.DeployRequest{
				Name:        "production",
				Description: "represents the production supply chain",
				Class:       constants.TokenClass_ANNOTATIONS,
			})
			t.Logf("Deployed token-type: %+v", deployResponses[2])

			// Get the token types one by one
			for _, deployResp := range deployResponses {
				newDeployResp := &types.DeployResponse{}
				env.testGetRequestRaw(t, deployResp.Url, newDeployResp)
				t.Logf("token-type: %+v", deployResp)
				require.Equal(t, deployResp.Url, constants.TokensTypesSubTree+deployResp.TypeId)
			}

			// Get all token types
			var tokenTypes []map[string]string
			env.testGetRequestRaw(t,
				constants.TokensTypesEndpoint,
				&tokenTypes,
			)
			require.Len(t, tokenTypes, 3)
			expectedTypes := []string{deployResponses[0].TypeId, deployResponses[1].TypeId, deployResponses[2].TypeId}
			actualTypes := []string{tokenTypes[0]["typeId"], tokenTypes[1]["typeId"], tokenTypes[2]["typeId"]}
			require.ElementsMatch(t, expectedTypes, actualTypes)
		})

		t.Run("update users", func(t *testing.T) {
			// Update "bob"
			userRecordBob.Privilege = nil // empty means all token types, can own copyright and lease
			resp = env.Put(t, constants.TokensUsersSubTree+"bob", userRecordBob)
			assertResponse(t, http.StatusOK, resp, &types.UserRecord{})

			// Update "charlie"
			userRecordCharlie.Privilege = []string{deployResponses[1].TypeId} // can only own token 2, i.e. only lease
			resp = env.Put(t, constants.TokensUsersSubTree+"charlie", userRecordCharlie)
			assertResponse(t, http.StatusOK, resp, &types.UserRecord{})
		})

		submitResponses := make([]*types.SubmitResponse, 5)

		t.Run("mint", func(t *testing.T) {
			// Mint some content tokens
			submitResponses[0] = env.mintToken(t, deployResponses[0].TypeId, &types.MintRequest{
				Owner:         "bob",
				AssetData:     "Title: game 1",
				AssetMetadata: "Ravens vs. Chargers",
			}, hashSignerBob)
			t.Logf("Minted: tokenId: %s, txId: %s", submitResponses[0].TxContext, submitResponses[0].TxId)

			submitResponses[1] = env.mintToken(t, deployResponses[0].TypeId, &types.MintRequest{
				Owner:         "bob",
				AssetData:     "Title: game 2",
				AssetMetadata: "Patriots vs. Steelers",
			}, hashSignerBob)
			t.Logf("Minted: tokenId: %s, txId: %s", submitResponses[1].TxContext, submitResponses[1].TxId)

			submitResponses[2] = env.mintToken(t, deployResponses[0].TypeId, &types.MintRequest{
				Owner:         "bob",
				AssetData:     "Title: game 3",
				AssetMetadata: "Jets vs. Browns",
			}, hashSignerBob)
			t.Logf("Minted: tokenId: %s, txId: %s", submitResponses[2].TxContext, submitResponses[2].TxId)

			// Mint some rights tokens
			require.NoError(t, err)
			submitResponses[3] = env.mintToken(t, deployResponses[1].TypeId, &types.MintRequest{
				Owner:         "charlie",
				AssetData:     "Lease: No. 1: " + submitResponses[0].TxContext,
				AssetMetadata: "Expire: 28/12/2023",
			}, hashSignerCharlie)
			t.Logf("Minted: tokenId: %s, txId: %s", submitResponses[3].TxContext, submitResponses[3].TxId)

			submitResponses[4] = env.mintToken(t, deployResponses[1].TypeId, &types.MintRequest{
				Owner:         "charlie",
				AssetData:     "Lease: No. 2: " + submitResponses[1].TxContext,
				AssetMetadata: "Expire: 28/12/2024",
			}, hashSignerCharlie)
			t.Logf("Minted: tokenId: %s, txId: %s", submitResponses[4].TxContext, submitResponses[4].TxId)

			// Get the tokens
			for _, submitResp := range submitResponses {
				tokenRecord := &types.TokenRecord{}
				env.testGetRequestRaw(t, constants.TokensAssetsSubTree+submitResp.TxContext, tokenRecord)
				t.Logf("TokenId: %s", submitResp.TxContext)
				t.Logf("Token: %+v", tokenRecord)
			}
		})

		t.Run("transfer", func(t *testing.T) {
			// Transfer the tokens
			for _, submitResp := range submitResponses[:3] {
				request := &types.TransferRequest{
					Owner:    "bob",
					NewOwner: "charlie",
				}
				resp := env.transferToken(t, submitResp.TxContext, request, signerBob)
				require.Equal(t, submitResp.TxContext, resp.TxContext)
			}

			// Transfer the tokens
			for _, submitResp := range submitResponses[3:] {
				request := &types.TransferRequest{
					Owner:    "charlie",
					NewOwner: "bob",
				}
				resp := env.transferToken(t, submitResp.TxContext, request, signerCharlie)
				require.Equal(t, submitResp.TxContext, resp.TxContext)
			}

			// Get charlie's tokens
			for _, submitResp := range submitResponses[:3] {
				tokenRecord := &types.TokenRecord{}
				env.testGetRequestRaw(t, constants.TokensAssetsSubTree+submitResp.TxContext, tokenRecord)
				require.Equal(t, "charlie", tokenRecord.Owner)
			}

			// Get bob's tokens
			for _, submitResp := range submitResponses[3:] {
				tokenRecord := &types.TokenRecord{}
				env.testGetRequestRaw(t, constants.TokensAssetsSubTree+submitResp.TxContext, tokenRecord)
				require.Equal(t, "bob", tokenRecord.Owner)
			}
		})

		t.Run("query", func(t *testing.T) {
			// Get tokens by owner
			var tokenRecords []*types.TokenRecord
			env.testGetRequestWithQueryRaw(t,
				constants.TokensAssetsEndpoint,
				"owner=bob&type="+deployResponses[1].TypeId,
				&tokenRecords,
			)
			require.Len(t, tokenRecords, 2)
			for _, tr := range tokenRecords {
				require.Equal(t, "bob", tr.Owner)
			}

			// Get tokens by owner
			tokenRecords = nil
			env.testGetRequestWithQueryRaw(t,
				constants.TokensAssetsEndpoint,
				"owner=charlie&type="+deployResponses[0].TypeId,
				&tokenRecords,
			)
			require.Len(t, tokenRecords, 3)
			for _, tr := range tokenRecords {
				require.Equal(t, "charlie", tr.Owner)
			}

			// Get tokens by owner
			tokenRecords = nil
			env.testGetRequestWithQueryRaw(t,
				constants.TokensAssetsEndpoint,
				"owner=bob&type="+deployResponses[0].TypeId,
				&tokenRecords,
			)
			require.Len(t, tokenRecords, 0)
		})
	})

	t.Run("Fungible", func(t *testing.T) {
		fungibleResponse := types.FungibleDeployResponse{}
		env.testPostRequest(t, "deploy",
			constants.FungibleDeploy,
			&types.FungibleDeployRequest{
				Name:         "Fungible test",
				ReserveOwner: "bob",
			},
			&fungibleResponse,
			http.StatusCreated,
		)
		assert.NotEmpty(t, fungibleResponse.TypeId)
		lg.Infof("Fung resp: %v", fungibleResponse)

		env.testGetRequest(t, "describe",
			constants.FungibleDescribe.ForResource(fungibleResponse.TypeId),
			&types.FungibleDescribeResponse{},
		)

		env.testPostSignAndSubmit(t, "mint",
			constants.FungibleMint.ForResource(fungibleResponse.TypeId),
			&types.FungibleMintRequest{Supply: 5},
			&types.FungibleMintResponse{},
			http.StatusOK,
			signerBob,
		)

		env.testPostSignAndSubmit(t, "transfer",
			constants.FungibleTransfer.ForResource(fungibleResponse.TypeId),
			&types.FungibleTransferRequest{
				Owner:    "bob",
				Account:  "reserve",
				NewOwner: "charlie",
				Quantity: 1,
			},
			&types.FungibleTransferResponse{},
			http.StatusOK,
			signerBob,
		)

		env.testPostSignAndSubmit(t, "consolidate",
			constants.FungibleConsolidate.ForResource(fungibleResponse.TypeId),
			&types.FungibleConsolidateRequest{
				Owner: "charlie",
			},
			&types.FungibleConsolidateResponse{},
			http.StatusOK,
			signerCharlie,
		)

		env.testGetRequestWithQuery(t, "accounts",
			constants.FungibleAccounts.ForResource(fungibleResponse.TypeId),
			url.Values{"owner": []string{"charlie"}}.Encode(),
			&types.FungibleAccountRecords{},
		)
	})

	wg.Add(1)
	err = tokensServer.Stop()
	require.NoError(t, err)
	wg.Wait()
}

// assertResponse validates the status code and the response fields
func assertResponse(t *testing.T, expectedStatus int, resp *http.Response, responseBody interface{}) bool {
	// Read the response body into a buffer, so we could print it in case of an error
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(resp.Body)
	require.NoError(t, err)

	if assert.Equal(t, expectedStatus, resp.StatusCode, "Status: %d, Response: %s", resp.StatusCode, buf.String()) {
		// If status code matches, then attempt to validate the response fields
		decoder := json.NewDecoder(buf)
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&responseBody)
		return assert.NoError(t, err, "Status: %d, Response: %s", resp.StatusCode, buf.String())
	}

	return false
}

func (e *serverTestEnv) testPostRequestRaw(
	t *testing.T, path string, request interface{}, response interface{}, expectedStatus int,
) {
	assertResponse(t, expectedStatus, e.Post(t, path, request), response)
}

func (e *serverTestEnv) testPostRequest(
	t *testing.T, name string, path string, request interface{}, response interface{}, status int,
) {
	t.Run(name, func(t *testing.T) {
		e.testPostRequestRaw(t, path, request, response, status)
	})
}

func (e *serverTestEnv) testGetRequestRaw(
	t *testing.T, path string, response interface{},
) {
	assertResponse(t, http.StatusOK, e.Get(t, path), response)
}

func (e *serverTestEnv) testGetRequestWithQueryRaw(
	t *testing.T, path string, query string, response interface{},
) {
	assertResponse(t, http.StatusOK, e.GetWithQuery(t, path, query), response)
}

func (e *serverTestEnv) testGetRequest(
	t *testing.T, name string, path string, response interface{},
) {
	t.Run(name, func(t *testing.T) {
		e.testGetRequestRaw(t, path, response)
	})
}

func (e *serverTestEnv) testGetRequestWithQuery(
	t *testing.T, name string, path string, query string, response interface{},
) {
	t.Run(name, func(t *testing.T) {
		e.testGetRequestWithQueryRaw(t, path, query, response)
	})
}

func (e *serverTestEnv) testPostSignAndSubmitRaw(
	t *testing.T, path string, request interface{}, response tokenscrypto.SignatureRequester, status int, signer crypto.Signer,
) *types.SubmitResponse {
	// Prepare
	e.testPostRequestRaw(t, path, request, response, status)

	// Sign
	submitRequest, err := tokenscrypto.SignTransactionResponse(signer, response)
	require.NoError(t, err)

	submitResponse := types.SubmitResponse{}
	// Submit
	e.testPostRequestRaw(
		t,
		constants.TokensAssetsSubmit,
		submitRequest,
		&submitResponse,
		http.StatusOK,
	)

	return &submitResponse
}

func (e *serverTestEnv) testPostSignAndSubmit(
	t *testing.T, name string, path string, request interface{}, response tokenscrypto.SignatureRequester, status int, signer crypto.Signer,
) {
	t.Run(name, func(t *testing.T) {
		e.testPostSignAndSubmitRaw(t, path, request, response, status, signer)
	})
}

func (e *serverTestEnv) deployTokenType(t *testing.T, deployReq *types.DeployRequest) *types.DeployResponse {
	responseBody := types.DeployResponse{}
	e.testPostRequestRaw(t, constants.TokensTypesEndpoint, deployReq, &responseBody, http.StatusCreated)
	return &responseBody
}

func (e *serverTestEnv) mintToken(t *testing.T, typeId string, mintRequest *types.MintRequest, hashSigner tokenscrypto.Signer) *types.SubmitResponse {
	return e.testPostSignAndSubmitRaw(t,
		constants.TokensAssetsPrepareMint+typeId,
		mintRequest,
		&types.MintResponse{},
		http.StatusOK,
		hashSigner,
	)
}

func (e *serverTestEnv) transferToken(t *testing.T, tokenId string, transferRequest *types.TransferRequest, signer crypto.Signer) *types.SubmitResponse {
	return e.testPostSignAndSubmitRaw(t,
		constants.TokensAssetsPrepareTransfer+tokenId,
		transferRequest,
		&types.TransferResponse{},
		http.StatusOK,
		signer,
	)
}
