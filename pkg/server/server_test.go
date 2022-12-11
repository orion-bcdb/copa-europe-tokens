package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/copa-europe-tokens/internal/common"
	"github.com/copa-europe-tokens/internal/tokens"
	"github.com/copa-europe-tokens/pkg/config"
	"github.com/copa-europe-tokens/pkg/constants"
	tokenscrypto "github.com/copa-europe-tokens/pkg/crypto"
	"github.com/copa-europe-tokens/pkg/types"
	sdkconfig "github.com/hyperledger-labs/orion-sdk-go/pkg/config"
	"github.com/hyperledger-labs/orion-server/pkg/crypto"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/hyperledger-labs/orion-server/pkg/server/testutils"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/hyperledger-labs/orion-server/test/setup"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/proto"
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

func (e *serverTestEnv) updateUsers(t *testing.T, records ...*types.UserRecord) {
	for _, record := range records {
		record.Privilege = nil
		resp := e.Put(t, constants.TokensUsersSubTree+record.Identity, record)
		assertResponse(t, http.StatusOK, resp, &types.UserRecord{})
	}
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
	require.NoError(t, err)

	certCharlie, signerCharlie := testutils.LoadTestCrypto(t, c.GetUserCertDir(), "charlie")
	_, charlieKeyPath := c.GetUserCertKeyPath("charlie")
	hashSignerCharlie, err := tokenscrypto.NewSigner("charlie", charlieKeyPath)
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
	mintRequest4 := &types.MintRequest{
		Owner:         "charlie",
		AssetData:     "Lease: No. 1: " + submitResponse1.TokenId,
		AssetMetadata: "Expire: 28/12/2023",
		Link:          submitResponse1.TokenId,
		Reference:     submitResponse2.TokenId,
	}
	submitResponse4 := mintToken(t, httpClient, baseURL, deployResp2.TypeId, mintRequest4, hashSignerCharlie)
	t.Logf("Minted: tokenId: %s, txId: %s", submitResponse4.TokenId, submitResponse4.TxId)

	mintRequest5 := &types.MintRequest{
		Owner:         "charlie",
		AssetData:     "Lease: No. 2: " + submitResponse2.TokenId,
		AssetMetadata: "Expire: 28/12/2024",
		Link:          submitResponse1.TokenId,
		Reference:     submitResponse2.TokenId,
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

	// Update the tokens metadata
	for _, tokenId := range []string{submitResponse4.TokenId, submitResponse5.TokenId} {
		request := &types.UpdateRequest{
			Owner:         "bob",
			AssetMetadata: "Expire: 01/01/2026",
		}
		resp := updateToken(t, httpClient, baseURL, tokenId, request, signerBob)
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
		require.Equal(t, "Expire: 01/01/2026", tokenRecord.AssetMetadata)
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
		require.Equal(t, submitResponse1.TokenId, tr.Link)
	}

	// Get tokens by link
	u = baseURL.ResolveReference(&url.URL{
		Path:     constants.TokensAssetsEndpoint,
		RawQuery: "type=" + deployResp2.TypeId + "&link=" + submitResponse1.TokenId,
	})
	resp, err = httpClient.Get(u.String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tokenRecords = []*types.TokenRecord{}
	err = json.NewDecoder(resp.Body).Decode(&tokenRecords)
	require.NoError(t, err)
	require.Len(t, tokenRecords, 2)
	for _, tr := range tokenRecords {
		require.Equal(t, "bob", tr.Owner)
		require.Equal(t, submitResponse1.TokenId, tr.Link)
	}

	// Get tokens by ref
	u = baseURL.ResolveReference(&url.URL{
		Path:     constants.TokensAssetsEndpoint,
		RawQuery: "type=" + deployResp2.TypeId + "&reference=" + submitResponse2.TokenId,
	})
	resp, err = httpClient.Get(u.String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tokenRecords = []*types.TokenRecord{}
	err = json.NewDecoder(resp.Body).Decode(&tokenRecords)
	require.NoError(t, err)
	require.Len(t, tokenRecords, 2)
	for _, tr := range tokenRecords {
		require.Equal(t, "bob", tr.Owner)
		require.Equal(t, submitResponse2.TokenId, tr.Reference)
	}

	// Get tokens by link & owner
	u = baseURL.ResolveReference(&url.URL{
		Path:     constants.TokensAssetsEndpoint,
		RawQuery: "owner=charlie&type=" + deployResp2.TypeId + "&link=" + submitResponse1.TokenId,
	})
	resp, err = httpClient.Get(u.String())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tokenRecords = []*types.TokenRecord{}
	err = json.NewDecoder(resp.Body).Decode(&tokenRecords)
	require.NoError(t, err)
	require.Len(t, tokenRecords, 0)

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
		require.Equal(t, "", tr.Link)
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

	t.Run("Annotations", func(t *testing.T) {
		var annotIDs []string
		t.Run("register", func(t *testing.T) {
			for i := 1; i <= 10; i++ {
				annotRequest := &types.AnnotationRegisterRequest{
					Owner:              "charlie",
					Link:               submitResponse1.TokenId,
					Reference:          submitResponse2.TokenId,
					AnnotationData:     fmt.Sprintf("Charlie: Operation %d on %s", i, submitResponse1.TokenId),
					AnnotationMetadata: "xxx",
				}

				annotSubmitResp := annotateToken(t, httpClient, baseURL, deployResp3.TypeId, annotRequest, hashSignerCharlie)
				annotIDs = append(annotIDs, annotSubmitResp.TokenId)
				t.Logf("Annotation: tokenId: %s, txId: %s", annotSubmitResp.TokenId, annotSubmitResp.TxId)

				annotRequest = &types.AnnotationRegisterRequest{
					Owner:              "charlie",
					Link:               submitResponse2.TokenId,
					Reference:          submitResponse1.TokenId,
					AnnotationData:     fmt.Sprintf("Charlie: Operation %d on %s", i, submitResponse2.TokenId),
					AnnotationMetadata: "yyy",
				}

				annotSubmitResp = annotateToken(t, httpClient, baseURL, deployResp3.TypeId, annotRequest, hashSignerCharlie)
				annotIDs = append(annotIDs, annotSubmitResp.TokenId)
				t.Logf("Annotation: tokenId: %s, txId: %s", annotSubmitResp.TokenId, annotSubmitResp.TxId)
			}

			for i := 1; i <= 7; i++ {
				annotRequest := &types.AnnotationRegisterRequest{
					Owner:              "bob",
					Link:               submitResponse1.TokenId,
					Reference:          submitResponse2.TokenId,
					AnnotationData:     fmt.Sprintf("Bob: Operation %d on %s", i, submitResponse1.TokenId),
					AnnotationMetadata: "zzz",
				}

				annotSubmitResp := annotateToken(t, httpClient, baseURL, deployResp3.TypeId, annotRequest, hashSignerBob)
				annotIDs = append(annotIDs, annotSubmitResp.TokenId)
				t.Logf("Annotation: tokenId: %s, txId: %s", annotSubmitResp.TokenId, annotSubmitResp.TxId)
			}
		})

		t.Run("query by link 1", func(t *testing.T) {
			u = baseURL.ResolveReference(&url.URL{
				Path:     constants.TokensAnnotationsEndpoint,
				RawQuery: "type=" + deployResp3.TypeId + "&" + "link=" + submitResponse1.TokenId,
			})
			t.Logf("GET: %s", u.String())
			resp, err := httpClient.Get(u.String())
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			annotationRecords := []*types.AnnotationRecord{}
			err = json.NewDecoder(resp.Body).Decode(&annotationRecords)
			require.NoError(t, err)
			require.Len(t, annotationRecords, 17)
		})

		t.Run("query by link 2", func(t *testing.T) {
			u = baseURL.ResolveReference(&url.URL{
				Path:     constants.TokensAnnotationsEndpoint,
				RawQuery: "type=" + deployResp3.TypeId + "&" + "link=" + submitResponse2.TokenId,
			})
			t.Logf("GET: %s", u.String())
			resp, err := httpClient.Get(u.String())
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			annotationRecords := []*types.AnnotationRecord{}
			err = json.NewDecoder(resp.Body).Decode(&annotationRecords)
			require.NoError(t, err)
			require.Len(t, annotationRecords, 10)
		})

		t.Run("query by ref 1", func(t *testing.T) {
			u = baseURL.ResolveReference(&url.URL{
				Path:     constants.TokensAnnotationsEndpoint,
				RawQuery: "type=" + deployResp3.TypeId + "&" + "reference=" + submitResponse2.TokenId,
			})
			t.Logf("GET: %s", u.String())
			resp, err := httpClient.Get(u.String())
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			annotationRecords := []*types.AnnotationRecord{}
			err = json.NewDecoder(resp.Body).Decode(&annotationRecords)
			require.NoError(t, err)
			require.Len(t, annotationRecords, 17)
		})

		t.Run("query by ref 2", func(t *testing.T) {
			u = baseURL.ResolveReference(&url.URL{
				Path:     constants.TokensAnnotationsEndpoint,
				RawQuery: "type=" + deployResp3.TypeId + "&" + "reference=" + submitResponse1.TokenId,
			})
			t.Logf("GET: %s", u.String())
			resp, err := httpClient.Get(u.String())
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			annotationRecords := []*types.AnnotationRecord{}
			err = json.NewDecoder(resp.Body).Decode(&annotationRecords)
			require.NoError(t, err)
			require.Len(t, annotationRecords, 10)
		})

		t.Run("query by link: empty", func(t *testing.T) {
			u = baseURL.ResolveReference(&url.URL{
				Path:     constants.TokensAnnotationsEndpoint,
				RawQuery: "type=" + deployResp3.TypeId + "&" + "link=xxx.yyy",
			})
			t.Logf("GET: %s", u.String())
			resp, err := httpClient.Get(u.String())
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			annotationRecords := []*types.AnnotationRecord{}
			err = json.NewDecoder(resp.Body).Decode(&annotationRecords)
			require.NoError(t, err)
			require.Len(t, annotationRecords, 0)
		})

		t.Run("query by ref: empty", func(t *testing.T) {
			u = baseURL.ResolveReference(&url.URL{
				Path:     constants.TokensAnnotationsEndpoint,
				RawQuery: "type=" + deployResp3.TypeId + "&" + "reference=xxx.yyy",
			})
			t.Logf("GET: %s", u.String())
			resp, err := httpClient.Get(u.String())
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			annotationRecords := []*types.AnnotationRecord{}
			err = json.NewDecoder(resp.Body).Decode(&annotationRecords)
			require.NoError(t, err)
			require.Len(t, annotationRecords, 0)
		})

		t.Run("query by owner", func(t *testing.T) {
			u = baseURL.ResolveReference(&url.URL{
				Path:     constants.TokensAnnotationsEndpoint,
				RawQuery: "type=" + deployResp3.TypeId + "&" + "owner=bob",
			})
			t.Logf("GET: %s", u.String())
			resp, err := httpClient.Get(u.String())
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			annotationRecords := []*types.AnnotationRecord{}
			err = json.NewDecoder(resp.Body).Decode(&annotationRecords)
			require.NoError(t, err)
			require.Len(t, annotationRecords, 7)
		})

		t.Run("query by link & owner", func(t *testing.T) {
			u = baseURL.ResolveReference(&url.URL{
				Path:     constants.TokensAnnotationsEndpoint,
				RawQuery: "type=" + deployResp3.TypeId + "&" + "link=" + submitResponse1.TokenId + "&owner=charlie",
			})
			t.Logf("GET: %s", u.String())
			resp, err := httpClient.Get(u.String())
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			annotationRecords := []*types.AnnotationRecord{}
			err = json.NewDecoder(resp.Body).Decode(&annotationRecords)
			require.NoError(t, err)
			require.Len(t, annotationRecords, 10)
		})

		t.Run("query by ref & owner", func(t *testing.T) {
			u = baseURL.ResolveReference(&url.URL{
				Path:     constants.TokensAnnotationsEndpoint,
				RawQuery: "type=" + deployResp3.TypeId + "&" + "reference=" + submitResponse2.TokenId + "&owner=charlie",
			})
			t.Logf("GET: %s", u.String())
			resp, err := httpClient.Get(u.String())
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			annotationRecords := []*types.AnnotationRecord{}
			err = json.NewDecoder(resp.Body).Decode(&annotationRecords)
			require.NoError(t, err)
			require.Len(t, annotationRecords, 10)
		})

		t.Run("get by annot-id", func(t *testing.T) {
			for _, id := range annotIDs {
				u = baseURL.ResolveReference(&url.URL{
					Path: path.Join(constants.TokensAnnotationsEndpoint, id),
				})
				t.Logf("GET: %s", u.String())
				resp, err := httpClient.Get(u.String())
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				annotationRecord := &types.AnnotationRecord{}
				err = json.NewDecoder(resp.Body).Decode(annotationRecord)
				require.NoError(t, err)
				require.Contains(t, annotationRecord.AnnotationData, "Operation")
			}
		})

		t.Run("get by annot-id: not found", func(t *testing.T) {
			u = baseURL.ResolveReference(&url.URL{
				Path: path.Join(constants.TokensAnnotationsEndpoint, "xxx.yyy"),
			})
			t.Logf("GET: %s", u.String())
			resp, err := httpClient.Get(u.String())
			require.NoError(t, err)
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	})

	var fungibleTypeId string
	t.Run("Fungible", func(t *testing.T) {
		var typeId string
		deployRequest := types.FungibleDeployRequest{
			Name:         "Fungible test",
			Description:  "Fungible test description",
			ReserveOwner: "bob",
		}

		t.Run("deploy", func(t *testing.T) {
			response := types.FungibleDeployResponse{}
			env.testPostRequest(t,
				constants.FungibleDeploy,
				&deployRequest,
				&response,
				http.StatusCreated,
			)
			assert.NotEmpty(t, response.TypeId)
			typeId = response.TypeId
			assert.Equal(t, uint64(0), response.Supply)
			assert.Equal(t, deployRequest.Name, response.Name)
			assert.Equal(t, deployRequest.Description, response.Description)
			lg.Infof("Fung resp: %v", response)
		})
		require.NotEmpty(t, typeId)
		fungibleTypeId = typeId

		t.Run("get-types", func(t *testing.T) {
			var response []types.TokenDescription
			env.testGetRequest(t,
				constants.TokensTypesEndpoint,
				&response,
			)
			assert.GreaterOrEqual(t, len(response), 1)
			tokenTypes := make([]string, len(response))
			for i, token := range response {
				tokenTypes[i] = token.TypeId
			}
			assert.Contains(t, tokenTypes, typeId)
		})

		env.updateUsers(t, userRecordBob, userRecordCharlie)

		t.Run("describe", func(t *testing.T) {
			response := types.FungibleDescribeResponse{}
			env.testGetRequest(t,
				common.URLForType(constants.FungibleTypeRoot, typeId),
				&response,
			)
			assert.Equal(t, typeId, response.TypeId)
			assert.Equal(t, uint64(0), response.Supply)
			assert.Equal(t, deployRequest.Name, response.Name)
			assert.Equal(t, deployRequest.Description, response.Description)
		})

		supply := uint64(5)
		t.Run("mint", func(t *testing.T) {
			mintReq := types.FungibleMintRequest{Supply: supply}
			mintResp := tokens.FungibleMintResponse{}
			env.testPostSignAndSubmit(t,
				common.URLForType(constants.FungibleMint, typeId),
				&mintReq,
				&mintResp,
				http.StatusOK,
				signerBob,
			)
			assert.Equal(t, typeId, mintResp.TypeId)

			describeResp := types.FungibleDescribeResponse{}
			env.testGetRequest(t,
				common.URLForType(constants.FungibleTypeRoot, typeId),
				&describeResp,
			)
			assert.Equal(t, typeId, describeResp.TypeId)
			assert.Equal(t, supply, describeResp.Supply)
		})

		charlieQuantity := uint64(1)
		t.Run("transfer", func(t *testing.T) {
			transReq := types.FungibleTransferRequest{
				Owner:    "reserve",
				NewOwner: "charlie",
				Quantity: charlieQuantity,
			}
			transResp := tokens.FungibleTransferResponse{}
			env.testPostSignAndSubmit(t,
				common.URLForType(constants.FungibleTransfer, typeId),
				&transReq,
				&transResp,
				http.StatusOK,
				signerBob,
			)
			assert.Equal(t, typeId, transResp.TypeId)
			assert.Equal(t, transReq.Owner, transResp.Owner)
			assert.Equal(t, "main", transResp.Account)
			assert.Equal(t, transReq.NewOwner, transResp.NewOwner)
			assert.NotEmpty(t, transResp.NewAccount)

			describeResp := types.FungibleDescribeResponse{}
			env.testGetRequest(t,
				common.URLForType(constants.FungibleTypeRoot, typeId),
				&describeResp,
			)
			assert.Equal(t, typeId, describeResp.TypeId)
			assert.Equal(t, supply, describeResp.Supply)
		})

		t.Run("reserve account", func(t *testing.T) {
			var accounts []types.FungibleAccountRecord
			env.testGetRequestWithQuery(t,
				common.URLForType(constants.FungibleAccounts, typeId),
				url.Values{"owner": []string{"reserve"}}.Encode(),
				&accounts,
			)
			assert.Len(t, accounts, 1)
			assert.Equal(t, "reserve", accounts[0].Owner)
			assert.Equal(t, "main", accounts[0].Account)
			assert.Equal(t, supply-charlieQuantity, accounts[0].Balance)
		})

		t.Run("charlie's accounts", func(t *testing.T) {
			var accounts []types.FungibleAccountRecord
			env.testGetRequestWithQuery(t,
				common.URLForType(constants.FungibleAccounts, typeId),
				url.Values{"owner": []string{"charlie"}}.Encode(),
				&accounts,
			)
			assert.Len(t, accounts, 1)
			assert.Equal(t, "charlie", accounts[0].Owner)
			assert.NotEmpty(t, accounts[0].Account)
			assert.NotEqual(t, "main", accounts[0].Account)
			assert.Equal(t, charlieQuantity, accounts[0].Balance)
		})

		t.Run("consolidate", func(t *testing.T) {
			request := types.FungibleConsolidateRequest{
				Owner: "charlie",
			}
			response := tokens.FungibleConsolidateResponse{}
			env.testPostSignAndSubmit(t,
				common.URLForType(constants.FungibleConsolidate, typeId),
				&request,
				&response,
				http.StatusOK,
				signerCharlie,
			)
			assert.Equal(t, typeId, response.TypeId)
			assert.Equal(t, request.Owner, response.Owner)
		})

		t.Run("charlie's main account", func(t *testing.T) {
			var accounts []types.FungibleAccountRecord
			env.testGetRequestWithQuery(t,
				common.URLForType(constants.FungibleAccounts, typeId),
				url.Values{"owner": []string{"charlie"}}.Encode(),
				&accounts,
			)
			assert.Len(t, accounts, 1)
			assert.Equal(t, "charlie", accounts[0].Owner)
			assert.Equal(t, "main", accounts[0].Account)
			assert.Equal(t, charlieQuantity, accounts[0].Balance)
		})
	})

	t.Run("Rights offer", func(t *testing.T) {
		var typeId string
		deployRequest := types.DeployRequest{
			Name:        "Offers test",
			Description: "Offers test description",
			Class:       constants.TokenClass_RIGHTS_OFFER,
		}

		t.Run("deploy", func(t *testing.T) {
			response := types.DeployResponse{}
			env.testPostRequest(t,
				constants.TokensTypesEndpoint,
				&deployRequest,
				&response,
				http.StatusCreated,
			)
			require.NotEmpty(t, response.TypeId)
			typeId = response.TypeId
			assert.Equal(t, deployRequest.Name, response.Name)
			assert.Equal(t, deployRequest.Description, response.Description)
			lg.Infof("Rights offer deploy resp: %v", response)

			env.updateUsers(t, userRecordBob, userRecordCharlie)
		})

		t.Run("get-types", func(t *testing.T) {
			require.NotEmpty(t, typeId)
			var response []types.TokenDescription
			env.testGetRequest(t,
				constants.TokensTypesEndpoint,
				&response,
			)
			assert.GreaterOrEqual(t, len(response), 1)
			tokenTypes := make([]string, len(response))
			for i, token := range response {
				tokenTypes[i] = token.TypeId
			}
			assert.Contains(t, tokenTypes, typeId)
		})

		var offerId string
		var offerRecord types.RightsOfferRecord
		t.Run("mint and get", func(t *testing.T) {
			require.NotEmpty(t, typeId)
			require.NotEmpty(t, fungibleTypeId)

			mintReq := types.RightsOfferMintRequest{
				Name:     "name",
				Owner:    "bob",
				Asset:    submitResponse5.TokenId,
				Rights:   deployResp1.TypeId,
				Template: "template",
				Price:    1,
				Currency: fungibleTypeId,
			}
			mintResp := tokens.RightsOfferResponse{}
			env.testRightsPostSignAndSubmit(t,
				common.URLForType(constants.RightsOfferMint, typeId),
				&mintReq,
				&mintResp,
				http.StatusOK,
				signerBob,
			)
			require.NotEmpty(t, mintResp.OfferId)
			offerId = mintResp.OfferId

			env.testGetRequest(t,
				common.URLForOffer(constants.RightsOfferGet, offerId),
				&offerRecord,
			)
			assert.Equal(t, mintReq.Name, offerRecord.Name)
			assert.Equal(t, mintReq.Owner, offerRecord.Owner)
			assert.Equal(t, mintReq.Asset, offerRecord.Asset)
			assert.Equal(t, mintReq.Rights, offerRecord.Rights)
			assert.Equal(t, mintReq.Template, offerRecord.Template)
			assert.Equal(t, mintReq.Price, offerRecord.Price)
			assert.Equal(t, mintReq.Currency, offerRecord.Currency)
			assert.Equal(t, true, offerRecord.Enabled)
		})

		t.Run("update and get", func(t *testing.T) {
			require.NotEmpty(t, offerId)

			updateResp := tokens.RightsOfferResponse{}
			env.testRightsPostSignAndSubmit(t,
				common.URLForOffer(constants.RightsOfferUpdate, offerId),
				&types.RightsOfferUpdateRequest{Enable: false},
				&updateResp,
				http.StatusOK,
				signerBob,
			)
			record := types.RightsOfferRecord{}
			env.testGetRequest(t,
				common.URLForOffer(constants.RightsOfferGet, offerId),
				&record,
			)
			assert.Equal(t, false, record.Enabled)

			env.testRightsPostSignAndSubmit(t,
				common.URLForOffer(constants.RightsOfferUpdate, offerId),
				&types.RightsOfferUpdateRequest{Enable: true},
				&updateResp,
				http.StatusOK,
				signerBob,
			)
			env.testGetRequest(t,
				common.URLForOffer(constants.RightsOfferGet, offerId),
				&record,
			)
			assert.Equal(t, true, record.Enabled)
		})

		t.Run("buy", func(t *testing.T) {
			require.NotEmpty(t, offerId)

			buyResp := tokens.RightsOfferBuyResponse{}
			env.testRightsPostSignAndSubmit(t,
				common.URLForOffer(constants.RightsOfferBuy, offerId),
				&types.RightsOfferBuyRequest{BuyerId: "charlie"},
				&buyResp,
				http.StatusOK,
				signerCharlie,
			)
			require.NotEmpty(t, buyResp.TokenId)

			tokenRecord := types.TokenRecord{}
			env.testGetRequest(t,
				common.URLForToken(constants.TokensAssetsQuery, buyResp.TokenId),
				&tokenRecord,
			)
			assert.Equal(t, "charlie", tokenRecord.Owner)
			assert.Equal(t, offerRecord.Asset, tokenRecord.Link)
			assert.Equal(t, offerRecord.OfferId, tokenRecord.Reference)

			assetData := &types.RightsRecord{}
			require.NoError(t, json.Unmarshal([]byte(tokenRecord.AssetData), assetData))
			assert.Equal(t, offerRecord.Asset, assetData.Asset)
			assert.Equal(t, offerRecord.OfferId, assetData.OfferId)
			assert.Equal(t, offerRecord.Template, assetData.Template)
		})

		t.Run("query by asset ID", func(t *testing.T) {
			require.NotEmpty(t, offerId)
			var offers []types.RightsOfferRecord
			env.testGetRequestWithQuery(t,
				common.URLForType(constants.RightsOfferQuery, typeId),
				url.Values{"asset": []string{offerRecord.Asset}}.Encode(),
				&offers,
			)
			assert.Len(t, offers, 1)
			assert.Equal(t, offerRecord, offers[0])
		})

		t.Run("query by owner", func(t *testing.T) {
			require.NotEmpty(t, offerId)
			var offers []types.RightsOfferRecord
			env.testGetRequestWithQuery(t,
				common.URLForType(constants.RightsOfferQuery, typeId),
				url.Values{"owner": []string{"bob"}}.Encode(),
				&offers,
			)
			assert.Len(t, offers, 1)
			assert.Equal(t, offerRecord, offers[0])
		})

		t.Run("query by owner and asset ID", func(t *testing.T) {
			require.NotEmpty(t, offerId)
			var offers []types.RightsOfferRecord
			env.testGetRequestWithQuery(t,
				common.URLForType(constants.RightsOfferQuery, typeId),
				url.Values{"owner": []string{"bob"}, "asset": []string{offerRecord.Asset}}.Encode(),
				&offers,
			)
			assert.Len(t, offers, 1)
			assert.Equal(t, offerRecord, offers[0])
		})
	})

	wg.Add(1)
	err = tokensServer.Stop()
	require.NoError(t, err)
	wg.Wait()
}

// =================================================
// Helpers
// =================================================

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

func (e *serverTestEnv) testPostRequest(
	t *testing.T, path string, request interface{}, response interface{}, expectedStatus int,
) {
	assertResponse(t, expectedStatus, e.Post(t, path, request), response)
}

func (e *serverTestEnv) testGetRequest(
	t *testing.T, path string, response interface{},
) {
	assertResponse(t, http.StatusOK, e.Get(t, path), response)
}

func (e *serverTestEnv) testGetRequestWithQuery(
	t *testing.T, path string, query string, response interface{},
) {
	assertResponse(t, http.StatusOK, e.GetWithQuery(t, path, query), response)
}

func (e *serverTestEnv) testPostPrepareAndSign(
	t *testing.T, path string, request interface{}, response tokens.SignatureRequester, status int, signer crypto.Signer,
) *tokens.SubmitContext {
	// Prepare
	e.testPostRequest(t, path, request, response, status)

	// Sign
	submitRequest, err := tokens.SignTransactionResponse(signer, response)
	require.NoError(t, err)

	return submitRequest
}

func (e *serverTestEnv) testPostSignAndSubmit(
	t *testing.T, path string, request interface{}, response tokens.SignatureRequester, status int, signer crypto.Signer,
) *types.FungibleSubmitResponse {
	submitRequest := e.testPostPrepareAndSign(t, path, request, response, status, signer)
	submitResponse := types.FungibleSubmitResponse{}
	// Submit
	e.testPostRequest(
		t,
		constants.FungibleSubmit,
		submitRequest.ToFungibleRequest(),
		&submitResponse,
		http.StatusOK,
	)
	return &submitResponse
}

func (e *serverTestEnv) testRightsPostSignAndSubmit(
	t *testing.T, path string, request interface{}, response tokens.SignatureRequester, status int, signer crypto.Signer,
) *types.RightsOfferSubmitResponse {
	submitRequest := e.testPostPrepareAndSign(t, path, request, response, status, signer)
	submitResponse := types.RightsOfferSubmitResponse{}
	// Submit
	e.testPostRequest(
		t,
		constants.RightsOfferSubmit,
		submitRequest.ToRightsRequest(),
		&submitResponse,
		http.StatusOK,
	)
	return &submitResponse
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

func updateToken(t *testing.T, httpClient *http.Client, baseURL *url.URL, tokenId string, updateRequest *types.UpdateRequest, signer crypto.Signer) *types.SubmitResponse {
	// 1. Transfer prepare
	u := baseURL.ResolveReference(&url.URL{Path: constants.TokensAssetsPrepareUpdate + tokenId})
	requestBytes, err := json.Marshal(updateRequest)
	require.NoError(t, err)
	reader := bytes.NewReader(requestBytes)
	require.NotNil(t, reader)
	resp, err := httpClient.Post(u.String(), "application/json", reader)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	updateResponse := &types.UpdateResponse{}
	err = json.NewDecoder(resp.Body).Decode(updateResponse)
	require.NoError(t, err)

	// 2. Sign by owner
	txEnvBytes, err := base64.StdEncoding.DecodeString(updateResponse.TxEnvelope)
	require.NoError(t, err)
	txEnv := &oriontypes.DataTxEnvelope{}
	err = proto.Unmarshal(txEnvBytes, txEnv)
	require.NoError(t, err)
	sig := testutils.SignatureFromTx(t, signer, txEnv.Payload)
	require.NotNil(t, sig)

	// 3. Submit
	u = baseURL.ResolveReference(&url.URL{Path: constants.TokensAssetsSubmit})
	submitRequest := &types.SubmitRequest{
		TokenId:       updateResponse.TokenId,
		TxEnvelope:    updateResponse.TxEnvelope,
		TxPayloadHash: updateResponse.TxPayloadHash,
		Signer:        updateResponse.Owner,
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

func annotateToken(t *testing.T, httpClient *http.Client, baseURL *url.URL, typeId string, annotRequest *types.AnnotationRegisterRequest, hashSigner tokenscrypto.Signer) *types.SubmitResponse {
	// 1. Mint prepare
	u := baseURL.ResolveReference(&url.URL{Path: constants.TokensAnnotationsPrepareRegister + typeId})
	requestBytes, err := json.Marshal(annotRequest)
	require.NoError(t, err)
	reader := bytes.NewReader(requestBytes)
	require.NotNil(t, reader)
	resp, err := httpClient.Post(u.String(), "application/json", reader)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	annotResponse := &types.AnnotationRegisterResponse{}
	err = json.NewDecoder(resp.Body).Decode(annotResponse)
	require.NoError(t, err)

	// 2. Sign by owner, using a Hash signer service that does not know Orion types
	hashBytes, err := base64.StdEncoding.DecodeString(annotResponse.TxPayloadHash)
	require.NoError(t, err)
	sig, err := hashSigner.SignHash(hashBytes)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// 3. Submit
	u = baseURL.ResolveReference(&url.URL{Path: constants.TokensAnnotationsSubmit})
	submitRequest := &types.SubmitRequest{
		TokenId:       annotResponse.AnnotationId,
		TxEnvelope:    annotResponse.TxEnvelope,
		TxPayloadHash: annotResponse.TxPayloadHash,
		Signer:        annotResponse.Owner,
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
