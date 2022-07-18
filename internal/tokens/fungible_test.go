// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"fmt"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func getDeployRequest(owner string, index int) *types.FungibleDeployRequest {
	return &types.FungibleDeployRequest{
		Name:         fmt.Sprintf("%v's Fungible #%v", owner, index),
		Description:  fmt.Sprintf("%v's  Test Fungible #%v", owner, index),
		ReserveOwner: owner,
	}
}

func getDeployRequests(owner string, num int) []*types.FungibleDeployRequest {
	var requests []*types.FungibleDeployRequest
	for i := 0; i < num; i++ {
		requests = append(requests, getDeployRequest(owner, i))
	}
	return requests
}

func assertRecordEqual(t *testing.T, expected types.FungibleAccountRecord, actual types.FungibleAccountRecord) {
	if expected.Account == reserveAccount {
		expected.Comment = ""
		actual.Comment = ""
	}
	assert.Equal(t, expected, actual)
}

func TestTokensManager_FungibleDeploy(t *testing.T) {
	env := newTestEnv(t)

	const messageCount = 3

	t.Run("success: deploy fungible and describe", func(t *testing.T) {
		for user := range env.userRecords {
			requests := getDeployRequests(user, messageCount)

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
					Url:          constants.FungibleDescribe.ForResource(expectedIdMy),
				}
				assert.Equal(t, (*types.FungibleDeployResponse)(&expectedDescribe), deployResponse)

				describeResponse, err := env.manager.FungibleDescribe(expectedIdMy)
				require.NoError(t, err)
				require.NotNil(t, deployResponse)
				assert.Equal(t, &expectedDescribe, describeResponse)

				typeDesc, err := env.manager.GetTokenType(expectedIdMy)
				assert.NoError(t, err)
				assert.Equal(t, map[string]string{
					"typeId":       expectedDescribe.TypeId,
					"name":         expectedDescribe.Name,
					"description":  expectedDescribe.Description,
					"reserveOwner": expectedDescribe.ReserveOwner,
					"class":        constants.TokenClass_FUNGIBLE,
					"url":          constants.TokensTypesSubTree + expectedIdMy,
				}, typeDesc)
			}
		}

		allTypes, err := env.manager.GetTokenTypes()
		assert.NoError(t, err)
		assert.Equal(t, messageCount*len(env.userRecords), len(allTypes))
	})

	t.Run("error: deploy again", func(t *testing.T) {
		deployResponseBad, err := env.manager.FungibleDeploy(getDeployRequest("bob", 0))
		assertTokenHttpErr(t, http.StatusConflict, deployResponseBad, err)
	})

	t.Run("error: empty name", func(t *testing.T) {
		deployRequestEmpty := &types.FungibleDeployRequest{
			Name:         "",
			Description:  "",
			ReserveOwner: "bob",
		}
		deployResponseBad, err := env.manager.FungibleDeploy(deployRequestEmpty)
		assertTokenHttpErr(t, http.StatusBadRequest, deployResponseBad, err)
	})

	t.Run("error: empty owner", func(t *testing.T) {
		deployRequestEmpty := &types.FungibleDeployRequest{
			Name:        "new-name",
			Description: "some description",
		}
		deployResponseBad, err := env.manager.FungibleDeploy(deployRequestEmpty)
		assertTokenHttpErr(t, http.StatusBadRequest, deployResponseBad, err)
	})

	t.Run("error: invalid owner", func(t *testing.T) {
		deployRequestEmpty := &types.FungibleDeployRequest{
			Name:         "new-name",
			Description:  "some description",
			ReserveOwner: "nonuser",
		}
		deployResponseBad, err := env.manager.FungibleDeploy(deployRequestEmpty)
		assertTokenHttpErr(t, http.StatusNotFound, deployResponseBad, err)
	})

	t.Run("error: admin/custodian owner", func(t *testing.T) {
		for _, user := range []string{"admin", "alice"} {
			deployRequestEmpty := &types.FungibleDeployRequest{
				Name:         "new-name",
				Description:  "some description",
				ReserveOwner: user,
			}
			deployResponseBad, err := env.manager.FungibleDeploy(deployRequestEmpty)
			assertTokenHttpErr(t, http.StatusBadRequest, deployResponseBad, err)
		}
	})
}

func TestTokensManager_FungibleMintToken(t *testing.T) {
	env := newTestEnv(t)

	response, err := env.manager.FungibleDeploy(getDeployRequest("bob", 0))
	require.NoError(t, err)
	typeId := response.TypeId

	t.Run("error: wrong signature (before mint)", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 5}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse, err := env.wrongSignAndSubmit("bob", mintResponse)
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: wrong signer (before mint)", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 5}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse, err := env.signAndSubmit("charlie", mintResponse)
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("success: signed by owner", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 5}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse := env.requireSignAndSubmit("bob", mintResponse)
		require.Equal(t, typeId, submitResponse.TxContext)

		desc, err := env.manager.FungibleDescribe(typeId)
		assert.NoError(t, err)
		assert.Equal(t, uint64(5), desc.Supply)
	})

	t.Run("success: second mint", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 5}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse := env.requireSignAndSubmit("bob", mintResponse)
		require.Equal(t, typeId, submitResponse.TxContext)

		desc, err := env.manager.FungibleDescribe(typeId)
		require.NoError(t, err)
		require.Equal(t, uint64(10), desc.Supply)
	})

	t.Run("error: wrong signature (after mint)", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 5}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse, err := env.wrongSignAndSubmit("bob", mintResponse)
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: wrong signer (after mint)", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 5}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		require.NoError(t, err)
		require.NotNil(t, mintResponse)

		submitResponse, err := env.signAndSubmit("charlie", mintResponse)
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: zero supply", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 0}
		mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
		assertTokenHttpErr(t, http.StatusBadRequest, mintResponse, err)
	})

	t.Run("error: type does not exists", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 1}
		tokenTypeIDBase64, _ := NameToID("FakeToken")
		mintResponse, err := env.manager.FungiblePrepareMint(tokenTypeIDBase64, mintRequest)
		assertTokenHttpErr(t, http.StatusNotFound, mintResponse, err)
	})

	t.Run("error: invalid type", func(t *testing.T) {
		mintRequest := &types.FungibleMintRequest{Supply: 1}
		mintResponse, err := env.manager.FungiblePrepareMint("a", mintRequest)
		assertTokenHttpErr(t, http.StatusBadRequest, mintResponse, err)
	})
}

func TestTokensManager_FungibleTransferToken(t *testing.T) {
	env := newTestEnv(t)

	deployResponse, err := env.manager.FungibleDeploy(getDeployRequest("bob", 0))
	require.NoError(t, err)
	typeId := deployResponse.TypeId

	mintRequest := &types.FungibleMintRequest{Supply: 10}
	mintResponse, err := env.manager.FungiblePrepareMint(typeId, mintRequest)
	require.NoError(t, err)
	require.NotNil(t, mintResponse)

	env.requireSignAndSubmit("bob", mintResponse)

	t.Run("success: reserve to bob", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    "bob",
			Account:  reserveAccount,
			NewOwner: "bob",
			Quantity: 2,
			Comment:  "tip",
		}
		transferResponse, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)
		assert.Equal(t, typeId, transferResponse.TypeId)
		assert.Equal(t, "bob", transferResponse.Owner)
		assert.Equal(t, reserveAccount, transferResponse.Account)
		assert.Equal(t, "bob", transferResponse.NewOwner)
		assert.NotEmpty(t, transferResponse.NewAccount)

		env.requireSignAndSubmit("bob", transferResponse)

		desc, err := env.manager.FungibleDescribe(typeId)
		assert.NoError(t, err)
		assert.Equal(t, uint64(10), desc.Supply)

		accList, err := env.manager.FungibleAccounts(typeId, "bob", reserveAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: reserveAccount,
			Owner:   "bob",
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
			Owner:    "bob",
			Account:  reserveAccount,
			NewOwner: "charlie",
			Quantity: 2,
			Comment:  "tip",
		}
		transferResponse, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)
		assert.Equal(t, typeId, transferResponse.TypeId)
		assert.Equal(t, "bob", transferResponse.Owner)
		assert.Equal(t, reserveAccount, transferResponse.Account)
		assert.Equal(t, "charlie", transferResponse.NewOwner)
		assert.NotEmpty(t, transferResponse.NewAccount)

		env.requireSignAndSubmit("bob", transferResponse)

		desc, err := env.manager.FungibleDescribe(typeId)
		assert.NoError(t, err)
		assert.Equal(t, uint64(10), desc.Supply)

		accList, err := env.manager.FungibleAccounts(typeId, "bob", reserveAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: reserveAccount,
			Owner:   "bob",
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

	t.Run("success: reserve to charlie (implicit owner)", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Account:  reserveAccount,
			NewOwner: "charlie",
			Quantity: 2,
			Comment:  "tip",
		}
		transferResponse, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		require.NoError(t, err)
		require.NotNil(t, transferResponse)
		assert.Equal(t, typeId, transferResponse.TypeId)
		assert.Equal(t, "bob", transferResponse.Owner)
		assert.Equal(t, reserveAccount, transferResponse.Account)
		assert.Equal(t, "charlie", transferResponse.NewOwner)
		assert.NotEmpty(t, transferResponse.NewAccount)

		env.requireSignAndSubmit("bob", transferResponse)

		desc, err := env.manager.FungibleDescribe(typeId)
		assert.NoError(t, err)
		assert.Equal(t, uint64(10), desc.Supply)

		accList, err := env.manager.FungibleAccounts(typeId, "bob", reserveAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: reserveAccount,
			Owner:   "bob",
			Balance: 4,
		}, accList[0])

		accList, err = env.manager.FungibleAccounts(typeId, "charlie", transferResponse.NewAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: transferResponse.NewAccount,
			Owner:   "charlie",
			Balance: 2,
			Comment: transferRequest.Comment,
		}, accList[0])
	})

	t.Run("error: insufficient funds", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Account:  reserveAccount,
			NewOwner: "charlie",
			Quantity: 10,
		}
		response, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		assertTokenHttpErr(t, http.StatusBadRequest, response, err)
	})

	for _, user := range []string{"admin", "alice"} {
		t.Run(fmt.Sprintf("error: transfer to %v", user), func(t *testing.T) {
			transferRequest := &types.FungibleTransferRequest{
				Account:  reserveAccount,
				NewOwner: user,
				Quantity: 1,
			}
			response, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
			assertTokenHttpErr(t, http.StatusBadRequest, response, err)
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
		assertTokenHttpErr(t, http.StatusNotFound, response, err)
	})

	t.Run("error: owner does not exists", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    "nonuser",
			NewOwner: "bob",
			Quantity: 1,
		}
		response, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		assertTokenHttpErr(t, http.StatusNotFound, response, err)
	})

	t.Run("error: new owner does not exists", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Account:  reserveAccount,
			NewOwner: "nonuser",
			Quantity: 1,
		}
		response, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		assertTokenHttpErr(t, http.StatusNotFound, response, err)
	})

	t.Run("error: wrong signature", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Account:  reserveAccount,
			NewOwner: "charlie",
			Quantity: 1,
		}
		response, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		require.NoError(t, err)
		require.NotNil(t, response)

		submitResponse, err := env.wrongSignAndSubmit("bob", response)
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: wrong signer", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Account:  reserveAccount,
			NewOwner: "charlie",
			Quantity: 1,
		}
		response, err := env.manager.FungiblePrepareTransfer(typeId, transferRequest)
		require.NoError(t, err)
		require.NotNil(t, response)

		submitResponse, err := env.signAndSubmit("dave", response)
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: type does not exists", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    "bob",
			Account:  reserveAccount,
			NewOwner: "charlie",
			Quantity: 1,
		}

		tokenTypeIDBase64, _ := NameToID("FakeToken")
		response, err := env.manager.FungiblePrepareTransfer(tokenTypeIDBase64, transferRequest)
		assertTokenHttpErr(t, http.StatusNotFound, response, err)
	})

	t.Run("error: invalid type", func(t *testing.T) {
		transferRequest := &types.FungibleTransferRequest{
			Owner:    "bob",
			Account:  reserveAccount,
			NewOwner: "charlie",
			Quantity: 1,
		}
		response, err := env.manager.FungiblePrepareTransfer("a", transferRequest)
		assertTokenHttpErr(t, http.StatusBadRequest, response, err)
	})
}

func TestTokensManager_FungibleConsolidateToken(t *testing.T) {
	env := newTestEnv(t)

	deployResponse, err := env.manager.FungibleDeploy(getDeployRequest("bob", 0))
	assert.NoError(t, err)
	typeId := deployResponse.TypeId

	mintResponse, err := env.manager.FungiblePrepareMint(typeId, &types.FungibleMintRequest{Supply: 100})
	require.NoError(t, err)
	require.NotNil(t, mintResponse)

	env.requireSignAndSubmit("bob", mintResponse)

	accounts := map[string][]string{}
	for user := range env.userRecords {
		for i := 0; i < 5; i++ {
			transferResponse, err := env.manager.FungiblePrepareTransfer(typeId, &types.FungibleTransferRequest{
				Account:  reserveAccount,
				NewOwner: user,
				Quantity: 1,
			})
			require.NoError(t, err)
			require.NotNil(t, transferResponse)

			env.requireSignAndSubmit("bob", transferResponse)

			accounts[user] = append(accounts[user], transferResponse.NewAccount)
		}
	}

	t.Run("success: all bob (implicit)", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{Owner: "bob"}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, typeId, response.TypeId)
		assert.Equal(t, "bob", response.Owner)

		env.requireSignAndSubmit("bob", response)

		accList, err := env.manager.FungibleAccounts(typeId, "bob", mainAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: mainAccount,
			Owner:   "bob",
			Balance: 5,
			Comment: mainAccount,
		}, accList[0])

		accList, err = env.manager.FungibleAccounts(typeId, "bob", "")
		assert.NoError(t, err)
		assert.Equal(t, 2, len(accList))
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

		env.requireSignAndSubmit("charlie", response)

		accList, err := env.manager.FungibleAccounts(typeId, "charlie", mainAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: mainAccount,
			Owner:   "charlie",
			Balance: 5,
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

		env.requireSignAndSubmit("dave", response)

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
		assert.Equal(t, 3, len(accList))
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

		env.requireSignAndSubmit("dave", response)

		accList, err := env.manager.FungibleAccounts(typeId, "dave", mainAccount)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(accList))
		assertRecordEqual(t, types.FungibleAccountRecord{
			Account: mainAccount,
			Owner:   "dave",
			Balance: 4,
			Comment: mainAccount,
		}, accList[0])

		accList, err = env.manager.FungibleAccounts(typeId, "dave", "")
		require.NoError(t, err)
		assert.Equal(t, 2, len(accList))
	})

	t.Run("error: no accounts to consolidate", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{
			Owner: "bob",
		}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		assertTokenHttpErr(t, http.StatusNotFound, response, err)
	})

	t.Run("error: empty account list", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{
			Owner:    "dave",
			Accounts: []string{},
		}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		assertTokenHttpErr(t, http.StatusBadRequest, response, err)
	})

	for _, accName := range []string{reserveAccount, mainAccount} {
		t.Run(fmt.Sprintf("error: include '%v' in list", accName), func(t *testing.T) {
			request := &types.FungibleConsolidateRequest{
				Owner:    "dave",
				Accounts: []string{accName},
			}
			response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
			assertTokenHttpErr(t, http.StatusBadRequest, response, err)
		})
	}

	t.Run("error: account does not exist", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{
			Owner:    "dave",
			Accounts: []string{"fake-account"},
		}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		assertTokenHttpErr(t, http.StatusNotFound, response, err)
	})

	t.Run("error: owner does not exists", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{Owner: "non-user"}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		assertTokenHttpErr(t, http.StatusNotFound, response, err)
	})

	t.Run("error: wrong signature", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{Owner: "dave"}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		require.NoError(t, err)
		require.NotNil(t, response)

		submitResponse, err := env.wrongSignAndSubmit("dave", response)
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: wrong signer", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{Owner: "dave"}
		response, err := env.manager.FungiblePrepareConsolidate(typeId, request)
		require.NoError(t, err)
		require.NotNil(t, response)

		submitResponse, err := env.signAndSubmit("charlie", response)
		assertTokenHttpErr(t, http.StatusForbidden, submitResponse, err)
	})

	t.Run("error: type does not exists", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{Owner: "dave"}
		tokenTypeIDBase64, _ := NameToID("FakeToken")
		response, err := env.manager.FungiblePrepareConsolidate(tokenTypeIDBase64, request)
		assertTokenHttpErr(t, http.StatusNotFound, response, err)
	})

	t.Run("error: invalid type", func(t *testing.T) {
		request := &types.FungibleConsolidateRequest{Owner: "dave"}
		response, err := env.manager.FungiblePrepareConsolidate("a", request)
		assertTokenHttpErr(t, http.StatusBadRequest, response, err)
	})
}
