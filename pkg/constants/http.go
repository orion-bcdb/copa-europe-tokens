// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package constants

import (
	"fmt"
)

type ResourceURI string

func (s ResourceURI) ForResource(resourceId string) string {
	return fmt.Sprintf(string(s), resourceId)
}

const (

	// Generic token type API

	StatusEndpoint = "/status"

	TokensTypesEndpoint = "/tokens/types"
	TokensTypesSubTree  = "/tokens/types/"
	TokensTypesQuery    = "/tokens/types/{typeId}"

	// Non fungible token type (NFT) API

	TokensAssetsEndpoint             = "/tokens/assets"
	TokensAssetsSubTree              = "/tokens/assets/"
	TokensAssetsPrepareMint          = "/tokens/assets/prepare-mint/"
	TokensAssetsPrepareMintMatch     = "/tokens/assets/prepare-mint/{typeId}"
	TokensAssetsPrepareTransfer      = "/tokens/assets/prepare-transfer/"
	TokensAssetsPrepareTransferMatch = "/tokens/assets/prepare-transfer/{tokenId}"
	TokensAssetsSubmit               = "/tokens/assets/submit"
	TokensAssetsQuery                = "/tokens/assets/{tokenId}"

	// Annotations API

	TokensAnnotationsEndpoint             = "/tokens/annotations"
	TokensAnnotationsSubTree              = "/tokens/annotations/"
	TokensAnnotationsPrepareRegister      = "/tokens/annotations/prepare-register/"
	TokensAnnotationsPrepareRegisterMatch = "/tokens/annotations/prepare-register/{typeId}"
	TokensAnnotationsSubmit               = "/tokens/annotations/submit"
	TokensAnnotationsQuery                = "/tokens/annotations/{tokenId}"

	// User API

	TokensUsersEndpoint = "/tokens/users"
	TokensUsersSubTree  = "/tokens/users/"
	TokensUsersMatch    = "/tokens/users/{userId}"

	// Fungible token type API

	FungibleRoot                    = "/tokens/fungible"
	FungibleEndpoint                = FungibleRoot + "/"
	FungibleDeploy                  = FungibleRoot + "/deploy"
	FungibleTypeRoot    ResourceURI = FungibleRoot + "/%s"
	FungibleDescribe                = FungibleTypeRoot
	FungibleMint                    = FungibleTypeRoot + "/mint-prepare"
	FungibleTransfer                = FungibleTypeRoot + "/transfer-prepare"
	FungibleConsolidate             = FungibleTypeRoot + "/consolidate-prepare"
	FungibleAccounts                = FungibleTypeRoot + "/accounts"
)
