// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package constants

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
	TokensAssetsPrepareUpdate        = "/tokens/assets/prepare-update/"
	TokensAssetsPrepareUpdateMatch   = "/tokens/assets/prepare-update/{tokenId}"
	TokensAssetsSubmit               = "/tokens/assets/submit"
	TokensAssetsQuery                = "/tokens/assets/{tokenId}"

	// Annotations API

	TokensAnnotationsEndpoint             = "/tokens/annotations"
	TokensAnnotationsSubTree              = "/tokens/annotations/"
	TokensAnnotationsPrepareRegister      = "/tokens/annotations/prepare-register/"
	TokensAnnotationsPrepareRegisterMatch = "/tokens/annotations/prepare-register/{typeId}"
	TokensAnnotationsSubmit               = "/tokens/annotations/submit"
	TokensAnnotationsQuery                = "/tokens/annotations/{annotationId}"

	// User API

	TokensUsersEndpoint = "/tokens/users"
	TokensUsersSubTree  = "/tokens/users/"
	TokensUsersMatch    = "/tokens/users/{userId}"

	// Fungible token type API

	FungibleRoot        = "/tokens/fungible"
	FungibleEndpoint    = FungibleRoot + "/"
	FungibleDeploy      = FungibleRoot + "/deploy"
	FungibleSubmit      = FungibleRoot + "/submit"
	FungibleTypeRoot    = FungibleRoot + "/{typeId}"
	FungibleMint        = FungibleTypeRoot + "/mint-prepare"
	FungibleTransfer    = FungibleTypeRoot + "/transfer-prepare"
	FungibleConsolidate = FungibleTypeRoot + "/consolidate-prepare"
	FungibleAccounts    = FungibleTypeRoot + "/accounts"
)
