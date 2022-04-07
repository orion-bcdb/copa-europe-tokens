// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package constants

const (
	StatusEndpoint = "/status"

	TokensTypesEndpoint = "/tokens/types"
	TokensTypesSubTree  = "/tokens/types/"
	TokensTypesQuery    = "/tokens/types/{typeId}"

	TokensAssetsEndpoint             = "/tokens/assets"
	TokensAssetsSubTree              = "/tokens/assets/"
	TokensAssetsPrepareMint          = "/tokens/assets/prepare-mint/"
	TokensAssetsPrepareMintMatch     = "/tokens/assets/prepare-mint/{typeId}"
	TokensAssetsPrepareTransfer      = "/tokens/assets/prepare-transfer/"
	TokensAssetsPrepareTransferMatch = "/tokens/assets/prepare-transfer/{tokenId}"
	TokensAssetsSubmit               = "/tokens/assets/submit"
	TokensAssetsQuery                = "/tokens/assets/{tokenId}"

	TokensUsersEndpoint = "/tokens/users"
	TokensUsersSubTree  = "/tokens/users/"
	TokensUsersMatch    = "/tokens/users/{userId}"
)
