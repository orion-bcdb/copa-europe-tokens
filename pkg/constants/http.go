// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package constants

const (
	StatusEndpoint = "/status"
	TokensEndpoint = "/tokens"

	TokensTypesEndpoint = "/tokens/types"
	TokensTypesQuery    = "/tokens/types/{typeId}"

	TokensAssetsEndpoint        = "/tokens/assets"
	TokensAssetsPrepareMint     = "/tokens/assets/prepare-mint/{typeId}"
	TokensAssetsPrepareTransfer = "/tokens/assets/prepare-transfer/{typeId}"
	TokensAssetsSubmit          = "/tokens/assets/submit"
	TokensAssetsQuery           = "/tokens/assets/{assetId}"
)
