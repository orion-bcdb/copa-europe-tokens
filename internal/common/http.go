// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import "strings"

func URLForType(path string, typeId string) string {
	return strings.Replace(path, "{typeId}", typeId, 1)
}

func URLForToken(path string, tokenId string) string {
	return strings.Replace(path, "{tokenId}", tokenId, 1)
}

func URLForOffer(path string, offerId string) string {
	return strings.Replace(path, "{offerId}", offerId, 1)
}
