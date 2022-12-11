// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import "strings"

func URLForType(path string, typeId string) string {
	return strings.Replace(path, "{typeId}", typeId, 1)
}

func URLForOffer(path string, typeId string) string {
	return strings.Replace(path, "{offerId}", typeId, 1)
}
