// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

func ComputeSHA256Hash(msgBytes []byte) ([]byte, error) {
	digest := crypto.SHA256.New()
	_, err := digest.Write(msgBytes)
	if err != nil {
		return nil, err
	}
	return digest.Sum(nil), nil
}

func ComputeSHA1Hash(msgBytes []byte) ([]byte, error) {
	digest := crypto.SHA1.New()
	_, err := digest.Write(msgBytes)
	if err != nil {
		return nil, err
	}
	return digest.Sum(nil), nil
}

func ComputeMD5Hash(msgBytes []byte) ([]byte, error) {
	digest := crypto.MD5.New()
	_, err := digest.Write(msgBytes)
	if err != nil {
		return nil, err
	}
	return digest.Sum(nil), nil
}

func NameToID(name string) (string, error) {
	tokenIDBytes, err := ComputeMD5Hash([]byte(name))
	if err != nil {
		return "", errors.Wrap(err, "failed to compute hash of name")
	}
	tokenTypeIDBase64 := base64.RawURLEncoding.EncodeToString(tokenIDBytes)
	return tokenTypeIDBase64, nil
}

func validateMD5Base64ID(tokenTypeId string, tag string) error {
	if tokenTypeId == "" {
		return &ErrInvalid{ErrMsg: fmt.Sprintf("%s ID is empty", tag)}
	}

	if len(tokenTypeId) > base64.RawURLEncoding.EncodedLen(crypto.MD5.Size()) {
		return &ErrInvalid{ErrMsg: fmt.Sprintf("%s ID is too long", tag)}
	}

	if _, err := base64.RawURLEncoding.DecodeString(tokenTypeId); err != nil {
		return &ErrInvalid{ErrMsg: fmt.Sprintf("%s ID is not in base64url", tag)}
	}

	return nil
}

func parseTokenId(tokenId string) (tokenTypeId, assetDataId string, err error) {
	ids := strings.Split(tokenId, ".")
	if len(ids) != 2 {
		return "", "", &ErrInvalid{ErrMsg: "invalid tokenId"}
	}

	if err := validateMD5Base64ID(ids[0], "token type"); err != nil {
		return "", "", err
	}

	if err := validateMD5Base64ID(ids[1], "asset"); err != nil {
		return "", "", err
	}

	return ids[0], ids[1], nil
}
