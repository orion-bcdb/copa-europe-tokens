// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto"
	"encoding/base64"

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
		return "", errors.Wrap(err, "failed to compute hash of token type name")
	}
	tokenTypeIDBase64 := base64.RawURLEncoding.EncodeToString(tokenIDBytes)
	return tokenTypeIDBase64, nil
}
