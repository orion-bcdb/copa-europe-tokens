// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"
)

// Signer is cryptographic primitive used only to sign messages. Each entity usually access single Signer
type Signer interface {
	Sign(msgBytes []byte) ([]byte, error)
	ComputeSHA256Hash(msgBytes []byte) ([]byte, error)
	SignHash(hashBytes []byte) ([]byte, error)
	Identity() string
}

type signer struct {
	singer   *ecdsa.PrivateKey
	identity string
}

// LoadPrivateKey key and returns instance, supports SEC1 EC and PKCS#8
// Based on crypto/tls/tls.go
func LoadPrivateKey(keyPEMBlock []byte) (crypto.PrivateKey, error) {
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			return nil, fmt.Errorf("failed to find private key block in pem file")
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
	}

	// OpenSSL 1.0.0 generates PKCS#8 keys.
	if key, err := x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes); err == nil {
		switch key := key.(type) {
		// Supports ECDSA at the moment.
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("found unknown private key type (%T) in PKCS#8 wrapping", key)
		}
	}

	// OpenSSL ecparam generates SEC1 EC private keys for ECDSA.
	key, err := x509.ParseECPrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return key, nil
}

func NewSigner(identity string, keyFilePath string) (Signer, error) {
	keyPEMBlock, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}

	key, err := LoadPrivateKey(keyPEMBlock)
	if err != nil {
		return nil, err
	}
	return &signer{
		singer:   key.(*ecdsa.PrivateKey),
		identity: identity,
	}, nil
}

func (s *signer) Sign(msgBytes []byte) ([]byte, error) {
	h, err := s.ComputeSHA256Hash(msgBytes)
	if err != nil {
		return nil, err
	}

	return s.singer.Sign(rand.Reader, h, crypto.SHA256)
}

func (s *signer) SignHash(hashBytes []byte) ([]byte, error) {
	return s.singer.Sign(rand.Reader, hashBytes, crypto.SHA256)
}

func (s *signer) Identity() string {
	return s.identity
}

func (_ *signer) ComputeSHA256Hash(msgBytes []byte) ([]byte, error) {
	digest := crypto.SHA256.New()
	_, err := digest.Write(msgBytes)
	if err != nil {
		return nil, err
	}
	return digest.Sum(nil), nil
}
