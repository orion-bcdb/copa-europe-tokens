// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"github.com/copa-europe-tokens/pkg/config"
	"github.com/pkg/errors"
)

type TokensServer struct {
}

func NewTokensServer(conf *config.Configuration) (*TokensServer, error) {
	//TODO bla
	return nil, errors.New("not implemented yet")
}

func (s *TokensServer) Start() error {
	//TODO
	return errors.New("not implemented yet")
}
