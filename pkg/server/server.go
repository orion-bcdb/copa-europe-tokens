// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net"
	"net/http"

	"github.com/copa-europe-tokens/internal/httphandlers"
	"github.com/copa-europe-tokens/internal/tokens"
	"github.com/copa-europe-tokens/pkg/config"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
	"github.com/pkg/errors"
)

type TokensServer struct {
	lg           *logger.SugarLogger
	tokenManager *tokens.Manager
	handler      http.Handler
	listen       net.Listener
	server       *http.Server
	conf         *config.Configuration
}

func NewTokensServer(conf *config.Configuration, lg *logger.SugarLogger) (*TokensServer, error) {
	tokenManager, err := tokens.NewManager(conf, lg)
	if err != nil {
		return nil, errors.Wrap(err, "error while creating the tokens manager object")
	}

	mux := http.NewServeMux()

	mux.Handle(constants.StatusEndpoint, httphandlers.NewStatusHandler(tokenManager, lg))
	mux.Handle(constants.TokensTypesEndpoint, httphandlers.NewDeployHandler(tokenManager, lg))
	mux.Handle(constants.TokensTypesSubTree, httphandlers.NewDeployHandler(tokenManager, lg))
	mux.Handle(constants.TokensAssetsSubTree, httphandlers.NewAssetsHandler(tokenManager, lg))
	mux.Handle(constants.TokensUsersEndpoint, httphandlers.NewUserHandler(tokenManager, lg))
	mux.Handle(constants.TokensUsersSubTree, httphandlers.NewUserHandler(tokenManager, lg))

	netConf := conf.Network
	addr := fmt.Sprintf("%s:%d", netConf.Address, netConf.Port)

	netListener, err := net.Listen("tcp", addr)
	if err != nil {
		lg.Errorf("Failed to create a tcp listener on: %s, error: %s", addr, err)
		return nil, errors.Wrapf(err, "error while creating a tcp listener on: %s", addr)
	}

	server := &http.Server{
		Handler: mux,
	}

	if conf.TLS.Enabled {
		// TODO support TLS
		return nil, errors.New("TLS on incoming connections is not yet supported")
	}

	return &TokensServer{
		tokenManager: tokenManager,
		handler:      mux,
		listen:       netListener,
		server:       server,
		conf:         conf,
		lg:           lg,
	}, nil
}

// Start starts the server
func (s *TokensServer) Start() error {

	// TODO Check connectivity to db

	s.lg.Info("Server starting")

	go s.serveRequests(s.listen)

	return nil
}

func (s *TokensServer) serveRequests(l net.Listener) {
	s.lg.Infof("Starting to serve requests on: %s", s.listen.Addr().String())

	var err error
	if s.conf.TLS.Enabled {
		err = s.server.ServeTLS(l, "", "")
	} else {
		err = s.server.Serve(l)
	}

	if err == http.ErrServerClosed {
		s.lg.Infof("Server stopped: %s", err)
	} else {
		s.lg.Panicf("server stopped unexpectedly, %v", err)
	}

	s.lg.Infof("Finished serving requests on: %s", s.listen.Addr().String())
}

// Stop stops the server
func (s *TokensServer) Stop() error {
	if s == nil || s.listen == nil || s.server == nil {
		return nil
	}

	var errR error

	s.lg.Infof("Stopping the server listening on: %s\n", s.listen.Addr().String())
	if err := s.server.Close(); err != nil {
		s.lg.Errorf("Failure while closing the http server: %s", err)
		errR = err
	}

	if err := s.tokenManager.Close(); err != nil {
		s.lg.Errorf("Failure while closing the database: %s", err)
		errR = err
	}
	return errR
}

// Port returns port number server allocated to run on
func (s *TokensServer) Port() (port string, err error) {
	_, port, err = net.SplitHostPort(s.listen.Addr().String())
	return
}
