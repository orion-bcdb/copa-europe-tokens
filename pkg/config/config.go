// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path"
	"time"

	"github.com/hyperledger-labs/orion-sdk-go/pkg/config"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	defaultLocalConfigFile = "config.yml"
)

type Configuration struct {
	// The network interface and port used to serve client requests.
	Network NetworkConf
	// TLS configuration of incoming connections.
	TLS TLSConf
	// Server logging level.
	LogLevel string
	// The Orion cluster settings.
	Orion OrionConf
	// Local users.
	Users UsersConf
	// Session parameters.
	Session SessionConf
}

// NetworkConf holds the listen address and port of an endpoint.
// See `net.Listen(network, address string)`. The `address` parameter will be the `Address`:`Port` defined below.
type NetworkConf struct {
	Address string
	Port    uint32
}

// TLSConf holds TLS configuration settings.
type TLSConf struct {
	// Require server-side TLS.
	Enabled bool
	// Require client certificates / mutual TLS for inbound connections.
	ClientAuthRequired bool
	// X.509 certificate used for TLS server
	ServerCertificatePath string
	// Private key for TLS server
	ServerKeyPath string
	// X.509 certificate used for creating TLS client connections.
	ClientCertificatePath string
	// Private key used for creating TLS client connections.
	ClientKeyPath string
	// The paths to the x509 certificates of the root and intermediate certificate authorities that issued
	// all the tls certificates.
	CaConfig CAConf
}

// CAConf holds the path to the x509 certificates of the certificate authorities who issues all certificates.
type CAConf struct {
	RootCACertsPath         []string
	IntermediateCACertsPath []string
}

type OrionConf struct {
	// A set of cluster replicas
	Replicas []*config.Replica
	// CAs that are used to issue all the signing keys & certificates.
	CaConfig CAConf
}

type UsersConf struct {
	Admin     config.UserConfig
	Custodian config.UserConfig
}

type SessionConf struct {
	// The transaction timeout given to the database server in case of tx sync commit.
	TxTimeout time.Duration
	// The query timeout - SDK will wait for query result maximum `QueryTimeout` time.
	QueryTimeout time.Duration
}

// Read reads configurations from the config file and returns the config
func Read(configFilePath string) (*Configuration, error) {
	if configFilePath == "" {
		return nil, errors.New("path to the configuration file is empty")
	}

	fileInfo, err := os.Stat(configFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read the status of the configuration path: '%s'", configFilePath)
	}

	fileName := configFilePath
	if fileInfo.IsDir() {
		fileName = path.Join(configFilePath, defaultLocalConfigFile)
	}

	conf, err := readLocalConfig(fileName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read the configuration from: '%s'", fileName)
	}

	return conf, nil
}

func readLocalConfig(localConfigFile string) (*Configuration, error) {
	if localConfigFile == "" {
		return nil, errors.New("path to the configuration file is empty")
	}

	v := viper.New()
	v.SetConfigFile(localConfigFile)

	if err := v.ReadInConfig(); err != nil {
		return nil, errors.Wrap(err, "error reading config file")
	}

	conf := &Configuration{}
	if err := v.UnmarshalExact(conf); err != nil {
		return nil, errors.Wrapf(err, "unable to unmarshal config file: '%s' into struct", localConfigFile)
	}

	return conf, nil
}
