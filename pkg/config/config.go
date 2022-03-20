// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	defaultLocalConfigFile = "config.yml"
)

type Configuration struct {
	// The network interface and port used to serve client requests.
	Network NetworkConf
	// Server logging level.
	LogLevel string
}


// NetworkConf holds the listen address and port of an endpoint.
// See `net.Listen(network, address string)`. The `address` parameter will be the `Address`:`Port` defined below.
type NetworkConf struct {
	Address string
	Port    uint32
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
