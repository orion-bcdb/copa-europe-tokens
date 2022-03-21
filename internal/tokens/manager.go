package tokens

import (
	"github.com/copa-europe-tokens/pkg/config"
	"github.com/hyperledger-labs/orion-server/pkg/logger"
)

type Manager struct {
	config *config.Configuration
	lg     *logger.SugarLogger
}

func NewManager(config *config.Configuration, lg *logger.SugarLogger) (*Manager, error) {

	//TODO validate the config, load keys and certs

	m := &Manager{
		config: config,
		lg:     lg,
	}
	return m, nil
}

func (m *Manager) Close() error {
	//TODO
	return nil
}
