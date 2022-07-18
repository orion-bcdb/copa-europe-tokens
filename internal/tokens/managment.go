// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"fmt"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
	"hash/crc32"
	"strings"
)

func nodeConfigToString(n *oriontypes.NodeConfig) string {
	return fmt.Sprintf("Id: %s, Address: %s, Port: %d, Cert-hash: %x", n.Id, n.Address, n.Port, crc32.ChecksumIEEE(n.Certificate))
}

func (m *Manager) Close() error {
	//TODO
	return nil
}

func (m *Manager) GetStatus() (string, error) {
	tx, err := m.adminSession.ConfigTx()
	if err != nil {
		return "", errors.Wrap(err, "failed to get status")
	}
	clusterConfig, err := tx.GetClusterConfig()
	if err != nil {
		return "", errors.Wrap(err, "failed to get status")
	}

	b := strings.Builder{}
	b.WriteString("{")
	for i, n := range clusterConfig.Nodes {
		b.WriteString(nodeConfigToString(n))
		if i < len(clusterConfig.Nodes)-1 {
			b.WriteString("; ")
		}
	}
	b.WriteString("}")
	return fmt.Sprintf("connected: %s", b.String()), nil
}
