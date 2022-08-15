// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"encoding/base64"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger-labs/orion-server/pkg/crypto"
	"github.com/hyperledger-labs/orion-server/pkg/cryptoservice"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
)

// SignatureRequester All response types that require to submit a signature, should implement this interface
type SignatureRequester interface {
	PrepareSubmit() *types.TokenSubmitRequest
}

func SignTransactionResponse(s crypto.Signer, response SignatureRequester) (*types.TokenSubmitRequest, error) {
	request := response.PrepareSubmit()
	txEnvBytes, err := base64.StdEncoding.DecodeString(request.TxEnvelope)
	if err != nil {
		return nil, err
	}

	txEnv := &oriontypes.DataTxEnvelope{}
	err = proto.Unmarshal(txEnvBytes, txEnv)
	if err != nil {
		return nil, err
	}

	sig, err := cryptoservice.SignTx(s, txEnv.Payload)
	if err != nil {
		return nil, err
	}

	request.Signer = s.Identity()
	request.Signature = base64.StdEncoding.EncodeToString(sig)

	return request, nil
}
