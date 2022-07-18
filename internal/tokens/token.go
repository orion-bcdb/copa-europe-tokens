// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"encoding/base64"
	"encoding/json"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger-labs/orion-sdk-go/pkg/bcdb"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
	"regexp"
)

// Detects unauthorized (401) error message
var unauthorizedRegexp = regexp.MustCompile(`(?i)status\s*:\s*401\s*unauthorized`)

// Workaround for issue: missing signature return bad-request (400) instead of unauthorized (401)
var mustSignRegexp = regexp.MustCompile(`(?i)users\s*\[.*]\s*in\s*the\s*must\s*sign\s*list\s*have\s*not\s*signed\s*the\s*transaction`)

// ====================================================
// Generic token type functional API implementation
// ====================================================

func (m *Manager) GetTokenType(tokenTypeId string) (map[string]string, error) {
	ctx, err := m.newTokenContext(tokenTypeId)
	if err != nil {
		return nil, err
	}

	tokenDesc := map[string]string{}
	if err = ctx.getTokenDescription(&tokenDesc); err != nil {
		return nil, err
	}

	tokenDesc["url"] = constants.TokensTypesSubTree + ctx.typeId
	return tokenDesc, nil
}

func (m *Manager) GetTokenTypes() ([]map[string]string, error) {
	jq, err := m.custodianSession.Query()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create JSONQuery")
	}

	query := `{"selector": {"typeId": {"$lte": "~"}}}` //base64 chars are always smaller
	results, err := jq.ExecuteJSONQuery(TypesDBName, query)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute JSONQuery")
	}

	var records []map[string]string
	for _, res := range results {
		tokenDesc := map[string]string{}
		err = json.Unmarshal(res.GetValue(), &tokenDesc)
		if err != nil {
			return nil, errors.Wrap(err, "failed to json.Unmarshal JSONQuery result")
		}
		tokenDesc["url"] = constants.TokensTypesSubTree + tokenDesc["typeId"]
		records = append(records, tokenDesc)
	}

	return records, nil
}

func (m *Manager) SubmitTx(submitRequest *types.SubmitRequest) (*types.SubmitResponse, error) {
	m.lg.Infof("Custodian [%s] preparing to submit TX to the database, context: %s, signer: %s",
		m.config.Users.Custodian.UserID, submitRequest.TxContext, submitRequest.Signer)

	txEnvBytes, err := base64.StdEncoding.DecodeString(submitRequest.TxEnvelope)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode TxEnvelope")
	}

	txEnv := &oriontypes.DataTxEnvelope{}
	err = proto.Unmarshal(txEnvBytes, txEnv)
	if err != nil {
		return nil, errors.Wrap(err, "failed to proto.Unmarshal TxEnvelope")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(submitRequest.Signature)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode Signature")
	}

	txEnv.Signatures[submitRequest.Signer] = sigBytes
	loadedTx, err := m.custodianSession.LoadDataTx(txEnv)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load tx envelope")
	}

	m.lg.Debugf("signed signers: %+v", loadedTx.SignedUsers())

	txID, receiptEnv, err := loadedTx.Commit(true)
	if err != nil {
		if unauthorizedRegexp.FindStringIndex(err.Error()) != nil {
			return nil, WrapErrPermission(err)
		}

		if mustSignRegexp.FindStringIndex(err.Error()) != nil {
			return nil, WrapErrPermission(err)
		}

		if errV, ok := err.(*bcdb.ErrorTxValidation); ok {
			switch oriontypes.Flag_value[errV.Flag] {
			case int32(oriontypes.Flag_INVALID_NO_PERMISSION), int32(oriontypes.Flag_INVALID_UNAUTHORISED), int32(oriontypes.Flag_INVALID_MISSING_SIGNATURE):
				return nil, WrapErrPermission(err)
			default:
				return nil, WrapErrInvalid(err)
			}
		}

		return nil, err
	}

	m.lg.Infof("Custodian [%s] committed the Tx to the database, txID: %s, receipt: %+v", m.config.Users.Custodian.UserID, txID, receiptEnv.GetResponse().GetReceipt())

	receiptBytes, err := proto.Marshal(receiptEnv)

	return &types.SubmitResponse{
		TxId:      txID,
		TxReceipt: base64.StdEncoding.EncodeToString(receiptBytes),
		TxContext: submitRequest.TxContext,
	}, nil
}
