// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"encoding/json"
	"fmt"
	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
)

type AssetTokenDBTxContext struct {
	TokenContext
	desc CommonTokenDescription
}

func (m *Manager) newAssetContext(typeId string) (*AssetTokenDBTxContext, error) {
	genericCtx, err := m.newTokenContextTx(typeId)
	if err != nil {
		return nil, err
	}
	ctx := AssetTokenDBTxContext{
		TokenContext: *genericCtx,
	}

	err = ctx.getTokenDescription(&ctx.desc)
	if err != nil {
		return nil, err
	}

	if ctx.desc.Class != constants.TokenClass_NFT && ctx.desc.Class != constants.TokenClass_ANNOTATIONS {
		return nil, NewErrInvalid("Type %v is not a fungible token.", typeId)
	}

	return &ctx, nil
}

func (m *Manager) newAssetContextTx(typeId string) (*AssetTokenDBTxContext, error) {
	ctx, err := m.newAssetContext(typeId)
	if err != nil {
		return nil, err
	}
	return ctx, ctx.initTx()
}

// ====================================================
// NFT functional API implementation
// ====================================================

func (m *Manager) DeployTokenType(deployRequest *types.DeployRequest) (*types.DeployResponse, error) {
	switch deployRequest.Class {
	case "": //backward compatibility
		deployRequest.Class = constants.TokenClass_NFT
	case constants.TokenClass_NFT:
	case constants.TokenClass_FUNGIBLE:
	case constants.TokenClass_ANNOTATIONS:
	default:
		return nil, NewErrInvalid("unsupported token class: %s", deployRequest.Class)
	}

	var indices []string
	switch deployRequest.Class {
	case constants.TokenClass_NFT:
		indices = []string{"owner"}
	case constants.TokenClass_FUNGIBLE:
		return nil, NewErrInvalid("Class is not supported via this API call: %s", deployRequest.Class)
	case constants.TokenClass_ANNOTATIONS:
		indices = []string{"owner", "link"}
	default:
		return nil, NewErrInvalid("unsupported token class: %s", deployRequest.Class)
	}

	tokenDesc := CommonTokenDescription{
		Name:        deployRequest.Name,
		Description: deployRequest.Description,
		Class:       deployRequest.Class,
	}

	err := m.deployNewTokenType(&tokenDesc, indices...)
	if err != nil {
		return nil, err
	}

	return &types.DeployResponse{
		TypeId:      tokenDesc.TypeId,
		Name:        tokenDesc.Name,
		Class:       tokenDesc.Class,
		Description: tokenDesc.Description,
		Url:         constants.TokensTypesSubTree + tokenDesc.TypeId,
	}, nil
}

func (m *Manager) PrepareMint(tokenTypeId string, mintRequest *types.MintRequest) (*types.MintResponse, error) {
	ctx, err := m.newAssetContext(tokenTypeId)
	if err != nil {
		return nil, err
	}
	defer ctx.abort()

	if err := m.validateUserExists(mintRequest.Owner); err != nil {
		return nil, err
	}

	if mintRequest.AssetData == "" {
		return nil, NewErrInvalid("missing asset data")
	}

	assetDataId, err := NameToID(mintRequest.AssetData)
	if err != nil {
		return nil, err
	}

	if err = ctx.initTx(); err != nil {
		return nil, err
	}

	val, meta, err := ctx.dataTx.Get(ctx.tokenDBName, assetDataId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to Get %s", ctx.tokenDBName)
	}
	if val != nil {
		m.lg.Debugf("token already exists: DB: %s, assetId: %s, record: %s, meta: %+v", ctx.tokenDBName, assetDataId, string(val), meta)
		return nil, NewErrExist("token already exists")
	}

	record := &types.TokenRecord{
		AssetDataId:   assetDataId,
		Owner:         mintRequest.Owner,
		AssetData:     mintRequest.AssetData,
		AssetMetadata: mintRequest.AssetMetadata,
	}

	val, err = json.Marshal(record)
	if err != nil {
		return nil, errors.Wrap(err, "failed to json.Marshal record")
	}

	err = ctx.dataTx.Put(ctx.tokenDBName, assetDataId, val,
		&oriontypes.AccessControl{
			ReadWriteUsers: map[string]bool{
				m.config.Users.Custodian.UserID: true,
				mintRequest.Owner:               true,
			},
			SignPolicyForWrite: oriontypes.AccessControl_ALL,
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to Put")
	}

	ctx.dataTx.AddMustSignUser(mintRequest.Owner)

	env, err := ctx.prepare()

	m.lg.Debugf("Received mint request for token: %+v", record)

	mintResponse := &types.MintResponse{
		TokenId:       tokenTypeId + "." + assetDataId,
		Owner:         mintRequest.Owner,
		TxEnvelope:    env.TxEnvelope,
		TxPayloadHash: env.TxPayloadHash,
	}

	return mintResponse, nil
}

func (m *Manager) PrepareTransfer(tokenId string, transferRequest *types.TransferRequest) (*types.TransferResponse, error) {
	m.lg.Debugf("Received transfer request: %+v, for tokenId: %s", transferRequest, tokenId)

	if err := m.validateUserExists(transferRequest.Owner); err != nil {
		return nil, err
	}
	if err := m.validateUserId(transferRequest.NewOwner); err != nil {
		return nil, err
	}

	tokenTypeId, assetId, err := parseTokenId(tokenId)
	if err != nil {
		return nil, err
	}

	ctx, err := m.newAssetContextTx(tokenTypeId)
	if err != nil {
		return nil, err
	}
	defer ctx.abort()

	if _, ok := m.tokenTypesDBs[ctx.tokenDBName]; !ok {
		return nil, NewErrNotFound("token type not found: %s", tokenTypeId)
	}

	val, meta, err := ctx.dataTx.Get(ctx.tokenDBName, assetId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to Get %s", ctx.tokenDBName)
	}
	if val == nil {
		return nil, NewErrNotFound("token not found: %s", tokenId)
	}

	record := &types.TokenRecord{}
	err = json.Unmarshal(val, record)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to json.Unmarshal %v", val)
	}

	if transferRequest.Owner != record.Owner {
		return nil, NewErrPermission("not owner: %s", transferRequest.Owner)
	}

	m.lg.Debugf("Token: %+v; meta: %+v", record, meta)

	record.Owner = transferRequest.NewOwner
	recordBytes, err := json.Marshal(record)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to json.Marshal %v", record)
	}

	acl := &oriontypes.AccessControl{
		ReadWriteUsers: map[string]bool{
			m.config.Users.Custodian.UserID: true,
			transferRequest.NewOwner:        true,
		},
		SignPolicyForWrite: oriontypes.AccessControl_ALL,
	}

	err = ctx.dataTx.Put(ctx.tokenDBName, assetId, recordBytes, acl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to Put")
	}

	env, err := ctx.prepare()
	if err != nil {
		return nil, err
	}

	transferResponse := &types.TransferResponse{
		TokenId:       tokenId,
		Owner:         transferRequest.Owner,
		NewOwner:      transferRequest.NewOwner,
		TxEnvelope:    env.TxEnvelope,
		TxPayloadHash: env.TxPayloadHash,
	}

	return transferResponse, nil
}

func (m *Manager) GetToken(tokenId string) (*types.TokenRecord, error) {
	tokenTypeId, assetId, err := parseTokenId(tokenId)
	if err != nil {
		return nil, err
	}

	dataTx, err := m.custodianSession.DataTx()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create DataTx")
	}
	defer abort(dataTx)

	tokenDBName, err := getTokenTypeDBName(tokenTypeId)
	if err != nil {
		return nil, err
	}

	if _, ok := m.tokenTypesDBs[tokenDBName]; !ok {
		return nil, NewErrNotFound("token type not found: %s", tokenTypeId)
	}

	val, meta, err := dataTx.Get(tokenDBName, assetId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to Get %s", tokenDBName)
	}
	if val == nil {
		return nil, NewErrNotFound("token not found")
	}

	record := &types.TokenRecord{}
	err = json.Unmarshal(val, record)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to json.Unmarshal %v", val)
	}

	m.lg.Debugf("Token record: %v; metadata: %+v", record, meta)

	return record, nil
}

func (m *Manager) GetTokensByOwner(tokenTypeId string, owner string) ([]*types.TokenRecord, error) {
	if tokenTypeId == "" {
		return nil, NewErrInvalid("missing typeId")
	}

	if owner == "" {
		return nil, NewErrInvalid("missing owner")
	}

	tokenDBName, err := getTokenTypeDBName(tokenTypeId)
	if err != nil {
		return nil, err
	}

	if _, ok := m.tokenTypesDBs[tokenDBName]; !ok {
		return nil, NewErrNotFound("token type not found: %s", tokenTypeId)
	}

	jq, err := m.custodianSession.Query()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create JSONQuery")
	}

	query := fmt.Sprintf(`{"selector": {"owner": {"$eq": "%s"}}}`, owner)
	results, err := jq.ExecuteJSONQuery(tokenDBName, query)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute JSONQuery")
	}

	var records []*types.TokenRecord
	for _, res := range results {
		record := &types.TokenRecord{}
		err = json.Unmarshal(res.GetValue(), record)
		if err != nil {
			return nil, errors.Wrap(err, "failed to json.Unmarshal JSONQuery result")
		}
		records = append(records, record)
	}

	return records, nil
}
