// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"github.com/copa-europe-tokens/internal/common"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/pkg/errors"
)

// TokenTypeTxContext handles a token transaction from start to finish
type TokenTypeTxContext struct {
	DbTxContext
	typeId string

	// Evaluated lazily
	description *types.TokenDescription
}

func getTokenTypeDBName(typeId string) (string, error) {
	if err := validateMD5Base64ID(typeId, "token type"); err != nil {
		return "", common.NewErrInvalid("Invalid type ID: %s", err)
	}
	return TokenTypeDBNamePrefix + typeId, nil
}

func (ctx *TokenTypeTxContext) getDescription() (*types.TokenDescription, error) {
	if ctx.description != nil {
		return ctx.description, nil
	}

	// We create a detached transaction since other users don't have read permissions to the types DB
	descCtx := ctx.detach().db(TypesDBName)
	defer descCtx.Abort()

	desc := &types.TokenDescription{}
	existed, err := descCtx.GetMarshal(ctx.dbName, desc)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, common.NewErrNotFound("token type not found")
	}

	ctx.description = desc
	return desc, nil
}

func (ctx *TokenTypeTxContext) validateTokenType(expectedClass string, tag string) error {
	desc, err := ctx.getDescription()
	if err != nil {
		return err
	}
	if desc == nil {
		return common.NewErrInvalid("%s token type does not exist.", tag)
	}
	if desc.Class != expectedClass {
		return common.NewErrInvalid("%s token type must be %s.", tag, expectedClass)
	}
	return nil
}

type TokenTxContext struct {
	TokenTypeTxContext
	assetData string
	tokenId   string
	assetId   string
}

func (ctx *TokenTypeTxContext) asset(assetData string) (*TokenTxContext, error) {
	if assetData == "" {
		return nil, common.NewErrInvalid("missing asset data")
	}

	assetId, err := NameToID(assetData)
	if err != nil {
		return nil, err
	}
	return &TokenTxContext{
		TokenTypeTxContext: *ctx,
		assetData:          assetData,
		assetId:            assetId,
		tokenId:            ctx.typeId + TokenDBSeparator + assetId,
	}, nil
}

func (ctx *TokenTxContext) GetToken() (*types.TokenRecord, error) {
	record := &types.TokenRecord{}
	existed, err := ctx.GetMarshal(ctx.assetId, record)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, common.NewErrNotFound("Key [%s] was not found in DB [%s]", ctx.assetId, ctx.dbName)
	}
	ctx.lg.Debugf("Token record: %v", record)
	if ctx.assetData == "" {
		ctx.assetData = record.AssetData
	}
	return record, nil
}

func (ctx *TokenTxContext) mint(owner, meta, link string) (*types.TokenRecord, error) {
	err := ctx.validateUserId(owner)
	if err != nil {
		return nil, err
	}

	val, existed, err := ctx.Get(ctx.assetId)
	if err != nil {
		return nil, err
	}
	if existed {
		ctx.lg.Debugf("token already exists: DB: %s, assetId: %s, record: %s", ctx.dbName, ctx.tokenId, string(val))
		return nil, common.NewErrExist("token already exists")
	}

	record := &types.TokenRecord{
		Owner:         owner,
		AssetDataId:   ctx.assetId,
		AssetData:     ctx.assetData,
		AssetMetadata: meta,
		Link:          link,
	}
	if err = ctx.PutMarshal(ctx.assetId, record, owner, true); err != nil {
		return nil, errors.Wrap(err, "failed to Put")
	}
	return record, nil
}
