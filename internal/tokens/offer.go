// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"github.com/copa-europe-tokens/internal/common"
	"github.com/copa-europe-tokens/pkg/types"
)

type OfferTypeTxContext struct {
	TokenTypeTxContext
}

type OfferTxContext struct {
	TokenTxContext
}

func (ctx *OfferTypeTxContext) offerName(offerName string) (*OfferTxContext, error) {
	newCtx, err := ctx.asset(offerName)
	if err != nil {
		return nil, err
	}
	return &OfferTxContext{*newCtx}, nil
}

func (ctx *OfferTxContext) putOfferRecord(record *types.RightsOfferRecord) error {
	record.OfferId = ctx.tokenId
	return ctx.PutAssetMarshal(record, record.Owner, true)
}

func (ctx *OfferTxContext) getOfferRecord() (*types.RightsOfferRecord, error) {
	record := &types.RightsOfferRecord{}
	existed, err := ctx.GetAssetMarshal(record)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, common.NewErrNotFound("Offer [%s] was not found", ctx.tokenId)
	}
	return record, nil
}
