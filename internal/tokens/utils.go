// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/copa-europe-tokens/internal/common"
	"github.com/copa-europe-tokens/pkg/types"
	"github.com/golang/protobuf/proto"
	orioncrypto "github.com/hyperledger-labs/orion-server/pkg/crypto"
	"github.com/hyperledger-labs/orion-server/pkg/cryptoservice"
	oriontypes "github.com/hyperledger-labs/orion-server/pkg/types"
	"github.com/pkg/errors"
)

func ComputeSHA256Hash(msgBytes []byte) ([]byte, error) {
	digest := crypto.SHA256.New()
	_, err := digest.Write(msgBytes)
	if err != nil {
		return nil, err
	}
	return digest.Sum(nil), nil
}

func ComputeSHA1Hash(msgBytes []byte) ([]byte, error) {
	digest := crypto.SHA1.New()
	_, err := digest.Write(msgBytes)
	if err != nil {
		return nil, err
	}
	return digest.Sum(nil), nil
}

func ComputeMD5Hash(msgBytes []byte) ([]byte, error) {
	digest := crypto.MD5.New()
	_, err := digest.Write(msgBytes)
	if err != nil {
		return nil, err
	}
	return digest.Sum(nil), nil
}

func NameToID(name string) (string, error) {
	tokenIDBytes, err := ComputeMD5Hash([]byte(name))
	if err != nil {
		return "", errors.Wrap(err, "failed to compute hash of name")
	}
	tokenTypeIDBase64 := base64.RawURLEncoding.EncodeToString(tokenIDBytes)
	return tokenTypeIDBase64, nil
}

func validateMD5Base64ID(tokenTypeId string, tag string) error {
	if tokenTypeId == "" {
		return &ErrInvalid{ErrMsg: fmt.Sprintf("%s ID is empty", tag)}
	}

	if len(tokenTypeId) > base64.RawURLEncoding.EncodedLen(crypto.MD5.Size()) {
		return &ErrInvalid{ErrMsg: fmt.Sprintf("%s ID is too long", tag)}
	}

	if _, err := base64.RawURLEncoding.DecodeString(tokenTypeId); err != nil {
		return &ErrInvalid{ErrMsg: fmt.Sprintf("%s ID is not in base64url", tag)}
	}

	return nil
}

func parseTokenId(tokenId string) (tokenTypeId, assetDataId string, err error) {
	ids := strings.Split(tokenId, ".")
	if len(ids) != 2 {
		return "", "", &ErrInvalid{ErrMsg: "invalid tokenId"}
	}

	if err := validateMD5Base64ID(ids[0], "token type"); err != nil {
		return "", "", err
	}

	if err := validateMD5Base64ID(ids[1], "asset"); err != nil {
		return "", "", err
	}

	return ids[0], ids[1], nil
}

// convertErrorType converts common.TokenHttpErr to the errors types above (to avoid modifying existing code)
func convertErrorType(err error) error {
	tknErr, ok := err.(*common.TokenHttpErr)
	if !ok {
		return err
	}

	switch tknErr.StatusCode {
	case http.StatusConflict:
		return &ErrExist{ErrMsg: tknErr.ErrMsg}
	case http.StatusBadRequest:
		return &ErrInvalid{ErrMsg: tknErr.ErrMsg}
	case http.StatusNotFound:
		return &ErrNotFound{ErrMsg: tknErr.ErrMsg}
	case http.StatusForbidden:
		return &ErrPermission{ErrMsg: tknErr.ErrMsg}
	default:
		return err
	}
}

// ====================================================
// Generic submit helper
// ====================================================

// Detects unauthorized (401) error message
var unauthorizedRegexp = regexp.MustCompile(`(?i)status\s*:\s*401\s*unauthorized`)

// Workaround for issue: missing signature return bad-request (400) instead of unauthorized (401)
var mustSignRegexp = regexp.MustCompile(`(?i)users\s*\[.*]\s*in\s*the\s*must\s*sign\s*list\s*have\s*not\s*signed\s*the\s*transaction`)

type SubmitContext struct {
	TxContext     string
	TxEnvelope    string
	TxPayloadHash string
	Signer        string
	Signature     string
	TxId          string
	TxReceipt     string
}

func submitContextFromNFT(submitRequest *types.SubmitRequest) *SubmitContext {
	return &SubmitContext{
		TxContext:     submitRequest.TokenId,
		TxEnvelope:    submitRequest.TxEnvelope,
		TxPayloadHash: submitRequest.TxPayloadHash,
		Signer:        submitRequest.Signer,
		Signature:     submitRequest.Signature,
	}
}

func submitContextFromFungible(submitRequest *types.FungibleSubmitRequest) *SubmitContext {
	return &SubmitContext{
		TxContext:     submitRequest.TypeId,
		TxEnvelope:    submitRequest.TxEnvelope,
		TxPayloadHash: submitRequest.TxPayloadHash,
		Signer:        submitRequest.Signer,
		Signature:     submitRequest.Signature,
	}
}

func (ctx *SubmitContext) ToNFTResponse() *types.SubmitResponse {
	return &types.SubmitResponse{
		TokenId:   ctx.TxContext,
		TxReceipt: ctx.TxReceipt,
		TxId:      ctx.TxId,
	}
}

func (ctx *SubmitContext) ToFungibleResponse() *types.FungibleSubmitResponse {
	return &types.FungibleSubmitResponse{
		TypeId:    ctx.TxContext,
		TxReceipt: ctx.TxReceipt,
		TxId:      ctx.TxId,
	}
}

func (ctx *SubmitContext) ToNFTRequest() *types.SubmitRequest {
	return &types.SubmitRequest{
		TokenId:       ctx.TxContext,
		TxEnvelope:    ctx.TxEnvelope,
		TxPayloadHash: ctx.TxPayloadHash,
		Signer:        ctx.Signer,
		Signature:     ctx.Signature,
	}
}

func (ctx *SubmitContext) ToFungibleRequest() *types.FungibleSubmitRequest {
	return &types.FungibleSubmitRequest{
		TypeId:        ctx.TxContext,
		TxEnvelope:    ctx.TxEnvelope,
		TxPayloadHash: ctx.TxPayloadHash,
		Signer:        ctx.Signer,
		Signature:     ctx.Signature,
	}
}

// =========================================================
// Generic submit helpers for manager and server testing
// =========================================================

type SignatureRequester interface {
	PrepareSubmit() *SubmitContext
}

func SignTransactionResponse(s orioncrypto.Signer, response SignatureRequester) (*SubmitContext, error) {
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

type MintResponse types.MintResponse
type TransferResponse types.TransferResponse
type FungibleMintResponse types.FungibleMintResponse
type FungibleTransferResponse types.FungibleTransferResponse
type FungibleConsolidateResponse types.FungibleConsolidateResponse

func (r *MintResponse) PrepareSubmit() *SubmitContext {
	return &SubmitContext{
		TxContext:     r.TokenId,
		TxEnvelope:    r.TxEnvelope,
		TxPayloadHash: r.TxPayloadHash,
	}
}

func (r *TransferResponse) PrepareSubmit() *SubmitContext {
	return &SubmitContext{
		TxContext:     r.TokenId,
		TxEnvelope:    r.TxEnvelope,
		TxPayloadHash: r.TxPayloadHash,
	}
}

func (r *FungibleMintResponse) PrepareSubmit() *SubmitContext {
	return &SubmitContext{
		TxContext:     r.TypeId,
		TxEnvelope:    r.TxEnvelope,
		TxPayloadHash: r.TxPayloadHash,
	}
}

func (r *FungibleTransferResponse) PrepareSubmit() *SubmitContext {
	return &SubmitContext{
		TxContext:     r.TypeId,
		TxEnvelope:    r.TxEnvelope,
		TxPayloadHash: r.TxPayloadHash,
	}
}

func (r *FungibleConsolidateResponse) PrepareSubmit() *SubmitContext {
	return &SubmitContext{
		TxContext:     r.TypeId,
		TxEnvelope:    r.TxEnvelope,
		TxPayloadHash: r.TxPayloadHash,
	}
}
