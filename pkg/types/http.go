// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// HttpResponseErr holds an error message. It is used as the body of an http error response.
type HttpResponseErr struct {
	ErrMsg string `json:"error"`
}

func (e *HttpResponseErr) Error() string {
	return e.ErrMsg
}

type StatusResponse struct {
	Status string `json:"status"`
}

type DeployRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type DeployResponse struct {
	TypeId      string `json:"typeId"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Url         string `json:"url"`
}

type MintRequest struct {
	Owner         string `json:"owner"`
	AssetData     string `json:"assetData"`
	AssetMetadata string `json:"assetMetadata"`
}

type MintResponse struct {
	TokenId       string `json:"tokenId"`
	Owner         string `json:"owner"`
	TxPayload     string `json:"txPayload"`
	TxPayloadHash string `json:"txPayloadHash"`
}

type SubmitRequest struct {
	TokenId       string `json:"TokenId"`
	TxPayload     string `json:"txPayload"`
	TxPayloadHash string `json:"txPayloadHash"`
	Signer        string `json:"signer"`
	Signature     string `json:"ownerSignature"`
}

type SubmitResponse struct {
	TokenId   string `json:"TokenId"`
	TxId      string `json:"txId"`
	TxReceipt string `json:"txReceipt"`
}

type TokenRecord struct {
	AssetDataId   string
	Owner         string
	AssetData     string `json:"assetData"`
	AssetMetadata string `json:"assetMetadata"`
}
