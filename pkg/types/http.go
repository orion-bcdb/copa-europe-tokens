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
	TxEnvelope    string `json:"txEnvelope"`    //base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` //base64 (std, padded) encoding of bytes
}

type TransferRequest struct {
	Owner    string `json:"owner"`
	NewOwner string `json:"newOwner"`
}

type TransferResponse struct {
	TokenId       string `json:"tokenId"`
	Owner         string `json:"owner"`
	NewOwner      string `json:"newOwner"`
	TxEnvelope    string `json:"txEnvelope"`    //base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` //base64 (std, padded) encoding of bytes
}

type SubmitRequest struct {
	TokenId       string `json:"TokenId"`
	TxEnvelope    string `json:"txEnvelope"`    //base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` //base64 (std, padded) encoding of bytes
	Signer        string `json:"signer"`
	Signature     string `json:"signature"` //base64 (std, padded) encoding of bytes
}

type SubmitResponse struct {
	TokenId   string `json:"TokenId"`
	TxId      string `json:"txId"`
	TxReceipt string `json:"txReceipt"`
}

type TokenRecord struct {
	AssetDataId   string `json:"assetDataId"`
	Owner         string `json:"owner"`
	AssetData     string `json:"assetData"`
	AssetMetadata string `json:"assetMetadata"`
}

type UserRecord struct {
	Identity    string   `json:"identity"`    //a unique identifier
	Certificate string   `json:"certificate"` //base64 (std, padded) encoding of bytes
	Privilege   []string `json:"privilege"`   //a list of token types, or empty for all
}
