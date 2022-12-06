// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// ====================================================
// Errors
// ====================================================

// HttpResponseErr holds an error message. It is used as the body of an http error response.
type HttpResponseErr struct {
	ErrMsg string `json:"error"`
}

func (e *HttpResponseErr) Error() string {
	return e.ErrMsg
}

// ====================================================
// Generic token type API
// ====================================================

type StatusResponse struct {
	Status string `json:"status"`
}

type TokenDescription struct {
	TypeId      string            `json:"typeId"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Class       string            `json:"class"`
	Extension   map[string]string `json:"extension"`
	Url         string            `json:"url"`
}

// ====================================================
// Non fungible token type (NFT) API
// ====================================================

type DeployRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Class       string `json:"class"`
}

type DeployResponse struct {
	TypeId      string `json:"typeId"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Class       string `json:"class"`
	Url         string `json:"url"`
}

type MintRequest struct {
	Owner         string `json:"owner"`
	Link          string `json:"link"`
	Reference     string `json:"reference"`
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

type UpdateRequest struct {
	Owner         string `json:"owner"`
	AssetMetadata string `json:"assetMetadata"`
}

type UpdateResponse struct {
	TokenId       string `json:"tokenId"`
	Owner         string `json:"owner"`
	AssetMetadata string `json:"assetMetadata"`
	TxEnvelope    string `json:"txEnvelope"`    //base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` //base64 (std, padded) encoding of bytes
}

type SubmitRequest struct {
	TokenId       string `json:"tokenId"`
	TxEnvelope    string `json:"txEnvelope"`    //base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` //base64 (std, padded) encoding of bytes
	Signer        string `json:"signer"`
	Signature     string `json:"signature"` //base64 (std, padded) encoding of bytes
}

type SubmitResponse struct {
	TokenId   string `json:"tokenId"`
	TxId      string `json:"txId"`
	TxReceipt string `json:"txReceipt"`
}

type TokenRecord struct {
	AssetDataId   string `json:"assetDataId"`
	Owner         string `json:"owner"`
	Link          string `json:"link"`
	Reference     string `json:"reference"`
	AssetData     string `json:"assetData"`
	AssetMetadata string `json:"assetMetadata"`
}

// ====================================================
// User API
// ====================================================

type UserRecord struct {
	Identity    string   `json:"identity"`    //a unique identifier
	Certificate string   `json:"certificate"` //base64 (std, padded) encoding of bytes
	Privilege   []string `json:"privilege"`   //a list of token types, or empty for all
}

// ====================================================
// Annotations API
// ====================================================

type AnnotationRegisterRequest struct {
	Owner              string `json:"owner"`
	Link               string `json:"link"`
	Reference          string `json:"reference"`
	AnnotationData     string `json:"annotationData"`
	AnnotationMetadata string `json:"annotationMetadata"`
}

type AnnotationRegisterResponse struct {
	AnnotationId  string `json:"annotationId"`
	Owner         string `json:"owner"`
	Link          string `json:"link"`
	Reference     string `json:"reference"`
	TxEnvelope    string `json:"txEnvelope"`    //base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` //base64 (std, padded) encoding of bytes
}

type AnnotationRecord struct {
	AnnotationDataId   string `json:"annotationDataId"`
	Owner              string `json:"owner"`
	Link               string `json:"link"`
	Reference          string `json:"reference"`
	AnnotationData     string `json:"annotationData"`
	AnnotationMetadata string `json:"annotationMetadata"`
}

// ====================================================
//  Fungible token type API
// ====================================================

type FungibleDeployRequest struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	ReserveOwner string `json:"reserveOwner"`
}

type FungibleDeployResponse struct {
	TypeId       string `json:"typeId"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Supply       uint64 `json:"supply"`
	ReserveOwner string `json:"reserveOwner"`
	Url          string `json:"url"`
}

type FungibleDescribeResponse FungibleDeployResponse

type FungibleMintRequest struct {
	Supply uint64 `json:"supply"`
}

type FungibleMintResponse struct {
	TypeId        string `json:"typeId"`
	TxEnvelope    string `json:"txEnvelope"`    //base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` //base64 (std, padded) encoding of bytes
}

type FungibleTransferRequest struct {
	Owner    string `json:"owner"`
	Account  string `json:"account"`
	NewOwner string `json:"newOwner"`
	Quantity uint64 `json:"quantity"`
	Comment  string `json:"comment"`
}

type FungibleTransferResponse struct {
	TypeId        string `json:"typeId"`
	Owner         string `json:"owner"`
	Account       string `json:"account"`
	NewOwner      string `json:"newOwner"`
	NewAccount    string `json:"newAccount"`
	TxEnvelope    string `json:"txEnvelope"`    //base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` //base64 (std, padded) encoding of bytes
}

type FungibleConsolidateRequest struct {
	Owner    string   `json:"owner"`
	Accounts []string `json:"accounts"`
}

type FungibleConsolidateResponse struct {
	TypeId        string `json:"typeId"`
	Owner         string `json:"owner"`
	TxEnvelope    string `json:"txEnvelope"`    //base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` //base64 (std, padded) encoding of bytes
}

type FungibleSubmitRequest struct {
	TypeId        string `json:"typeId"`
	TxEnvelope    string `json:"txEnvelope"`    //base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` //base64 (std, padded) encoding of bytes
	Signer        string `json:"signer"`
	Signature     string `json:"signature"` //base64 (std, padded) encoding of bytes
}

type FungibleSubmitResponse struct {
	TypeId    string `json:"typeId"`
	TxId      string `json:"txId"`
	TxReceipt string `json:"txReceipt"`
}

type FungibleAccountRecord struct {
	Account string `json:"account"`
	Owner   string `json:"owner"`
	Balance uint64 `json:"balance"`
	Comment string `json:"comment"`
}
