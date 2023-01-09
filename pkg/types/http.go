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

type FungibleMovementRecord struct {
	SourceAccounts     []string `json:"sourceAccounts"`     // the source accounts (there may be multiple sources for consolidate)
	DestinationAccount string   `json:"destinationAccount"` // the receiver account
	MainBalance        uint64   `json:"mainBalance"`        // the balance of the main account
	IncomeBalance      uint64   `json:"incomeBalance"`      // the sum of all incoming accounts balance
}

type FungibleMovementsResponse struct {
	TypeId         string                   `json:"typeId"`         // the token type that was queried
	Owner          string                   `json:"owner"`          // the user ID that was queried
	NextStartToken string                   `json:"nextStartToken"` // opaque base64 encoding to be used for the next query
	Movements      []FungibleMovementRecord `json:"movements"`      // the movements ordered from the latest to the oldest
}

// ====================================================
//  Rights Offer API
// ====================================================

type RightsOfferMintRequest struct {
	Name     string `json:"name"`     // An offer name chosen by the mint requester
	Owner    string `json:"owner"`    // The owner's user ID (must be the asset's owner)
	Asset    string `json:"asset"`    // An asset's token ID of class NFT
	Rights   string `json:"rights"`   // A token type ID of class NFT
	Template string `json:"template"` // A template text to be attached to each issued right token
	Price    uint64 `json:"price"`    // The price of the rights
	Currency string `json:"currency"` // A token type ID of class FUNGIBLE
}

type RightsOfferResponse struct {
	OfferId       string `json:"offerId"`
	TxEnvelope    string `json:"txEnvelope"`    //base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` //base64 (std, padded) encoding of bytes
}

type RightsOfferMintResponse RightsOfferResponse

type RightsOfferUpdateRequest struct {
	Enable bool `json:"enable"`
}

type RightsOfferUpdateResponse RightsOfferResponse

type RightsOfferBuyRequest struct {
	BuyerId  string `json:"buyerId"`  // The user ID of the buyer to which the new token will be issued
	Metadata string `json:"metadata"` // A metadata to be attached to the new issued token (amendable later by the buyer)
}

type RightsOfferBuyResponse struct {
	OfferId       string                `json:"offerId"`       // The purchased offer
	TokenId       string                `json:"tokenId"`       // The newly issued rights token
	Transfer      FungibleAccountRecord `json:"transfer"`      // The fungible transaction details
	TxEnvelope    string                `json:"txEnvelope"`    //base64 (std, padded) encoding of bytes
	TxPayloadHash string                `json:"txPayloadHash"` //base64 (std, padded) encoding of bytes
}

type RightsOfferSubmitRequest struct {
	OfferId       string `json:"offerId"`
	TxEnvelope    string `json:"txEnvelope"`    //base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` //base64 (std, padded) encoding of bytes
	Signer        string `json:"signer"`
	Signature     string `json:"signature"` //base64 (std, padded) encoding of bytes
}

type RightsOfferSubmitResponse struct {
	OfferId   string `json:"offerId"`
	TxId      string `json:"txId"`
	TxReceipt string `json:"txReceipt"`
}

type RightsOfferRecord struct {
	OfferId  string `json:"offerId"`
	Name     string `json:"name"`
	Owner    string `json:"owner"`
	Asset    string `json:"asset"`
	Rights   string `json:"rights"`
	Template string `json:"template"`
	Price    uint64 `json:"price"`
	Currency string `json:"currency"`
	Enabled  bool   `json:"enabled"`
}

type RightsRecord struct {
	RightsId string `json:"rightsId"`
	Template string `json:"template"`
}
