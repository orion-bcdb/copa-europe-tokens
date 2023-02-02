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
	Name         string `json:"name"`         // the name of the token (unique)
	Description  string `json:"description"`  // a free form description of the token
	ReserveOwner string `json:"reserveOwner"` // the owner (user ID) of the reserve account
}

type FungibleDeployResponse struct {
	TypeId       string `json:"typeId"`       // the unique ID of the token
	Name         string `json:"name"`         // the name of the token
	Description  string `json:"description"`  // a free form description of the token
	Supply       uint64 `json:"supply"`       // the current supply of the token
	ReserveOwner string `json:"reserveOwner"` // the owner (user ID) of the reserve account
	Url          string `json:"url"`          // the token address
}

type FungibleDescribeResponse FungibleDeployResponse

type FungibleMintRequest struct {
	Burn     bool   `json:"burn"`     // if true, the requested quantity will be burnt instead of minted
	Quantity uint64 `json:"quantity"` // the quantity of tokens added/burnt to the supply
	Comment  string `json:"comment"`  // a free form description of the operation
}

type FungibleMintResponse struct {
	TypeId        string `json:"typeId"`        // the unique ID of the token
	TxEnvelope    string `json:"txEnvelope"`    // base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` // base64 (std, padded) encoding of bytes
}

type FungibleTransferRequest struct {
	Owner    string `json:"owner"`    // the owner of the source account
	Account  string `json:"account"`  // the source account
	NewOwner string `json:"newOwner"` // the transfer destination user ID
	Quantity uint64 `json:"quantity"` // the quantity of tokens to transfer
	Comment  string `json:"comment"`  // a free form description of the operation
}

type FungibleTransferResponse struct {
	TypeId        string `json:"typeId"`        // the unique ID of the token
	Owner         string `json:"owner"`         // the owner of the source account
	Account       string `json:"account"`       // the source account
	NewOwner      string `json:"newOwner"`      // the transfer destination user ID
	NewAccount    string `json:"newAccount"`    // the transfer destination account ID
	TxEnvelope    string `json:"txEnvelope"`    // base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` // base64 (std, padded) encoding of bytes
}

type FungibleConsolidateRequest struct {
	Owner    string   `json:"owner"`    // the owner of the account(s)
	Accounts []string `json:"accounts"` // the account IDs to consolidate
}

type FungibleConsolidateResponse struct {
	TypeId        string `json:"typeId"`        // the unique ID of the token
	Owner         string `json:"owner"`         // the owner of the account(s)
	TxEnvelope    string `json:"txEnvelope"`    // base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` // base64 (std, padded) encoding of bytes
}

type FungibleSubmitRequest struct {
	TypeId        string `json:"typeId"`        // the unique ID of the token
	TxEnvelope    string `json:"txEnvelope"`    // base64 (std, padded) encoding of bytes
	TxPayloadHash string `json:"txPayloadHash"` // base64 (std, padded) encoding of bytes
	Signer        string `json:"signer"`        // the signers of the operation
	Signature     string `json:"signature"`     // base64 (std, padded) encoding of bytes
}

type FungibleSubmitResponse struct {
	TypeId    string `json:"typeId"`    // the unique ID of the token
	TxId      string `json:"txId"`      // the transaction ID
	TxReceipt string `json:"txReceipt"` // the transaction receipt
}

type FungibleAccountRecord struct {
	Account string `json:"account"` // the account ID (main or TX ID)
	Owner   string `json:"owner"`   // the owner of the account (user ID)
	Balance uint64 `json:"balance"` // the account's balance
	Comment string `json:"comment"` // a free form description of the account ("main" or the transfer's description)
}

type TxVersion struct {
	BlockNum uint64 `json:"blockNum"` // the block to which an operation was inserted
	TxNum    uint64 `json:"txNum"`    // the TX index in the block
}

type FungibleIncomingTxAccountRecord struct {
	Version     TxVersion `json:"version"`     // the tx account version for this movement
	Account     string    `json:"account"`     // the tx account ID
	Quantity    uint64    `json:"quantity"`    // the tx account balance
	Comment     string    `json:"comment"`     // a free form description of the operation (the transfer's description)
	SourceOwner string    `json:"sourceOwner"` // the user ID that transferred the fungible tokens
}

type FungibleOutgoingTxAccountRecord struct {
	Account  string `json:"account"`  // the tx account ID
	Quantity uint64 `json:"quantity"` // the tx account balance
	Comment  string `json:"comment"`  // a free form description of the operation (the transfer's description)
}

type FungibleMintTxRecord struct {
	Supply   uint64 `json:"supply"`   // the total supply of the token after this tx
	Burn     bool   `json:"burn"`     // if true, the tx burnt tokens instead of minting them
	Quantity uint64 `json:"quantity"` // the tx minted/burnt quantity
	Comment  string `json:"comment"`  // a free form description of the operation (the mint's description)
}

type FungibleMovementRecord struct {
	Version             TxVersion                         `json:"version"`                       // the main account version for this movement
	SourceAccounts      []FungibleIncomingTxAccountRecord `json:"sourceAccounts,omitempty"`      // the incoming accounts' movements (for consolidate, otherwise empty)
	DestinationAccounts []FungibleOutgoingTxAccountRecord `json:"destinationAccounts,omitempty"` // the receivers' accounts (for transfer, otherwise empty)
	MintRecord          *FungibleMintTxRecord             `json:"mintRecord,omitempty"`          // the mint record (for mint, otherwise empty)
	MainBalance         uint64                            `json:"mainBalance"`                   // the balance of the main account after this movement
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
