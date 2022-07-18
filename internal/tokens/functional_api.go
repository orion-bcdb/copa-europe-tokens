package tokens

import "github.com/copa-europe-tokens/pkg/types"

//go:generate counterfeiter -o mocks/operations.go --fake-name Operations . Operations

type Operations interface {

	// Management API

	Close() error
	GetStatus() (string, error)

	// User API

	AddUser(userRecord *types.UserRecord) error
	UpdateUser(userRecord *types.UserRecord) error
	RemoveUser(userId string) error
	GetUser(userId string) (*types.UserRecord, error)

	// Generic token type API

	GetTokenType(tokenTypeId string) (map[string]string, error)
	GetTokenTypes() ([]map[string]string, error)
	SubmitTx(submitRequest *types.SubmitRequest) (*types.SubmitResponse, error)

	// Non fungible token type (NFT) API

	DeployTokenType(deployRequest *types.DeployRequest) (*types.DeployResponse, error)
	PrepareMint(tokenTypeId string, mintRequest *types.MintRequest) (*types.MintResponse, error)
	PrepareTransfer(tokenId string, transferRequest *types.TransferRequest) (*types.TransferResponse, error)
	GetToken(tokenId string) (*types.TokenRecord, error)
	GetTokensByOwner(tokenTypeId string, owner string) ([]*types.TokenRecord, error)

	// Fungible token type API

	FungibleDeploy(deployRequest *types.FungibleDeployRequest) (*types.FungibleDeployResponse, error)
	FungibleDescribe(typeId string) (*types.FungibleDescribeResponse, error)
	FungiblePrepareMint(typeId string, request *types.FungibleMintRequest) (*types.FungibleMintResponse, error)
	FungiblePrepareTransfer(typeId string, request *types.FungibleTransferRequest) (*types.FungibleTransferResponse, error)
	FungiblePrepareConsolidate(typeId string, request *types.FungibleConsolidateRequest) (*types.FungibleConsolidateResponse, error)
	FungibleAccounts(typeId string, owner string, account string) (types.FungibleAccountRecords, error)
}
