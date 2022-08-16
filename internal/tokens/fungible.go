package tokens

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/copa-europe-tokens/pkg/constants"
	"github.com/copa-europe-tokens/pkg/types"
)

type TokenHttpErr struct {
	ErrMsg     string
	StatusCode int
}

func (e *TokenHttpErr) Error() string {
	return e.ErrMsg
}

func (e *TokenHttpErr) String() string {
	return fmt.Sprintf("[%d: %s] %s", e.StatusCode, http.StatusText(e.StatusCode), e.ErrMsg)
}

func newTokenErr(statusCode int, format string, a ...interface{}) *TokenHttpErr {
	return &TokenHttpErr{
		ErrMsg:     fmt.Sprintf(format, a...),
		StatusCode: statusCode,
	}
}

func NewErrExist(format string, a ...interface{}) *TokenHttpErr {
	return newTokenErr(http.StatusConflict, format, a...)
}

func WrapErrExist(err error) *TokenHttpErr {
	return NewErrExist(err.Error())
}

func NewErrInvalid(format string, a ...interface{}) *TokenHttpErr {
	return newTokenErr(http.StatusBadRequest, format, a...)
}

func WrapErrInvalid(err error) *TokenHttpErr {
	return NewErrInvalid(err.Error())
}

func NewErrNotFound(format string, a ...interface{}) *TokenHttpErr {
	return newTokenErr(http.StatusNotFound, format, a...)
}

func WrapErrNotFound(err error) *TokenHttpErr {
	return NewErrNotFound(err.Error())
}

func NewErrPermission(format string, a ...interface{}) *TokenHttpErr {
	return newTokenErr(http.StatusForbidden, format, a...)
}

func WrapErrPermission(err error) *TokenHttpErr {
	return NewErrPermission(err.Error())
}

func URLForType(path string, typeId string) string {
	return strings.Replace(path, "{typeId}", typeId, 1)
}

func FungibleTypeURL(typeId string) string {
	return URLForType(constants.FungibleTypeRoot, typeId)
}

// ====================================================
// Fungible functional API implementation
// ====================================================

func (m *Manager) FungibleDeploy(request *types.FungibleDeployRequest) (*types.FungibleDeployResponse, error) {
	return nil, nil
}

func (m *Manager) FungibleDescribe(typeId string) (*types.FungibleDescribeResponse, error) {
	return &types.FungibleDescribeResponse{
		Url: FungibleTypeURL(typeId),
	}, nil
}

func (m *Manager) FungiblePrepareMint(typeId string, request *types.FungibleMintRequest) (*types.FungibleMintResponse, error) {
	return nil, nil
}

func (m *Manager) FungiblePrepareTransfer(typeId string, request *types.FungibleTransferRequest) (*types.FungibleTransferResponse, error) {
	return nil, nil
}

func (m *Manager) FungiblePrepareConsolidate(typeId string, request *types.FungibleConsolidateRequest) (*types.FungibleConsolidateResponse, error) {
	return nil, nil
}

func (m *Manager) FungibleSubmitTx(submitRequest *types.FungibleSubmitRequest) (*types.FungibleSubmitResponse, error) {
	return nil, nil
}

func (m *Manager) FungibleAccounts(typeId string, owner string, account string) ([]types.FungibleAccountRecord, error) {
	return nil, nil
}
