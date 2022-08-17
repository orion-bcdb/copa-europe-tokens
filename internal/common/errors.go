// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"fmt"
	"net/http"
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
