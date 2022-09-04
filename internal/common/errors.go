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

func NewTokenHttpErr(statusCode int, format string, a ...interface{}) *TokenHttpErr {
	return &TokenHttpErr{
		ErrMsg:     fmt.Sprintf(format, a...),
		StatusCode: statusCode,
	}
}

func NewErrExist(format string, a ...interface{}) *TokenHttpErr {
	return NewTokenHttpErr(http.StatusConflict, format, a...)
}

func NewErrInvalid(format string, a ...interface{}) *TokenHttpErr {
	return NewTokenHttpErr(http.StatusBadRequest, format, a...)
}

func NewErrNotFound(format string, a ...interface{}) *TokenHttpErr {
	return NewTokenHttpErr(http.StatusNotFound, format, a...)
}

func NewErrPermission(format string, a ...interface{}) *TokenHttpErr {
	return NewTokenHttpErr(http.StatusForbidden, format, a...)
}

func NewErrInternal(format string, a ...interface{}) *TokenHttpErr {
	return NewTokenHttpErr(http.StatusInternalServerError, format, a...)
}
