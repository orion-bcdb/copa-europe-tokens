// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"

	"github.com/copa-europe-tokens/internal/tokens"
	"github.com/copa-europe-tokens/pkg/types"
)

type Operations struct {
	DeployTokenTypeStub        func(*types.DeployRequest) (*types.DeployResponse, error)
	deployTokenTypeMutex       sync.RWMutex
	deployTokenTypeArgsForCall []struct {
		arg1 *types.DeployRequest
	}
	deployTokenTypeReturns struct {
		result1 *types.DeployResponse
		result2 error
	}
	deployTokenTypeReturnsOnCall map[int]struct {
		result1 *types.DeployResponse
		result2 error
	}
	GetStatusStub        func() (string, error)
	getStatusMutex       sync.RWMutex
	getStatusArgsForCall []struct {
	}
	getStatusReturns struct {
		result1 string
		result2 error
	}
	getStatusReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	GetTokenTypeStub        func(string) (*types.DeployResponse, error)
	getTokenTypeMutex       sync.RWMutex
	getTokenTypeArgsForCall []struct {
		arg1 string
	}
	getTokenTypeReturns struct {
		result1 *types.DeployResponse
		result2 error
	}
	getTokenTypeReturnsOnCall map[int]struct {
		result1 *types.DeployResponse
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Operations) DeployTokenType(arg1 *types.DeployRequest) (*types.DeployResponse, error) {
	fake.deployTokenTypeMutex.Lock()
	ret, specificReturn := fake.deployTokenTypeReturnsOnCall[len(fake.deployTokenTypeArgsForCall)]
	fake.deployTokenTypeArgsForCall = append(fake.deployTokenTypeArgsForCall, struct {
		arg1 *types.DeployRequest
	}{arg1})
	fake.recordInvocation("DeployTokenType", []interface{}{arg1})
	fake.deployTokenTypeMutex.Unlock()
	if fake.DeployTokenTypeStub != nil {
		return fake.DeployTokenTypeStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.deployTokenTypeReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Operations) DeployTokenTypeCallCount() int {
	fake.deployTokenTypeMutex.RLock()
	defer fake.deployTokenTypeMutex.RUnlock()
	return len(fake.deployTokenTypeArgsForCall)
}

func (fake *Operations) DeployTokenTypeCalls(stub func(*types.DeployRequest) (*types.DeployResponse, error)) {
	fake.deployTokenTypeMutex.Lock()
	defer fake.deployTokenTypeMutex.Unlock()
	fake.DeployTokenTypeStub = stub
}

func (fake *Operations) DeployTokenTypeArgsForCall(i int) *types.DeployRequest {
	fake.deployTokenTypeMutex.RLock()
	defer fake.deployTokenTypeMutex.RUnlock()
	argsForCall := fake.deployTokenTypeArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Operations) DeployTokenTypeReturns(result1 *types.DeployResponse, result2 error) {
	fake.deployTokenTypeMutex.Lock()
	defer fake.deployTokenTypeMutex.Unlock()
	fake.DeployTokenTypeStub = nil
	fake.deployTokenTypeReturns = struct {
		result1 *types.DeployResponse
		result2 error
	}{result1, result2}
}

func (fake *Operations) DeployTokenTypeReturnsOnCall(i int, result1 *types.DeployResponse, result2 error) {
	fake.deployTokenTypeMutex.Lock()
	defer fake.deployTokenTypeMutex.Unlock()
	fake.DeployTokenTypeStub = nil
	if fake.deployTokenTypeReturnsOnCall == nil {
		fake.deployTokenTypeReturnsOnCall = make(map[int]struct {
			result1 *types.DeployResponse
			result2 error
		})
	}
	fake.deployTokenTypeReturnsOnCall[i] = struct {
		result1 *types.DeployResponse
		result2 error
	}{result1, result2}
}

func (fake *Operations) GetStatus() (string, error) {
	fake.getStatusMutex.Lock()
	ret, specificReturn := fake.getStatusReturnsOnCall[len(fake.getStatusArgsForCall)]
	fake.getStatusArgsForCall = append(fake.getStatusArgsForCall, struct {
	}{})
	fake.recordInvocation("GetStatus", []interface{}{})
	fake.getStatusMutex.Unlock()
	if fake.GetStatusStub != nil {
		return fake.GetStatusStub()
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getStatusReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Operations) GetStatusCallCount() int {
	fake.getStatusMutex.RLock()
	defer fake.getStatusMutex.RUnlock()
	return len(fake.getStatusArgsForCall)
}

func (fake *Operations) GetStatusCalls(stub func() (string, error)) {
	fake.getStatusMutex.Lock()
	defer fake.getStatusMutex.Unlock()
	fake.GetStatusStub = stub
}

func (fake *Operations) GetStatusReturns(result1 string, result2 error) {
	fake.getStatusMutex.Lock()
	defer fake.getStatusMutex.Unlock()
	fake.GetStatusStub = nil
	fake.getStatusReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *Operations) GetStatusReturnsOnCall(i int, result1 string, result2 error) {
	fake.getStatusMutex.Lock()
	defer fake.getStatusMutex.Unlock()
	fake.GetStatusStub = nil
	if fake.getStatusReturnsOnCall == nil {
		fake.getStatusReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.getStatusReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *Operations) GetTokenType(arg1 string) (*types.DeployResponse, error) {
	fake.getTokenTypeMutex.Lock()
	ret, specificReturn := fake.getTokenTypeReturnsOnCall[len(fake.getTokenTypeArgsForCall)]
	fake.getTokenTypeArgsForCall = append(fake.getTokenTypeArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("GetTokenType", []interface{}{arg1})
	fake.getTokenTypeMutex.Unlock()
	if fake.GetTokenTypeStub != nil {
		return fake.GetTokenTypeStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getTokenTypeReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Operations) GetTokenTypeCallCount() int {
	fake.getTokenTypeMutex.RLock()
	defer fake.getTokenTypeMutex.RUnlock()
	return len(fake.getTokenTypeArgsForCall)
}

func (fake *Operations) GetTokenTypeCalls(stub func(string) (*types.DeployResponse, error)) {
	fake.getTokenTypeMutex.Lock()
	defer fake.getTokenTypeMutex.Unlock()
	fake.GetTokenTypeStub = stub
}

func (fake *Operations) GetTokenTypeArgsForCall(i int) string {
	fake.getTokenTypeMutex.RLock()
	defer fake.getTokenTypeMutex.RUnlock()
	argsForCall := fake.getTokenTypeArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Operations) GetTokenTypeReturns(result1 *types.DeployResponse, result2 error) {
	fake.getTokenTypeMutex.Lock()
	defer fake.getTokenTypeMutex.Unlock()
	fake.GetTokenTypeStub = nil
	fake.getTokenTypeReturns = struct {
		result1 *types.DeployResponse
		result2 error
	}{result1, result2}
}

func (fake *Operations) GetTokenTypeReturnsOnCall(i int, result1 *types.DeployResponse, result2 error) {
	fake.getTokenTypeMutex.Lock()
	defer fake.getTokenTypeMutex.Unlock()
	fake.GetTokenTypeStub = nil
	if fake.getTokenTypeReturnsOnCall == nil {
		fake.getTokenTypeReturnsOnCall = make(map[int]struct {
			result1 *types.DeployResponse
			result2 error
		})
	}
	fake.getTokenTypeReturnsOnCall[i] = struct {
		result1 *types.DeployResponse
		result2 error
	}{result1, result2}
}

func (fake *Operations) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.deployTokenTypeMutex.RLock()
	defer fake.deployTokenTypeMutex.RUnlock()
	fake.getStatusMutex.RLock()
	defer fake.getStatusMutex.RUnlock()
	fake.getTokenTypeMutex.RLock()
	defer fake.getTokenTypeMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Operations) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ tokens.Operations = new(Operations)
