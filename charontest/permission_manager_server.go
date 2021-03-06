// Code generated by mockery v1.0.0
package charontest

import charonrpc "github.com/piotrkowalczuk/charon/charonrpc"
import context "context"
import mock "github.com/stretchr/testify/mock"

// PermissionManagerServer is an autogenerated mock type for the PermissionManagerServer type
type PermissionManagerServer struct {
	mock.Mock
}

// Get provides a mock function with given fields: _a0, _a1
func (_m *PermissionManagerServer) Get(_a0 context.Context, _a1 *charonrpc.GetPermissionRequest) (*charonrpc.GetPermissionResponse, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *charonrpc.GetPermissionResponse
	if rf, ok := ret.Get(0).(func(context.Context, *charonrpc.GetPermissionRequest) *charonrpc.GetPermissionResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*charonrpc.GetPermissionResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *charonrpc.GetPermissionRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// List provides a mock function with given fields: _a0, _a1
func (_m *PermissionManagerServer) List(_a0 context.Context, _a1 *charonrpc.ListPermissionsRequest) (*charonrpc.ListPermissionsResponse, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *charonrpc.ListPermissionsResponse
	if rf, ok := ret.Get(0).(func(context.Context, *charonrpc.ListPermissionsRequest) *charonrpc.ListPermissionsResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*charonrpc.ListPermissionsResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *charonrpc.ListPermissionsRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Register provides a mock function with given fields: _a0, _a1
func (_m *PermissionManagerServer) Register(_a0 context.Context, _a1 *charonrpc.RegisterPermissionsRequest) (*charonrpc.RegisterPermissionsResponse, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *charonrpc.RegisterPermissionsResponse
	if rf, ok := ret.Get(0).(func(context.Context, *charonrpc.RegisterPermissionsRequest) *charonrpc.RegisterPermissionsResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*charonrpc.RegisterPermissionsResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *charonrpc.RegisterPermissionsRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
