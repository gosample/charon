// Code generated by mockery v1.0.0
package charontest

import charonrpc "github.com/piotrkowalczuk/charon/charonrpc"
import context "context"
import mock "github.com/stretchr/testify/mock"
import wrappers "github.com/golang/protobuf/ptypes/wrappers"

// GroupManagerServer is an autogenerated mock type for the GroupManagerServer type
type GroupManagerServer struct {
	mock.Mock
}

// Create provides a mock function with given fields: _a0, _a1
func (_m *GroupManagerServer) Create(_a0 context.Context, _a1 *charonrpc.CreateGroupRequest) (*charonrpc.CreateGroupResponse, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *charonrpc.CreateGroupResponse
	if rf, ok := ret.Get(0).(func(context.Context, *charonrpc.CreateGroupRequest) *charonrpc.CreateGroupResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*charonrpc.CreateGroupResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *charonrpc.CreateGroupRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Delete provides a mock function with given fields: _a0, _a1
func (_m *GroupManagerServer) Delete(_a0 context.Context, _a1 *charonrpc.DeleteGroupRequest) (*wrappers.BoolValue, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *wrappers.BoolValue
	if rf, ok := ret.Get(0).(func(context.Context, *charonrpc.DeleteGroupRequest) *wrappers.BoolValue); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*wrappers.BoolValue)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *charonrpc.DeleteGroupRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Get provides a mock function with given fields: _a0, _a1
func (_m *GroupManagerServer) Get(_a0 context.Context, _a1 *charonrpc.GetGroupRequest) (*charonrpc.GetGroupResponse, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *charonrpc.GetGroupResponse
	if rf, ok := ret.Get(0).(func(context.Context, *charonrpc.GetGroupRequest) *charonrpc.GetGroupResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*charonrpc.GetGroupResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *charonrpc.GetGroupRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// List provides a mock function with given fields: _a0, _a1
func (_m *GroupManagerServer) List(_a0 context.Context, _a1 *charonrpc.ListGroupsRequest) (*charonrpc.ListGroupsResponse, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *charonrpc.ListGroupsResponse
	if rf, ok := ret.Get(0).(func(context.Context, *charonrpc.ListGroupsRequest) *charonrpc.ListGroupsResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*charonrpc.ListGroupsResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *charonrpc.ListGroupsRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListPermissions provides a mock function with given fields: _a0, _a1
func (_m *GroupManagerServer) ListPermissions(_a0 context.Context, _a1 *charonrpc.ListGroupPermissionsRequest) (*charonrpc.ListGroupPermissionsResponse, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *charonrpc.ListGroupPermissionsResponse
	if rf, ok := ret.Get(0).(func(context.Context, *charonrpc.ListGroupPermissionsRequest) *charonrpc.ListGroupPermissionsResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*charonrpc.ListGroupPermissionsResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *charonrpc.ListGroupPermissionsRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Modify provides a mock function with given fields: _a0, _a1
func (_m *GroupManagerServer) Modify(_a0 context.Context, _a1 *charonrpc.ModifyGroupRequest) (*charonrpc.ModifyGroupResponse, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *charonrpc.ModifyGroupResponse
	if rf, ok := ret.Get(0).(func(context.Context, *charonrpc.ModifyGroupRequest) *charonrpc.ModifyGroupResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*charonrpc.ModifyGroupResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *charonrpc.ModifyGroupRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetPermissions provides a mock function with given fields: _a0, _a1
func (_m *GroupManagerServer) SetPermissions(_a0 context.Context, _a1 *charonrpc.SetGroupPermissionsRequest) (*charonrpc.SetGroupPermissionsResponse, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *charonrpc.SetGroupPermissionsResponse
	if rf, ok := ret.Get(0).(func(context.Context, *charonrpc.SetGroupPermissionsRequest) *charonrpc.SetGroupPermissionsResponse); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*charonrpc.SetGroupPermissionsResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *charonrpc.SetGroupPermissionsRequest) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
