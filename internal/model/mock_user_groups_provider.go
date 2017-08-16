// Code generated by mockery v1.0.0
package model

import context "context"
import mock "github.com/stretchr/testify/mock"

// MockUserGroupsProvider is an autogenerated mock type for the UserGroupsProvider type
type MockUserGroupsProvider struct {
	mock.Mock
}

// DeleteByUserID provides a mock function with given fields: ctx, id
func (_m *MockUserGroupsProvider) DeleteByUserID(ctx context.Context, id int64) (int64, error) {
	ret := _m.Called(ctx, id)

	var r0 int64
	if rf, ok := ret.Get(0).(func(context.Context, int64) int64); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Get(0).(int64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, int64) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Exists provides a mock function with given fields: ctx, userID, groupID
func (_m *MockUserGroupsProvider) Exists(ctx context.Context, userID int64, groupID int64) (bool, error) {
	ret := _m.Called(ctx, userID, groupID)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, int64, int64) bool); ok {
		r0 = rf(ctx, userID, groupID)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, int64, int64) error); ok {
		r1 = rf(ctx, userID, groupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Find provides a mock function with given fields: ctx, expr
func (_m *MockUserGroupsProvider) Find(ctx context.Context, expr *UserGroupsFindExpr) ([]*UserGroupsEntity, error) {
	ret := _m.Called(ctx, expr)

	var r0 []*UserGroupsEntity
	if rf, ok := ret.Get(0).(func(context.Context, *UserGroupsFindExpr) []*UserGroupsEntity); ok {
		r0 = rf(ctx, expr)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*UserGroupsEntity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *UserGroupsFindExpr) error); ok {
		r1 = rf(ctx, expr)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Insert provides a mock function with given fields: ctx, ent
func (_m *MockUserGroupsProvider) Insert(ctx context.Context, ent *UserGroupsEntity) (*UserGroupsEntity, error) {
	ret := _m.Called(ctx, ent)

	var r0 *UserGroupsEntity
	if rf, ok := ret.Get(0).(func(context.Context, *UserGroupsEntity) *UserGroupsEntity); ok {
		r0 = rf(ctx, ent)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*UserGroupsEntity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *UserGroupsEntity) error); ok {
		r1 = rf(ctx, ent)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Set provides a mock function with given fields: ctx, userID, groupIDs
func (_m *MockUserGroupsProvider) Set(ctx context.Context, userID int64, groupIDs []int64) (int64, int64, error) {
	ret := _m.Called(ctx, userID, groupIDs)

	var r0 int64
	if rf, ok := ret.Get(0).(func(context.Context, int64, []int64) int64); ok {
		r0 = rf(ctx, userID, groupIDs)
	} else {
		r0 = ret.Get(0).(int64)
	}

	var r1 int64
	if rf, ok := ret.Get(1).(func(context.Context, int64, []int64) int64); ok {
		r1 = rf(ctx, userID, groupIDs)
	} else {
		r1 = ret.Get(1).(int64)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, int64, []int64) error); ok {
		r2 = rf(ctx, userID, groupIDs)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}
