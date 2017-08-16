// Code generated by mockery v1.0.0
package model

import charon "github.com/piotrkowalczuk/charon"
import context "context"
import mock "github.com/stretchr/testify/mock"

// MockUserProvider is an autogenerated mock type for the UserProvider type
type MockUserProvider struct {
	mock.Mock
}

// ChangePassword provides a mock function with given fields: ctx, id, password
func (_m *MockUserProvider) ChangePassword(ctx context.Context, id int64, password string) error {
	ret := _m.Called(ctx, id, password)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, int64, string) error); ok {
		r0 = rf(ctx, id, password)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Count provides a mock function with given fields: _a0
func (_m *MockUserProvider) Count(_a0 context.Context) (int64, error) {
	ret := _m.Called(_a0)

	var r0 int64
	if rf, ok := ret.Get(0).(func(context.Context) int64); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(int64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Create provides a mock function with given fields: _a0, _a1
func (_m *MockUserProvider) Create(_a0 context.Context, _a1 *UserEntity) (*UserEntity, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *UserEntity
	if rf, ok := ret.Get(0).(func(context.Context, *UserEntity) *UserEntity); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*UserEntity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *UserEntity) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateSuperuser provides a mock function with given fields: ctx, username, password, FirstName, LastName
func (_m *MockUserProvider) CreateSuperuser(ctx context.Context, username string, password []byte, FirstName string, LastName string) (*UserEntity, error) {
	ret := _m.Called(ctx, username, password, FirstName, LastName)

	var r0 *UserEntity
	if rf, ok := ret.Get(0).(func(context.Context, string, []byte, string, string) *UserEntity); ok {
		r0 = rf(ctx, username, password, FirstName, LastName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*UserEntity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, []byte, string, string) error); ok {
		r1 = rf(ctx, username, password, FirstName, LastName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeleteOneByID provides a mock function with given fields: _a0, _a1
func (_m *MockUserProvider) DeleteOneByID(_a0 context.Context, _a1 int64) (int64, error) {
	ret := _m.Called(_a0, _a1)

	var r0 int64
	if rf, ok := ret.Get(0).(func(context.Context, int64) int64); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Get(0).(int64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, int64) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Exists provides a mock function with given fields: _a0, _a1
func (_m *MockUserProvider) Exists(_a0 context.Context, _a1 int64) (bool, error) {
	ret := _m.Called(_a0, _a1)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, int64) bool); ok {
		r0 = rf(_a0, _a1)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, int64) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Find provides a mock function with given fields: _a0, _a1
func (_m *MockUserProvider) Find(_a0 context.Context, _a1 *UserFindExpr) ([]*UserEntity, error) {
	ret := _m.Called(_a0, _a1)

	var r0 []*UserEntity
	if rf, ok := ret.Get(0).(func(context.Context, *UserFindExpr) []*UserEntity); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*UserEntity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *UserFindExpr) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindOneByID provides a mock function with given fields: _a0, _a1
func (_m *MockUserProvider) FindOneByID(_a0 context.Context, _a1 int64) (*UserEntity, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *UserEntity
	if rf, ok := ret.Get(0).(func(context.Context, int64) *UserEntity); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*UserEntity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, int64) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindOneByUsername provides a mock function with given fields: _a0, _a1
func (_m *MockUserProvider) FindOneByUsername(_a0 context.Context, _a1 string) (*UserEntity, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *UserEntity
	if rf, ok := ret.Get(0).(func(context.Context, string) *UserEntity); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*UserEntity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Insert provides a mock function with given fields: _a0, _a1
func (_m *MockUserProvider) Insert(_a0 context.Context, _a1 *UserEntity) (*UserEntity, error) {
	ret := _m.Called(_a0, _a1)

	var r0 *UserEntity
	if rf, ok := ret.Get(0).(func(context.Context, *UserEntity) *UserEntity); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*UserEntity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *UserEntity) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IsGranted provides a mock function with given fields: ctx, id, permission
func (_m *MockUserProvider) IsGranted(ctx context.Context, id int64, permission charon.Permission) (bool, error) {
	ret := _m.Called(ctx, id, permission)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, int64, charon.Permission) bool); ok {
		r0 = rf(ctx, id, permission)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, int64, charon.Permission) error); ok {
		r1 = rf(ctx, id, permission)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RegistrationConfirmation provides a mock function with given fields: ctx, id, confirmationToken
func (_m *MockUserProvider) RegistrationConfirmation(ctx context.Context, id int64, confirmationToken string) (int64, error) {
	ret := _m.Called(ctx, id, confirmationToken)

	var r0 int64
	if rf, ok := ret.Get(0).(func(context.Context, int64, string) int64); ok {
		r0 = rf(ctx, id, confirmationToken)
	} else {
		r0 = ret.Get(0).(int64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, int64, string) error); ok {
		r1 = rf(ctx, id, confirmationToken)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetPermissions provides a mock function with given fields: ctx, id, permissions
func (_m *MockUserProvider) SetPermissions(ctx context.Context, id int64, permissions ...charon.Permission) (int64, int64, error) {
	_va := make([]interface{}, len(permissions))
	for _i := range permissions {
		_va[_i] = permissions[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, id)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 int64
	if rf, ok := ret.Get(0).(func(context.Context, int64, ...charon.Permission) int64); ok {
		r0 = rf(ctx, id, permissions...)
	} else {
		r0 = ret.Get(0).(int64)
	}

	var r1 int64
	if rf, ok := ret.Get(1).(func(context.Context, int64, ...charon.Permission) int64); ok {
		r1 = rf(ctx, id, permissions...)
	} else {
		r1 = ret.Get(1).(int64)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, int64, ...charon.Permission) error); ok {
		r2 = rf(ctx, id, permissions...)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// UpdateLastLoginAt provides a mock function with given fields: ctx, id
func (_m *MockUserProvider) UpdateLastLoginAt(ctx context.Context, id int64) (int64, error) {
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

// UpdateOneByID provides a mock function with given fields: _a0, _a1, _a2
func (_m *MockUserProvider) UpdateOneByID(_a0 context.Context, _a1 int64, _a2 *UserPatch) (*UserEntity, error) {
	ret := _m.Called(_a0, _a1, _a2)

	var r0 *UserEntity
	if rf, ok := ret.Get(0).(func(context.Context, int64, *UserPatch) *UserEntity); ok {
		r0 = rf(_a0, _a1, _a2)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*UserEntity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, int64, *UserPatch) error); ok {
		r1 = rf(_a0, _a1, _a2)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
