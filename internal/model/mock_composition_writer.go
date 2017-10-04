// Code generated by mockery v1.0.0
package model

import mock "github.com/stretchr/testify/mock"

// MockCompositionWriter is an autogenerated mock type for the CompositionWriter type
type MockCompositionWriter struct {
	mock.Mock
}

// WriteComposition provides a mock function with given fields: _a0, _a1, _a2
func (_m *MockCompositionWriter) WriteComposition(_a0 string, _a1 *Composer, _a2 *CompositionOpts) error {
	ret := _m.Called(_a0, _a1, _a2)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, *Composer, *CompositionOpts) error); ok {
		r0 = rf(_a0, _a1, _a2)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}