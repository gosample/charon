package charond

import (
	"testing"

	"github.com/piotrkowalczuk/charon"
	"github.com/piotrkowalczuk/charon/charonrpc"
	"github.com/piotrkowalczuk/charon/internal/model"
	"github.com/piotrkowalczuk/charon/internal/session"
	"github.com/piotrkowalczuk/ntypes"
	"github.com/piotrkowalczuk/qtypes"
)

func TestListUsersHandler_firewall_success(t *testing.T) {
	cases := map[string]struct {
		req charonrpc.ListUsersRequest
		act session.Actor
	}{
		"as-owner": {

			req: charonrpc.ListUsersRequest{
				CreatedBy: qtypes.EqualInt64(1),
			},
			act: session.Actor{
				User: &model.UserEntity{ID: 1},
				Permissions: charon.Permissions{
					charon.UserCanRetrieveAsOwner,
				},
			},
		},
		"as-stranger": {
			req: charonrpc.ListUsersRequest{
				CreatedBy: qtypes.EqualInt64(3),
			},
			act: session.Actor{
				User: &model.UserEntity{ID: 1},
				Permissions: charon.Permissions{
					charon.UserCanRetrieveAsStranger,
				},
			},
		},
		"as-superuser-search-for-superusers": {
			req: charonrpc.ListUsersRequest{
				IsSuperuser: &ntypes.Bool{Bool: true, Valid: true},
			},
			act: session.Actor{
				User: &model.UserEntity{
					ID:          1,
					IsSuperuser: true,
				},
			},
		},
		"as-superuser": {
			req: charonrpc.ListUsersRequest{},
			act: session.Actor{
				User: &model.UserEntity{
					ID:          1,
					IsSuperuser: true,
				},
			},
		},
		"as-owner-search-for-staff": {
			req: charonrpc.ListUsersRequest{
				IsStaff:   &ntypes.Bool{Bool: true, Valid: true},
				CreatedBy: qtypes.EqualInt64(1),
			},
			act: session.Actor{
				User: &model.UserEntity{
					ID: 1,
				},
				Permissions: charon.Permissions{
					charon.UserCanRetrieveStaffAsOwner,
				},
			},
		},
		"as-stranger-search-for-staff": {
			req: charonrpc.ListUsersRequest{
				IsStaff:   &ntypes.Bool{Bool: true, Valid: true},
				CreatedBy: qtypes.EqualInt64(3),
			},
			act: session.Actor{
				User: &model.UserEntity{
					ID: 1,
				},
				Permissions: charon.Permissions{
					charon.UserCanRetrieveStaffAsStranger,
				},
			},
		},
		"all-Permissions": {
			req: charonrpc.ListUsersRequest{},
			act: session.Actor{
				User: &model.UserEntity{ID: 1},
				Permissions: charon.Permissions{
					charon.UserCanRetrieveAsStranger,
					charon.UserCanRetrieveAsOwner,
					charon.UserCanRetrieveStaffAsStranger,
					charon.UserCanRetrieveStaffAsOwner,
				},
			},
		},
		"as-superuser-with-all-Permissions": {
			req: charonrpc.ListUsersRequest{
				IsSuperuser: &ntypes.Bool{Bool: true, Valid: true},
			},
			act: session.Actor{
				User: &model.UserEntity{ID: 1, IsSuperuser: true},
				Permissions: charon.Permissions{
					charon.UserCanRetrieveAsStranger,
					charon.UserCanRetrieveAsOwner,
					charon.UserCanRetrieveStaffAsStranger,
					charon.UserCanRetrieveStaffAsOwner,
				},
			},
		},
	}

	h := &listUsersHandler{}
	for hint, c := range cases {
		t.Run(hint, func(t *testing.T) {
			if err := h.firewall(&c.req, &c.act); err != nil {
				t.Errorf("unexpected error for %s", err.Error())
			}
		})
	}
}

func TestListUsersHandler_firewall_failure(t *testing.T) {
	data := []struct {
		req charonrpc.ListUsersRequest
		act session.Actor
	}{
		{
			req: charonrpc.ListUsersRequest{},
			act: session.Actor{
				User: &model.UserEntity{},
			},
		},
		{
			req: charonrpc.ListUsersRequest{},
			act: session.Actor{
				User: &model.UserEntity{ID: 1},
			},
		},
		{
			req: charonrpc.ListUsersRequest{
				IsSuperuser: &ntypes.Bool{Bool: true, Valid: true},
			},
			act: session.Actor{
				User: &model.UserEntity{ID: 1},
				Permissions: charon.Permissions{
					charon.UserCanRetrieveAsStranger,
					charon.UserCanRetrieveAsOwner,
					charon.UserCanRetrieveStaffAsStranger,
					charon.UserCanRetrieveStaffAsOwner,
				},
			},
		},
	}

	h := &listUsersHandler{}
	for i, d := range data {
		if err := h.firewall(&d.req, &d.act); err == nil {
			t.Errorf("expected error for %d, got nil", i)
		}
	}
}
