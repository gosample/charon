package charond

import (
	"testing"

	"github.com/piotrkowalczuk/charon"
	"github.com/piotrkowalczuk/charon/charonrpc"
	"github.com/piotrkowalczuk/charon/internal/model"
	"github.com/piotrkowalczuk/charon/internal/session"
)

func TestListRefreshTokensHandler_firewall_success(t *testing.T) {
	cases := map[string]struct {
		req charonrpc.ListRefreshTokensRequest
		act session.Actor
	}{
		"as-stranger": {
			req: charonrpc.ListRefreshTokensRequest{},
			act: session.Actor{
				User: &model.UserEntity{ID: 1},
				Permissions: charon.Permissions{
					charon.RefreshTokenCanRetrieveAsStranger,
				},
			},
		},
		"as-superuser": {
			req: charonrpc.ListRefreshTokensRequest{},
			act: session.Actor{
				User: &model.UserEntity{ID: 2, IsSuperuser: true},
			},
		},
		"as-owner": {
			req: charonrpc.ListRefreshTokensRequest{},
			act: session.Actor{
				User: &model.UserEntity{ID: 2},
				Permissions: charon.Permissions{
					charon.RefreshTokenCanRetrieveAsOwner,
				},
			},
		},
	}

	for hint, c := range cases {
		t.Run(hint, func(t *testing.T) {
			h := &listRefreshTokensHandler{}
			if err := h.firewall(&c.req, &c.act); err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}
		})
	}
}

func TestListRefreshTokensHandler_firewall_failure(t *testing.T) {
	data := map[string]struct {
		req charonrpc.ListRefreshTokensRequest
		act session.Actor
	}{
		"as-noone": {
			req: charonrpc.ListRefreshTokensRequest{},
			act: session.Actor{
				User: &model.UserEntity{ID: 1},
			},
		},
		"as-staff": {
			req: charonrpc.ListRefreshTokensRequest{},
			act: session.Actor{
				User: &model.UserEntity{
					ID:      2,
					IsStaff: true,
				},
			},
		},
	}

	for hint, d := range data {
		t.Run(hint, func(t *testing.T) {
			h := &listRefreshTokensHandler{}
			if err := h.firewall(&d.req, &d.act); err == nil {
				t.Error("expected error, got nil")
			}

		})
	}
}
