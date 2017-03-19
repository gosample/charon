package charond

import (
	"testing"

	"github.com/piotrkowalczuk/charon"
	"github.com/piotrkowalczuk/charon/charonrpc"
	"github.com/piotrkowalczuk/charon/internal/model"
	"github.com/piotrkowalczuk/charon/internal/session"
	"github.com/piotrkowalczuk/ntypes"
)

func TestCreateRefreshTokenHandler_Create(t *testing.T) {
	suite := &endToEndSuite{}
	suite.setup(t)
	defer suite.teardown(t)

	ctx := testRPCServerLogin(t, suite)

	cases := map[string]func(t *testing.T){
		"only-notes": func(t *testing.T) {
			req := &charonrpc.CreateRefreshTokenRequest{
				Notes: &ntypes.String{
					Valid: true,
					Chars: "note",
				},
			}
			res, err := suite.charon.refreshToken.Create(timeout(ctx), req)
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			if *res.RefreshToken.Notes != *req.Notes {
				t.Errorf("wrong notes, expected %s but got %s", req.Notes, res.RefreshToken.Notes)
			}
			if res.RefreshToken.ExpireAt != req.ExpireAt {
				t.Errorf("wrong expire at, expected %#v but got %#v", req.ExpireAt, res.RefreshToken.ExpireAt)
			}
		},
	}

	for hint, fn := range cases {
		t.Run(hint, fn)
	}
}

func TestCreateRefreshTokenHandler_firewall_success(t *testing.T) {
	data := []struct {
		req charonrpc.CreateRefreshTokenRequest
		act session.Actor
	}{
		{
			req: charonrpc.CreateRefreshTokenRequest{},
			act: session.Actor{
				User: &model.UserEntity{ID: 2},
				Permissions: charon.Permissions{
					charon.RefreshTokenCanCreate,
				},
			},
		},
		{
			req: charonrpc.CreateRefreshTokenRequest{},
			act: session.Actor{
				User: &model.UserEntity{ID: 2, IsSuperuser: true},
			},
		},
	}

	h := &createRefreshTokenHandler{}
	for _, d := range data {
		if err := h.firewall(&d.req, &d.act); err != nil {
			t.Errorf("unexpected error: %s", err.Error())
		}
	}
}

func TestCreateRefreshTokenHandler_firewall_failure(t *testing.T) {
	data := []struct {
		req charonrpc.CreateRefreshTokenRequest
		act session.Actor
	}{
		{
			req: charonrpc.CreateRefreshTokenRequest{},
			act: session.Actor{
				User: &model.UserEntity{ID: 2},
			},
		},
		{
			req: charonrpc.CreateRefreshTokenRequest{},
			act: session.Actor{
				User: &model.UserEntity{
					ID:      2,
					IsStaff: true,
				},
			},
		},
		{
			req: charonrpc.CreateRefreshTokenRequest{},
			act: session.Actor{
				User: &model.UserEntity{ID: 1},
			},
		},
	}

	h := &createRefreshTokenHandler{}
	for _, d := range data {
		if err := h.firewall(&d.req, &d.act); err == nil {
			t.Error("expected error, got nil")
		}
	}
}
