package charond

import (
	"testing"

	"github.com/piotrkowalczuk/charon/charonrpc"
	"github.com/piotrkowalczuk/ntypes"
	"google.golang.org/grpc"
)

func TestDisableRefreshTokenHandler_Disable(t *testing.T) {
	suite := &endToEndSuite{}
	suite.setup(t)
	defer suite.teardown(t)

	ctx := testRPCServerLogin(t, suite)

	cases := map[string]func(t *testing.T){
		"simple": func(t *testing.T) {
			res, err := suite.charon.refreshToken.Create(timeout(ctx), &charonrpc.CreateRefreshTokenRequest{
				Notes: &ntypes.String{
					Valid: true,
					Chars: "note",
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			res2, err := suite.charon.refreshToken.Disable(timeout(ctx), &charonrpc.DisableRefreshTokenRequest{
				Token:  res.RefreshToken.Token,
				UserId: res.RefreshToken.UserId,
			})
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			if !res2.RefreshToken.Disabled {
				t.Error("refresh token expected to be disabled")
			}
		},
		"missing-user-id": func(t *testing.T) {
			exp := "refresh token cannot be disabled, missing user id"
			res, err := suite.charon.refreshToken.Create(timeout(ctx), &charonrpc.CreateRefreshTokenRequest{})
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			_, err = suite.charon.refreshToken.Disable(timeout(ctx), &charonrpc.DisableRefreshTokenRequest{
				Token: res.RefreshToken.Token,
			})
			if err == nil {
				t.Fatal("error expected")
			}

			got := grpc.ErrorDesc(err)
			if got != exp {
				t.Errorf("wrong error, expected '%s' but got '%s'", exp, got)
			}
		},
	}

	for hint, fn := range cases {
		t.Run(hint, fn)
	}
}
