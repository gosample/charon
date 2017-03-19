package charond

import (
	"database/sql"

	"github.com/piotrkowalczuk/charon"
	"github.com/piotrkowalczuk/charon/charonrpc"
	"github.com/piotrkowalczuk/charon/internal/model"
	"github.com/piotrkowalczuk/charon/internal/session"
	"github.com/piotrkowalczuk/mnemosyne/mnemosynerpc"
	"github.com/piotrkowalczuk/ntypes"
	"github.com/piotrkowalczuk/sklog"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type disableRefreshTokenHandler struct {
	*handler
}

func (drth *disableRefreshTokenHandler) Disable(ctx context.Context, req *charonrpc.DisableRefreshTokenRequest) (*charonrpc.DisableRefreshTokenResponse, error) {
	if len(req.Token) == 0 {
		return nil, grpc.Errorf(codes.InvalidArgument, "refresh token cannot be disabled, invalid token: %s", req.Token)
	}
	if req.UserId == 0 {
		return nil, grpc.Errorf(codes.InvalidArgument, "refresh token cannot be disabled, missing user id")
	}

	act, err := drth.retrieveActor(ctx)
	if err != nil {
		return nil, err
	}
	ent, err := drth.repository.refreshToken.FindOneByTokenAndUserID(ctx, req.Token, req.UserId)
	if err != nil {
		return nil, err
	}
	if err = drth.firewall(req, act, ent); err != nil {
		return nil, err
	}

	ent, err = drth.repository.refreshToken.UpdateOneByTokenAndUserID(ctx, req.Token, req.UserId, &model.RefreshTokenPatch{
		Disabled: ntypes.Bool{Bool: true, Valid: true},
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, grpc.Errorf(codes.NotFound, "refresh token does not exists")
		}
		return nil, err
	}

	res, err := drth.session.Delete(ctx, &mnemosynerpc.DeleteRequest{
		SubjectId:    session.ActorIDFromInt64(ent.UserID).String(),
		RefreshToken: req.Token,
	})
	if err != nil {
		if grpc.Code(err) != codes.NotFound {
			return nil, err
		}
	}
	sklog.Debug(drth.logger, "refresh token coresponding sessions removed", "count", res.Count)

	msg, err := ent.Message()
	if err != nil {
		return nil, err
	}
	return &charonrpc.DisableRefreshTokenResponse{
		RefreshToken: msg,
	}, nil
}

func (drth *disableRefreshTokenHandler) firewall(req *charonrpc.DisableRefreshTokenRequest, act *session.Actor, ent *model.RefreshTokenEntity) error {
	if act.User.IsSuperuser {
		return nil
	}
	if act.Permissions.Contains(charon.RefreshTokenCanDisableAsStranger) {
		return nil
	}
	if act.Permissions.Contains(charon.RefreshTokenCanDisableAsOwner) {
		if act.User.ID == ent.UserID {
			return nil
		}
		return grpc.Errorf(codes.PermissionDenied, "refresh token cannot be disabled by stranger, missing permission")
	}
	return grpc.Errorf(codes.PermissionDenied, "refresh token cannot be disabled, missing permission")
}
