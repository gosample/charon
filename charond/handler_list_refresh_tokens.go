package charond

import (
	"github.com/piotrkowalczuk/charon"
	"github.com/piotrkowalczuk/charon/charonrpc"
	"github.com/piotrkowalczuk/charon/internal/model"
	"github.com/piotrkowalczuk/charon/internal/session"
	"github.com/piotrkowalczuk/qtypes"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type listRefreshTokensHandler struct {
	*handler
}

func (lrth *listRefreshTokensHandler) List(ctx context.Context, req *charonrpc.ListRefreshTokensRequest) (*charonrpc.ListRefreshTokensResponse, error) {
	act, err := lrth.retrieveActor(ctx)
	if err != nil {
		return nil, err
	}
	if err = lrth.firewall(req, act); err != nil {
		return nil, err
	}

	ents, err := lrth.repository.refreshToken.Find(ctx, &model.RefreshTokenFindExpr{
		Limit:  req.Limit.Int64Or(10),
		Offset: req.Offset.Int64Or(0),
		Where: &model.RefreshTokenCriteria{
			UserID:     req.UserId,
			Notes:      req.Notes,
			ExpireAt:   req.ExpireAt,
			LastUsedAt: req.LastUsedAt,
			CreatedAt:  req.CreatedAt,
			UpdatedAt:  req.UpdatedAt,
		},
	})
	if err != nil {
		return nil, err
	}

	return lrth.response(ents)
}

func (lrth *listRefreshTokensHandler) firewall(req *charonrpc.ListRefreshTokensRequest, act *session.Actor) error {
	if act.User.IsSuperuser {
		return nil
	}
	if act.Permissions.Contains(charon.RefreshTokenCanRetrieveAsStranger) {
		return nil
	}
	if act.Permissions.Contains(charon.RefreshTokenCanRetrieveAsOwner) {
		req.UserId = qtypes.EqualInt64(act.User.ID)
		return nil
	}

	return grpc.Errorf(codes.PermissionDenied, "list of refresh tokens cannot be retrieved, missing permission")
}

func (lrth *listRefreshTokensHandler) response(ents []*model.RefreshTokenEntity) (*charonrpc.ListRefreshTokensResponse, error) {
	resp := &charonrpc.ListRefreshTokensResponse{
		RefreshTokens: make([]*charonrpc.RefreshToken, 0, len(ents)),
	}
	var (
		err error
		msg *charonrpc.RefreshToken
	)
	for _, e := range ents {
		if msg, err = e.Message(); err != nil {
			return nil, err
		}
		resp.RefreshTokens = append(resp.RefreshTokens, msg)
	}

	return resp, nil
}
