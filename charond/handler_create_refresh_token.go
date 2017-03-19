package charond

import (
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/lib/pq"
	"github.com/piotrkowalczuk/charon"
	"github.com/piotrkowalczuk/charon/charonrpc"
	"github.com/piotrkowalczuk/charon/internal/model"
	"github.com/piotrkowalczuk/charon/internal/refreshtoken"
	"github.com/piotrkowalczuk/charon/internal/session"
	"github.com/piotrkowalczuk/ntypes"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type createRefreshTokenHandler struct {
	*handler
}

func (crth *createRefreshTokenHandler) Create(ctx context.Context, req *charonrpc.CreateRefreshTokenRequest) (*charonrpc.CreateRefreshTokenResponse, error) {
	act, err := crth.retrieveActor(ctx)
	if err != nil {
		return nil, err
	}
	if err = crth.firewall(req, act); err != nil {
		return nil, err
	}

	tkn, err := refreshtoken.Random()
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "refresh tkn generation failure: %s", err.Error())
	}

	var expireAt time.Time
	if req.ExpireAt != nil {
		if ts, err := ptypes.Timestamp(req.ExpireAt); err == nil {
			expireAt = ts
		}
	}
	ent, err := crth.repository.refreshToken.Create(ctx, &model.RefreshTokenEntity{
		UserID: act.User.ID,
		Token:  tkn,
		ExpireAt: pq.NullTime{
			Time:  expireAt.UTC(),
			Valid: !expireAt.IsZero(),
		},
		CreatedBy: ntypes.Int64{Int64: act.User.ID, Valid: true},
		Notes:     allocNilString(req.Notes),
	})
	if err != nil {
		switch model.ErrorConstraint(err) {
		case model.TableRefreshTokenConstraintCreatedByForeignKey:
			return nil, grpc.Errorf(codes.FailedPrecondition, "such user does not exist")
		case model.TableRefreshTokenConstraintTokenUserIDUnique:
			return nil, grpc.Errorf(codes.AlreadyExists, "such refresh tkn for given user already exists")
		case model.TableRefreshTokenConstraintUserIDForeignKey:
			return nil, grpc.Errorf(codes.FailedPrecondition, "such user does not exist")
		default:
			return nil, err
		}
	}

	return crth.response(ent)
}

func (crth *createRefreshTokenHandler) firewall(req *charonrpc.CreateRefreshTokenRequest, act *session.Actor) error {
	if act.User.IsSuperuser {
		return nil
	}
	if act.Permissions.Contains(charon.RefreshTokenCanCreate) {
		return nil
	}

	return grpc.Errorf(codes.PermissionDenied, "refresh token cannot be created, missing permission")
}

func (crth *createRefreshTokenHandler) response(ent *model.RefreshTokenEntity) (*charonrpc.CreateRefreshTokenResponse, error) {
	msg, err := ent.Message()
	if err != nil {
		return nil, err
	}
	return &charonrpc.CreateRefreshTokenResponse{
		RefreshToken: msg,
	}, nil
}
