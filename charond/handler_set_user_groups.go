package charond

import (
	"github.com/lib/pq"
	"github.com/piotrkowalczuk/charon"
	"github.com/piotrkowalczuk/charon/charonrpc"
	"github.com/piotrkowalczuk/charon/internal/model"
	"github.com/piotrkowalczuk/charon/internal/session"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type setUserGroupsHandler struct {
	*handler
}

func (sugh *setUserGroupsHandler) SetGroups(ctx context.Context, req *charonrpc.SetUserGroupsRequest) (*charonrpc.SetUserGroupsResponse, error) {
	act, err := sugh.retrieveActor(ctx)
	if err != nil {
		return nil, err
	}

	if err = sugh.firewall(req, act); err != nil {
		return nil, err
	}

	created, removed, err := sugh.repository.userGroups.Set(ctx, req.UserId, req.Groups)
	if err != nil {
		switch model.ErrorConstraint(err) {
		case model.TableUserGroupsConstraintGroupIDForeignKey:
			return nil, errf(codes.NotFound, "%s: group does not exist", err.(*pq.Error).Detail)
		case model.TableUserGroupsConstraintUserIDForeignKey:
			return nil, errf(codes.NotFound, "%s: user does not exist", err.(*pq.Error).Detail)
		default:
			return nil, err
		}
	}

	return &charonrpc.SetUserGroupsResponse{
		Created:   created,
		Removed:   removed,
		Untouched: untouched(int64(len(req.Groups)), created, removed),
	}, nil
}

func (sugh *setUserGroupsHandler) firewall(req *charonrpc.SetUserGroupsRequest, act *session.Actor) error {
	if act.User.IsSuperuser {
		return nil
	}
	if act.Permissions.Contains(charon.UserGroupCanCreate) && act.Permissions.Contains(charon.UserGroupCanDelete) {
		return nil
	}

	return grpc.Errorf(codes.PermissionDenied, "user groups cannot be set, missing permission")
}
