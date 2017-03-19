package charond

import (
	"github.com/pborman/uuid"
	"github.com/piotrkowalczuk/charon"
	"github.com/piotrkowalczuk/charon/charonrpc"
	"github.com/piotrkowalczuk/charon/internal/model"
	"github.com/piotrkowalczuk/charon/internal/password"
	"github.com/piotrkowalczuk/charon/internal/session"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type createUserHandler struct {
	*handler
	hasher password.Hasher
}

func (cuh *createUserHandler) Create(ctx context.Context, req *charonrpc.CreateUserRequest) (*charonrpc.CreateUserResponse, error) {
	if len(req.Username) < 3 {
		return nil, grpc.Errorf(codes.InvalidArgument, "username needs to be at least 3 characters long but got %d", len(req.Username))
	}
	if len(req.PlainPassword) < 8 {
		return nil, grpc.Errorf(codes.InvalidArgument, "password needs to be at least 8 characters long but got %d", len(req.PlainPassword))
	}

	act, err := cuh.retrieveActor(ctx)
	if err != nil {
		if req.IsSuperuser.BoolOr(false) {
			count, err := cuh.repository.user.Count(ctx)
			if err != nil {
				return nil, err
			}
			if count > 0 {
				return nil, grpc.Errorf(codes.AlreadyExists, "initial superuser account already exists")
			}

			// If session.Actor does not exists, even single User does not exists and request contains IsSuperuser equals to true.
			// Then move forward, its request that is trying to create first User (that needs to be a superuser).
		} else {
			return nil, err
		}
	} else {
		if err = cuh.firewall(req, act); err != nil {
			return nil, err
		}
	}

	if len(req.SecurePassword) == 0 {
		req.SecurePassword, err = cuh.hasher.Hash([]byte(req.PlainPassword))
		if err != nil {
			return nil, err
		}
	} else {
		// TODO: only one superuser can be defined so this else statement makes no sense in this place.
		if !act.User.IsSuperuser {
			return nil, grpc.Errorf(codes.PermissionDenied, "only superuser can create an User with manualy defined secure password")
		}
	}

	ent, err := cuh.repository.user.Create(
		ctx,
		req.Username,
		req.SecurePassword,
		req.FirstName,
		req.LastName,
		uuid.NewRandom(),
		req.IsSuperuser.BoolOr(false),
		req.IsStaff.BoolOr(false),
		req.IsActive.BoolOr(false),
		req.IsConfirmed.BoolOr(false),
	)
	if err != nil {
		switch model.ErrorConstraint(err) {
		case model.TableUserConstraintPrimaryKey:
			return nil, grpc.Errorf(codes.AlreadyExists, "user with such id already exists")
		case model.TableUserConstraintUsernameUnique:
			return nil, grpc.Errorf(codes.AlreadyExists, "user with such username already exists")
		default:
			return nil, err
		}
	}

	return cuh.response(ent)
}

func (cuh *createUserHandler) firewall(req *charonrpc.CreateUserRequest, act *session.Actor) error {
	if act.IsLocal || act.User.IsSuperuser {
		return nil
	}
	if req.IsSuperuser.BoolOr(false) {
		return grpc.Errorf(codes.PermissionDenied, "User is not allowed to create superuser")
	}
	if req.IsStaff.BoolOr(false) && !act.Permissions.Contains(charon.UserCanCreateStaff) {
		return grpc.Errorf(codes.PermissionDenied, "User is not allowed to create staff User")
	}
	if !act.Permissions.Contains(charon.UserCanCreateStaff, charon.UserCanCreate) {
		return grpc.Errorf(codes.PermissionDenied, "User is not allowed to create another User")
	}

	return nil
}

func (cuh *createUserHandler) response(ent *model.UserEntity) (*charonrpc.CreateUserResponse, error) {
	msg, err := ent.Message()
	if err != nil {
		return nil, err
	}
	return &charonrpc.CreateUserResponse{
		User: msg,
	}, nil
}
