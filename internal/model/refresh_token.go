package model

import (
	"context"
	"database/sql"

	"github.com/golang/protobuf/ptypes"
	pbts "github.com/golang/protobuf/ptypes/timestamp"
	"github.com/piotrkowalczuk/charon/charonrpc"
)

// Message maps entity into protobuf message.
func (rte *RefreshTokenEntity) Message() (*charonrpc.RefreshToken, error) {
	var (
		err                                        error
		expireAt, lastUsedAt, createdAt, updatedAt *pbts.Timestamp
	)

	if createdAt, err = ptypes.TimestampProto(rte.CreatedAt); err != nil {
		return nil, err
	}
	if rte.UpdatedAt.Valid {
		if updatedAt, err = ptypes.TimestampProto(rte.UpdatedAt.Time); err != nil {
			return nil, err
		}
	}
	if rte.ExpireAt.Valid {
		if expireAt, err = ptypes.TimestampProto(rte.ExpireAt.Time); err != nil {
			return nil, err
		}
	}
	if rte.LastUsedAt.Valid {
		if lastUsedAt, err = ptypes.TimestampProto(rte.LastUsedAt.Time); err != nil {
			return nil, err
		}
	}

	return &charonrpc.RefreshToken{
		Token:      rte.Token,
		Notes:      &rte.Notes,
		Disabled:   rte.Disabled,
		ExpireAt:   expireAt,
		LastUsedAt: lastUsedAt,
		UserId:     rte.UserID,
		CreatedAt:  createdAt,
		CreatedBy:  &rte.CreatedBy,
		UpdatedAt:  updatedAt,
		UpdatedBy:  &rte.UpdatedBy,
	}, nil
}

// RefreshTokenProvider ...
type RefreshTokenProvider interface {
	// Find ...
	Find(context.Context, *RefreshTokenFindExpr) ([]*RefreshTokenEntity, error)
	// FindOneByTokenAndUserID ...
	FindOneByTokenAndUserID(context.Context, string, int64) (*RefreshTokenEntity, error)
	// Create ...
	Create(context.Context, *RefreshTokenEntity) (*RefreshTokenEntity, error)
	// UpdateOneByTokenAndUserID ...
	UpdateOneByTokenAndUserID(context.Context, string, int64, *RefreshTokenPatch) (*RefreshTokenEntity, error)
}

// RefreshTokenRepository extends RefreshTokenRepositoryBase
type RefreshTokenRepository struct {
	RefreshTokenRepositoryBase
}

// NewRefreshTokenRepository ...
func NewRefreshTokenRepository(dbPool *sql.DB) RefreshTokenProvider {
	return &RefreshTokenRepository{
		RefreshTokenRepositoryBase: RefreshTokenRepositoryBase{
			DB:      dbPool,
			Table:   TableRefreshToken,
			Columns: TableRefreshTokenColumns,
		},
	}
}

// Create ...
func (rtr *RefreshTokenRepository) Create(ctx context.Context, ent *RefreshTokenEntity) (*RefreshTokenEntity, error) {
	return rtr.Insert(ctx, ent)
}
