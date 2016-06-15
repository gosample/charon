package charond

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/golang/protobuf/ptypes"
	pbts "github.com/golang/protobuf/ptypes/timestamp"
	"github.com/piotrkowalczuk/charon"
	"github.com/piotrkowalczuk/ntypes"
	"github.com/piotrkowalczuk/pqcomp"
)

func (ge *groupEntity) message() (*charon.Group, error) {
	var (
		err                  error
		createdAt, updatedAt *pbts.Timestamp
	)

	if createdAt, err = ptypes.TimestampProto(ge.CreatedAt); err != nil {
		return nil, err
	}
	if ge.UpdatedAt != nil {
		if updatedAt, err = ptypes.TimestampProto(*ge.UpdatedAt); err != nil {
			return nil, err
		}
	}

	return &charon.Group{
		Id:          ge.ID,
		Name:        ge.Name,
		Description: ge.Description.String,
		CreatedAt:   createdAt,
		CreatedBy:   ge.CreatedBy,
		UpdatedAt:   updatedAt,
		UpdatedBy:   ge.UpdatedBy,
	}, nil
}

type groupProvider interface {
	Insert(entity *groupEntity) (*groupEntity, error)
	// FindByUserID retrieves all groups for user represented by given id.
	FindByUserID(int64) ([]*groupEntity, error)
	// FindOneByID retrieves group for given id.
	FindOneByID(int64) (*groupEntity, error)
	// Find ...
	Find(c *groupCriteria) ([]*groupEntity, error)
	// Create ...
	Create(createdBy int64, name string, description *ntypes.String) (*groupEntity, error)
	// UpdateOneByID ...
	UpdateOneByID(id, updatedBy int64, name, description *ntypes.String) (*groupEntity, error)
	// DeleteByID ...
	DeleteByID(id int64) (int64, error)
	// IsGranted ...
	IsGranted(id int64, permission charon.Permission) (bool, error)
	// SetPermissions ...
	SetPermissions(id int64, permissions ...charon.Permission) (int64, int64, error)
}

type groupRepository struct {
	groupRepositoryBase
}

func newGroupRepository(dbPool *sql.DB) groupProvider {
	return &groupRepository{
		groupRepositoryBase: groupRepositoryBase{
			db:      dbPool,
			table:   tableGroup,
			columns: tableGroupColumns,
		},
	}
}

func (gr *groupRepository) queryRow(query string, args ...interface{}) (*groupEntity, error) {
	var entity groupEntity
	err := gr.db.QueryRow(query, args...).Scan(
		&entity.CreatedAt,
		&entity.CreatedBy,
		&entity.Description,
		&entity.ID,
		&entity.Name,
		&entity.UpdatedAt,
		&entity.UpdatedBy,
	)
	if err != nil {
		return nil, err
	}

	return &entity, nil
}

// FindByUserID implements GroupRepository interface.
func (gr *groupRepository) FindByUserID(userID int64) ([]*groupEntity, error) {
	query := `
		SELECT  ` + strings.Join(tableGroupColumns, ",") + `
		FROM ` + tableGroup + ` AS g
		JOIN ` + tableUserGroups + ` AS ug ON ug.group_id = g.id AND ug.user_id = $1
	`

	rows, err := gr.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groups := []*groupEntity{}
	for rows.Next() {
		var g groupEntity
		err = rows.Scan(
			&g.CreatedAt,
			&g.CreatedBy,
			&g.Description,
			&g.ID,
			&g.Name,
			&g.UpdatedAt,
			&g.UpdatedBy,
		)
		if err != nil {
			return nil, err
		}

		groups = append(groups, &g)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return groups, nil
}

// Create implements GroupRepository interface.
func (gr *groupRepository) Create(createdBy int64, name string, description *ntypes.String) (*groupEntity, error) {
	if description == nil {
		description = &ntypes.String{}
	}
	entity := groupEntity{
		Name:        name,
		Description: description,
		CreatedBy:   &ntypes.Int64{Int64: createdBy, Valid: createdBy > 0},
	}

	err := gr.insert(&entity)
	if err != nil {
		return nil, err
	}

	return &entity, nil
}

func (gr *groupRepository) insert(e *groupEntity) error {
	query := `
		INSERT INTO ` + tableGroup + ` (
			name, description, created_at, created_by
		)
		VALUES ($1, $2, NOW(), $3)
		RETURNING id, created_at
	`
	return gr.db.QueryRow(
		query,
		e.Name,
		e.Description,
		e.CreatedBy,
	).Scan(&e.ID, &e.CreatedAt)
}

// UpdateOneByID implements GroupRepository interface.
func (gr *groupRepository) UpdateOneByID(id, updatedBy int64, name, description *ntypes.String) (*groupEntity, error) {
	var (
		err    error
		entity groupEntity
		query  string
	)

	comp := pqcomp.New(2, 2)
	comp.AddArg(id)
	comp.AddArg(updatedBy)
	comp.AddExpr("g.name", pqcomp.Equal, name)
	comp.AddExpr("g.description", pqcomp.Equal, description)

	if comp.Len() == 0 {
		return nil, errors.New("nothing to update")
	}

	query = `UPDATE ` + tableGroup + ` SET `
	for comp.Next() {
		if !comp.First() {
			query += ", "
		}

		query += fmt.Sprintf("%s %s %s", comp.Key(), comp.Oper(), comp.PlaceHolder())
	}

	query += `
		, updated_by = $2, updated_at = NOW()
		WHERE id = $1
		RETURNING ` + strings.Join(tableGroupColumns, ",") + `
	`

	err = gr.db.QueryRow(query, comp.Args()).Scan(
		&entity.CreatedAt,
		&entity.CreatedBy,
		&entity.Description,
		&entity.ID,
		&entity.Name,
		&entity.UpdatedAt,
		&entity.UpdatedBy,
	)
	if err != nil {
		return nil, err
	}

	return &entity, nil
}

// IsGranted implements GroupRepository interface.
func (gr *groupRepository) IsGranted(id int64, p charon.Permission) (bool, error) {
	var exists bool
	subsystem, module, action := p.Split()
	if err := gr.db.QueryRow(isGrantedQuery(
		tableGroupPermissions,
		tableGroupPermissionsColumnGroupID,
		tableGroupPermissionsColumnPermissionSubsystem,
		tableGroupPermissionsColumnPermissionModule,
		tableGroupPermissionsColumnPermissionAction,
	), id, subsystem, module, action).Scan(&exists); err != nil {
		return false, err
	}

	return exists, nil
}

// SetPermissions implements GroupRepository interface.
func (gr *groupRepository) SetPermissions(id int64, p ...charon.Permission) (int64, int64, error) {
	return setPermissions(gr.db, tableGroupPermissions,
		tableUserPermissionsColumnUserID,
		tableUserPermissionsColumnPermissionSubsystem,
		tableUserPermissionsColumnPermissionModule,
		tableUserPermissionsColumnPermissionAction, id, p)
}
