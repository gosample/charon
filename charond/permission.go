package charond

import (
	"database/sql"
	"errors"
	"strings"
	"sync"

	"github.com/piotrkowalczuk/charon"
)

// charon.Permission returns charon.Permission value that is concatenated
// using entity properties like subsystem, module and action.
func (pe *permissionEntity) Permission() charon.Permission {
	return charon.Permission(pe.subsystem + ":" + pe.module + ":" + pe.action)
}

type permissionProvider interface {
	find(criteria *permissionCriteria) ([]*permissionEntity, error)
	findOneByID(id int64) (entity *permissionEntity, err error)
	// findByUserID retrieves all permissions for user represented by given id.
	findByUserID(userID int64) (entities []*permissionEntity, err error)
	// findByGroupID retrieves all permissions for group represented by given id.
	findByGroupID(groupID int64) (entities []*permissionEntity, err error)
	register(permissions charon.Permissions) (created, untouched, removed int64, err error)
	insert(entity *permissionEntity) (*permissionEntity, error)
}

type permissionRepository struct {
	permissionRepositoryBase
}

func newPermissionRepository(dbPool *sql.DB) *permissionRepository {
	return &permissionRepository{
		permissionRepositoryBase: permissionRepositoryBase{
			db:      dbPool,
			table:   tablePermission,
			columns: tablePermissionColumns,
		},
	}
}

// findByUserID implements charon.PermissionRepository interface.
func (pr *permissionRepository) findByUserID(userID int64) ([]*permissionEntity, error) {
	// TODO: does it work?
	return pr.findBy(`
		SELECT DISTINCT ON (p.id)
			`+columns(tablePermissionColumns, "p")+`
		FROM `+pr.table+` AS p
		LEFT JOIN `+tableUserPermissions+` AS up
			ON up.`+tableUserPermissionsColumnPermissionSubsystem+` = p.`+tablePermissionColumnSubsystem+`
			AND up.`+tableUserPermissionsColumnPermissionModule+` = p.`+tablePermissionColumnModule+`
			AND up.`+tableUserPermissionsColumnPermissionAction+` = p.`+tablePermissionColumnAction+`
		LEFT JOIN `+tableUserGroups+` AS ug ON ug.`+tableUserGroupsColumnUserID+` = $1
		LEFT JOIN `+tableGroupPermissions+` AS gp
			ON gp.`+tableGroupPermissionsColumnPermissionSubsystem+` = p.`+tablePermissionColumnSubsystem+`
			AND gp.`+tableGroupPermissionsColumnPermissionModule+` = p.`+tablePermissionColumnModule+`
			AND gp.`+tableGroupPermissionsColumnPermissionAction+` = p.`+tablePermissionColumnAction+`
			AND gp.`+tableGroupPermissionsColumnGroupID+` = ug.`+tableUserGroupsColumnGroupID+`
		WHERE up.`+tableUserPermissionsColumnUserID+` = $1 OR ug.`+tableUserGroupsColumnUserID+` = $1
	`, userID)
}

// findByGroupID implements charon.PermissionRepository interface.
func (pr *permissionRepository) findByGroupID(userID int64) ([]*permissionEntity, error) {
	// TODO: does it work?
	return pr.findBy(`
		SELECT DISTINCT ON (p.id)
			`+columns(tablePermissionColumns, "p")+`
		FROM `+pr.table+` AS p
		LEFT JOIN `+tableGroupPermissions+` AS gp ON gp.permission_id = p.id AND gp.group_id = ug.group_id
		WHERE up.user_id = $1 OR ug.user_id = $1
	`, userID)
}

func (pr *permissionRepository) findBy(query string, args ...interface{}) ([]*permissionEntity, error) {
	rows, err := pr.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	permissions := []*permissionEntity{}
	for rows.Next() {
		var p permissionEntity
		err = rows.Scan(
			&p.action,
			&p.createdAt,
			&p.id,
			&p.module,
			&p.subsystem,
			&p.updatedAt,
		)
		if err != nil {
			return nil, err
		}

		permissions = append(permissions, &p)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return permissions, nil
}

func (pr *permissionRepository) findOneStmt() (*sql.Stmt, error) {
	return pr.db.Prepare(
		"SELECT " + strings.Join(tablePermissionColumns, ",") + " " +
			"FROM " + pr.table + " AS p " +
			"WHERE p.subsystem = $1 AND p.module = $2 AND p.action = $3",
	)
}

func (pr *permissionRepository) register(permissions charon.Permissions) (created, unt, removed int64, err error) {
	var (
		tx             *sql.Tx
		insert, delete *sql.Stmt
		rows           *sql.Rows
		res            sql.Result
		subsystem      string
		entities       []*permissionEntity
		affected       int64
	)
	if len(permissions) == 0 {
		return 0, 0, 0, errors.New("empty slice, permissions cannot be registered")
	}

	subsystem = permissions[0].Subsystem()
	if subsystem == "" {
		return 0, 0, 0, errors.New("subsystem name is empty string, permissions cannot be registered")
	}

	for _, p := range permissions {
		if p.Subsystem() != subsystem {
			return 0, 0, 0, errors.New("provided permissions do not belong to one subsystem, permissions cannot be registered")
		}
	}

	tx, err = pr.db.Begin()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
			unt = untouched(int64(len(permissions)), created, removed)
		}
	}()

	rows, err = tx.Query("SELECT "+strings.Join(tablePermissionColumns, ",")+" FROM "+pr.table+" AS p WHERE p.subsystem = $1", subsystem)
	if err != nil {
		return
	}
	defer rows.Close()

	entities = []*permissionEntity{}
	for rows.Next() {
		var entity permissionEntity
		err = rows.Scan(
			&entity.action,
			&entity.createdAt,
			&entity.id,
			&entity.module,
			&entity.subsystem,
			&entity.updatedAt,
		)
		if err != nil {
			return
		}
		entities = append(entities, &entity)
	}
	if rows.Err() != nil {
		return 0, 0, 0, rows.Err()
	}

	insert, err = tx.Prepare("INSERT INTO " + pr.table + " (subsystem, module, action) VALUES ($1, $2, $3)")
	if err != nil {
		return
	}

MissingPermissionsLoop:
	for _, p := range permissions {
		for _, e := range entities {
			if p == e.Permission() {
				continue MissingPermissionsLoop
			}
		}

		if res, err = insert.Exec(p.Split()); err != nil {
			return
		}
		if affected, err = res.RowsAffected(); err != nil {
			return
		}
		created += affected
	}

	delete, err = tx.Prepare("DELETE FROM " + pr.table + " AS p WHERE p.id = $1")
	if err != nil {
		return
	}

RedundantPermissionsLoop:
	for _, e := range entities {
		for _, p := range permissions {
			if e.Permission() == p {
				continue RedundantPermissionsLoop
			}
		}

		if res, err = delete.Exec(e.id); err != nil {
			return
		}
		if affected, err = res.RowsAffected(); err != nil {
			return
		}

		removed += affected
	}

	return
}

// permissionRegistry is an interface that describes in memory storage that holds information
// about permissions that was registered by 3rd party services.
// Should be only used as a proxy for registration process to avoid multiple sql hits.
type permissionRegistry interface {
	// Exists returns true if given charon.Permission was already registered.
	exists(permission charon.Permission) (exists bool)
	// Register checks if given collection is valid and
	// calls charon.PermissionRepository to store provided permissions
	// in persistent way.
	register(permissions charon.Permissions) (created, untouched, removed int64, err error)
}

type permissionReg struct {
	sync.RWMutex
	repository  permissionProvider
	permissions map[charon.Permission]struct{}
}

func newPermissionRegistry(r permissionProvider) permissionRegistry {
	return &permissionReg{
		repository:  r,
		permissions: make(map[charon.Permission]struct{}),
	}
}

func (pr *permissionReg) exists(permission charon.Permission) (ok bool) {
	pr.RLock()
	pr.RUnlock()

	_, ok = pr.permissions[permission]
	return
}

func (pr *permissionReg) register(permissions charon.Permissions) (created, untouched, removed int64, err error) {
	pr.Lock()
	defer pr.Unlock()

	nb := 0
	for _, p := range permissions {
		if _, ok := pr.permissions[p]; !ok {
			pr.permissions[p] = struct{}{}
			nb++
		}
	}

	if nb > 0 {
		return pr.repository.register(permissions)
	}

	return 0, 0, 0, nil
}

func (pr *permissionRepository) findByTag(userID int64) ([]*permissionEntity, error) {
	query := `
		SELECT DISTINCT ON (p.id)
			` + columns(tablePermissionColumns, "p") + `
		FROM ` + pr.table + ` AS p
		LEFT JOIN ` + tableUserPermissions + ` AS up ON up.permission_id = p.id AND up.user_id = $1
		LEFT JOIN ` + tableUserGroups + ` AS ug ON ug.user_id = $1
		LEFT JOIN ` + tableGroupPermissions + ` AS gp ON gp.permission_id = p.id AND gp.group_id = ug.group_id
		WHERE up.user_id = $1 OR ug.user_id = $1
	`

	rows, err := pr.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	permissions := []*permissionEntity{}
	for rows.Next() {
		var p permissionEntity
		err = rows.Scan(
			&p.action,
			&p.createdAt,
			&p.id,
			&p.module,
			&p.subsystem,
			&p.updatedAt,
		)
		if err != nil {
			return nil, err
		}

		permissions = append(permissions, &p)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return permissions, nil
}
