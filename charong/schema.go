package main

import "github.com/piotrkowalczuk/pqt"

func databaseSchema() *pqt.Schema {
	user := databaseTableUser()
	group := databaseTableGroup(user)
	permission, groupPermissions, userPermissions := databaseTablePermission(user, group)
	userGroups := databaseTableUserGroups(user, group)

	return pqt.NewSchema("charon").
	AddTable(user).
	AddTable(group).
	AddTable(permission).
	AddTable(userGroups).
	AddTable(groupPermissions).
	AddTable(userPermissions)
}

func databaseTableUser() *pqt.Table {
	t := pqt.NewTable("user", pqt.WithIfNotExists()).
	AddColumn(pqt.NewColumn("password", pqt.TypeBytea(), pqt.WithNotNull())).
	AddColumn(pqt.NewColumn("username", pqt.TypeText(), pqt.WithNotNull(), pqt.WithUnique())).
	AddColumn(pqt.NewColumn("first_name", pqt.TypeText(), pqt.WithNotNull())).
	AddColumn(pqt.NewColumn("last_name", pqt.TypeText(), pqt.WithNotNull())).
	AddColumn(pqt.NewColumn("is_superuser", pqt.TypeBool(), pqt.WithNotNull(), pqt.WithDefault("FALSE"))).
	AddColumn(pqt.NewColumn("is_active", pqt.TypeBool(), pqt.WithNotNull(), pqt.WithDefault("FALSE"))).
	AddColumn(pqt.NewColumn("is_staff", pqt.TypeBool(), pqt.WithNotNull(), pqt.WithDefault("FALSE"))).
	AddColumn(pqt.NewColumn("is_confirmed", pqt.TypeBool(), pqt.WithNotNull(), pqt.WithDefault("FALSE"))).
	AddColumn(pqt.NewColumn("confirmation_token", pqt.TypeBytea())).
	AddColumn(pqt.NewColumn("last_login_at", pqt.TypeTimestampTZ()))

	identifierable(t)
	ownerable(t, pqt.SelfReference())
	timestampable(t)

	return t
}

func databaseTableGroup(user *pqt.Table) *pqt.Table {
	t := pqt.NewTable("group", pqt.WithIfNotExists()).
	AddColumn(pqt.NewColumn("name", pqt.TypeText(), pqt.WithNotNull(), pqt.WithUnique())).
	AddColumn(pqt.NewColumn("description", pqt.TypeText()))

	identifierable(t)
	ownerable(t, user)
	timestampable(t)

	return t
}

func databaseTablePermission(user, group *pqt.Table) (*pqt.Table, *pqt.Table,*pqt.Table) {
	subsystem := notNullText("subsystem", "")
	module := notNullText("module", "")
	action := notNullText("action", "")

	permission := pqt.NewTable("permission", pqt.WithIfNotExists()).
	AddColumn(subsystem).
	AddColumn(module).
	AddColumn(action).
	AddUnique(subsystem, module, action)

	identifierable(permission)
	timestampable(permission)

	groupPermissions := pqt.NewTable("group_permissions", pqt.WithIfNotExists()).
	AddRelationship(pqt.ManyToMany(
		group,
		permission,
		pqt.WithBidirectional(),
		pqt.WithInversedForeignKey(
			pqt.Columns{
				notNullText("permission_subsystem", "subsystem"),
				notNullText("permission_module", "module"),
				notNullText("permission_action", "action"),
			},
			pqt.Columns{subsystem, module, action},
		),
	))

	ownerable(groupPermissions, user)
	timestampable(groupPermissions)

	userPermissions := pqt.NewTable("user_permissions", pqt.WithIfNotExists()).
	AddRelationship(pqt.ManyToMany(
		user,
		permission,
		pqt.WithBidirectional(),
		pqt.WithInversedForeignKey(
			pqt.Columns{
				notNullText("permission_subsystem", "subsystem"),
				notNullText("permission_module", "module"),
				notNullText("permission_action", "action"),
			},
			pqt.Columns{subsystem, module, action},
		),
	))

	ownerable(userPermissions, user)
	timestampable(userPermissions)

	return permission, groupPermissions, userPermissions
}

func databaseTableUserGroups(user, group *pqt.Table) *pqt.Table {
	t := pqt.NewTable("user_groups", pqt.WithIfNotExists()).
	AddRelationship(pqt.ManyToMany(user, group, pqt.WithBidirectional()), pqt.WithNotNull())

	ownerable(t, user)
	timestampable(t)

	return t
}


func identifierable(t *pqt.Table) {
	t.AddColumn(pqt.NewColumn("id", pqt.TypeSerialBig(), pqt.WithPrimaryKey()))
}

func ownerable(owner, inversed *pqt.Table) {
	owner.AddRelationship(pqt.ManyToOne(inversed, pqt.WithColumnName("created_by"), pqt.WithInversedName("Author"))).
	AddRelationship(pqt.ManyToOne(inversed, pqt.WithColumnName("updated_by"), pqt.WithInversedName("Modifier")))
}

func timestampable(t *pqt.Table) {
	t.AddColumn(pqt.NewColumn("created_at", pqt.TypeTimestampTZ(), pqt.WithNotNull(), pqt.WithDefault("NOW()"))).
	AddColumn(pqt.NewColumn("updated_at", pqt.TypeTimestampTZ(), pqt.WithDefault("NOW()", pqt.EventUpdate)))
}

func notNullText(name, short string) *pqt.Column {
	if short == "" {
		short = name
	}
	return pqt.NewColumn(name, pqt.TypeText(), pqt.WithNotNull(), pqt.WithShortName(short))
}