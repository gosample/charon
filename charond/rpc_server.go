package charond

import (
	"github.com/go-kit/kit/log"
	"github.com/piotrkowalczuk/charon"
	"github.com/piotrkowalczuk/mnemosyne"
	"github.com/piotrkowalczuk/mnemosyne/mnemosynerpc"
	"golang.org/x/net/context"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

type rpcServer struct {
	meta               metadata.MD
	logger             log.Logger
	monitor            monitoring
	session            mnemosyne.Mnemosyne
	passwordHasher     charon.PasswordHasher
	permissionRegistry PermissionRegistry
	repository         repositories
}

type actor struct {
	user        *userEntity
	session     *mnemosynerpc.Session
	permissions charon.Permissions
	isLocal     bool
}

func (rs *rpcServer) loggerBackground(ctx context.Context, keyval ...interface{}) log.Logger {
	l := log.NewContext(rs.logger).With(keyval...)
	if md, ok := metadata.FromContext(ctx); ok {
		if rid, ok := md["request_id"]; ok && len(rid) >= 1 {
			l = l.With("request_id", rid[0])
		}
	}

	if p, ok := peer.FromContext(ctx); ok {
		l = l.With("peer_address", p.Addr.String())
	}

	return l
}

// Context create new context based on given metadata and instance metadata.
func (rs *rpcServer) Context(md metadata.MD) context.Context {
	if md.Len() == 0 {
		md = rs.meta
	} else {
		md = rs.metadata(md)
	}

	return metadata.NewContext(context.Background(), md)
}

func (rs *rpcServer) metadata(md metadata.MD) metadata.MD {
	for key, value := range rs.meta {
		if _, ok := md[key]; !ok {
			md[key] = value
		}
	}

	return md
}

// Login implements RPCServer interface.
func (rs *rpcServer) Login(ctx context.Context, req *charon.LoginRequest) (*charon.LoginResponse, error) {
	h := &loginHandler{
		handler: newHandler(rs, ctx, "login"),
		hasher:  rs.passwordHasher,
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "subject has been logged in"); err != nil {
		return nil, err
	}

	return resp, err
}

// Logout implements RPCServer interface.
func (rs *rpcServer) Logout(ctx context.Context, req *charon.LogoutRequest) (*charon.LogoutResponse, error) {
	h := &logoutHandler{
		handler: newHandler(rs, ctx, "logout"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "subject has been logged out"); err != nil {
		return nil, err
	}

	return resp, err
}

// IsAuthenticated implements RPCServer interface.
func (rs *rpcServer) IsAuthenticated(ctx context.Context, req *charon.IsAuthenticatedRequest) (*charon.IsAuthenticatedResponse, error) {
	h := &isAuthenticatedHandler{
		handler: newHandler(rs, ctx, "is_authenticated"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "subject authentication status has been checked"); err != nil {
		return nil, err
	}

	return resp, err
}

// Subject implements RPCServer interface.
func (rs *rpcServer) Subject(ctx context.Context, req *charon.SubjectRequest) (*charon.SubjectResponse, error) {
	h := &subjectHandler{
		handler: newHandler(rs, ctx, "subject"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "subject has been retrieved"); err != nil {
		return nil, err
	}

	return resp, err
}

// IsGranted implements RPCServer interface.
func (rs *rpcServer) IsGranted(ctx context.Context, req *charon.IsGrantedRequest) (*charon.IsGrantedResponse, error) {
	h := &isGrantedHandler{
		handler: newHandler(rs, ctx, "is_granted"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "permission has been checked"); err != nil {
		return nil, err
	}

	return resp, err
}

// BelongsTo implements RPCServer interface.
func (rs *rpcServer) BelongsTo(ctx context.Context, req *charon.BelongsToRequest) (*charon.BelongsToResponse, error) {
	h := &belongsToHandler{
		handler: newHandler(rs, ctx, "belongs_to"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "belonging to the group has been checked"); err != nil {
		return nil, err
	}

	return resp, err
}

// CreateGroup implements RPCServer interface.
func (rs *rpcServer) CreateGroup(ctx context.Context, req *charon.CreateGroupRequest) (*charon.CreateGroupResponse, error) {
	h := &createGroupHandler{
		handler: newHandler(rs, ctx, "create_group"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "group has been created"); err != nil {
		return nil, err
	}

	return resp, err
}

// ModifyGroup implements RPCServer interface.
func (rs *rpcServer) ModifyGroup(ctx context.Context, req *charon.ModifyGroupRequest) (*charon.ModifyGroupResponse, error) {
	h := &modifyGroupHandler{
		handler: newHandler(rs, ctx, "modify_group"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "group has been created"); err != nil {
		return nil, err
	}

	return resp, err
}

// DeleteGroup implements RPCServer interface.
func (rs *rpcServer) DeleteGroup(ctx context.Context, req *charon.DeleteGroupRequest) (*charon.DeleteGroupResponse, error) {
	h := &deleteGroupHandler{
		handler: newHandler(rs, ctx, "delete_group"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "group has been deleted"); err != nil {
		return nil, err
	}

	return resp, err
}

// GetGroup implements RPCServer interface.
func (rs *rpcServer) GetGroup(ctx context.Context, req *charon.GetGroupRequest) (*charon.GetGroupResponse, error) {
	h := &getGroupHandler{
		handler: newHandler(rs, ctx, "get_group"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "group has been retrieved"); err != nil {
		return nil, err
	}

	return resp, err
}

// ListGroups implements RPCServer interface.
func (rs *rpcServer) ListGroups(ctx context.Context, req *charon.ListGroupsRequest) (*charon.ListGroupsResponse, error) {
	h := &listGroupsHandler{
		handler: newHandler(rs, ctx, "list_groups"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "list of groups has been retrieved"); err != nil {
		return nil, err
	}

	return resp, err
}

// ListGroupPermissions implements RPCServer interface.
func (rs *rpcServer) ListGroupPermissions(ctx context.Context, req *charon.ListGroupPermissionsRequest) (*charon.ListGroupPermissionsResponse, error) {
	h := &listGroupPermissionsHandler{
		handler: newHandler(rs, ctx, "list_group_permissions"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "list of group permissions has been retrieved"); err != nil {
		return nil, err
	}

	return resp, err
}

// SetGroupPermissions implements RPCServer interface.
func (rs *rpcServer) SetGroupPermissions(ctx context.Context, req *charon.SetGroupPermissionsRequest) (*charon.SetGroupPermissionsResponse, error) {
	h := &setGroupPermissionsHandler{
		handler: newHandler(rs, ctx, "set_group_permissions"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "group permissions has been set"); err != nil {
		return nil, err
	}

	return resp, err
}

// GetPermission implements RPCServer interface.
func (rs *rpcServer) GetPermission(ctx context.Context, req *charon.GetPermissionRequest) (*charon.GetPermissionResponse, error) {
	h := &getPermissionHandler{
		handler: newHandler(rs, ctx, "get_permission"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "permission has been retrieved"); err != nil {
		return nil, err
	}

	return resp, err
}

// RegisterPermissions implements RPCServer interface.
func (rs *rpcServer) RegisterPermissions(ctx context.Context, req *charon.RegisterPermissionsRequest) (*charon.RegisterPermissionsResponse, error) {
	h := &registerPermissionsHandler{
		handler:  newHandler(rs, ctx, "register_permissions"),
		registry: rs.permissionRegistry,
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "permissions has been registered"); err != nil {
		return nil, err
	}

	return resp, err
}

// ListPermissions implements RPCServer interface.
func (rs *rpcServer) ListPermissions(ctx context.Context, req *charon.ListPermissionsRequest) (*charon.ListPermissionsResponse, error) {
	h := &listPermissionsHandler{
		handler: newHandler(rs, ctx, "list_permissions"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "list of permissions has been retrieved"); err != nil {
		return nil, err
	}

	return resp, err
}

// CreateUser implements RPCServer interface.
func (rs *rpcServer) CreateUser(ctx context.Context, req *charon.CreateUserRequest) (*charon.CreateUserResponse, error) {
	h := &createUserHandler{
		handler: newHandler(rs, ctx, "create_user"),
		hasher:  rs.passwordHasher,
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "user has been created"); err != nil {
		return nil, err
	}

	return resp, err
}

// ModifyUser implements RPCServer interface.
func (rs *rpcServer) ModifyUser(ctx context.Context, req *charon.ModifyUserRequest) (*charon.ModifyUserResponse, error) {
	h := &modifyUserHandler{
		handler: newHandler(rs, ctx, "modify_user"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "user has been modified"); err != nil {
		return nil, err
	}

	return resp, err
}

// GetUser implements RPCServer interface.
func (rs *rpcServer) GetUser(ctx context.Context, req *charon.GetUserRequest) (*charon.GetUserResponse, error) {
	h := &getUserHandler{
		handler: newHandler(rs, ctx, "get_user"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "user has been retrieved"); err != nil {
		return nil, err
	}

	return resp, err
}

// ListUsers implements RPCServer interface.
func (rs *rpcServer) ListUsers(ctx context.Context, req *charon.ListUsersRequest) (*charon.ListUsersResponse, error) {
	h := &listUsersHandler{
		handler: newHandler(rs, ctx, "list_users"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "list of users has been retrieved"); err != nil {
		return nil, err
	}

	return resp, err
}

// DeleteUser implements RPCServer interface.
func (rs *rpcServer) DeleteUser(ctx context.Context, req *charon.DeleteUserRequest) (*charon.DeleteUserResponse, error) {
	h := &deleteUserHandler{
		handler: newHandler(rs, ctx, "delete_user"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "user has been deleted"); err != nil {
		return nil, err
	}

	return resp, err
}

// SetUserGroups implements RPCServer interface.
func (rs *rpcServer) SetUserGroups(ctx context.Context, req *charon.SetUserGroupsRequest) (*charon.SetUserGroupsResponse, error) {
	h := &setUserGroupsHandler{
		handler: newHandler(rs, ctx, "set_user_groups"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "user groups has been set"); err != nil {
		return nil, err
	}

	return resp, err
}

// ListUserGroups implements RPCServer interface.
func (rs *rpcServer) ListUserGroups(ctx context.Context, req *charon.ListUserGroupsRequest) (*charon.ListUserGroupsResponse, error) {
	h := &listUserGroupsHandler{
		handler: newHandler(rs, ctx, "list_user_groups"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "list of user groups has been retrieved"); err != nil {
		return nil, err
	}

	return resp, err
}

// SetUserPermissions implements RPCServer interface.
func (rs *rpcServer) SetUserPermissions(ctx context.Context, req *charon.SetUserPermissionsRequest) (*charon.SetUserPermissionsResponse, error) {
	h := &setUserPermissionsHandler{
		handler: newHandler(rs, ctx, "set_user_permissions"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "user permissions has been set"); err != nil {
		return nil, err
	}

	return resp, err
}

// ListUserPermissions implements RPCServer interface.
func (rs *rpcServer) ListUserPermissions(ctx context.Context, req *charon.ListUserPermissionsRequest) (*charon.ListUserPermissionsResponse, error) {
	h := &listUserPermissionsHandler{
		handler: newHandler(rs, ctx, "list_user_permissions"),
	}
	h.addRequest(1)

	resp, err := h.handle(ctx, req)
	if err = h.handler.handle(err, "list of user permissions has been retrieved"); err != nil {
		return nil, err
	}

	return resp, err
}
