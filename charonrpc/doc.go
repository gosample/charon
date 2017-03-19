package charonrpc

//go:generate protoc -I=. -I=../vendor -I=${GOPATH}/src --go_out=plugins=grpc:. auth.proto user.proto group.proto permission.proto refresh_token.proto
//go:generate goimports -w auth.pb.go
