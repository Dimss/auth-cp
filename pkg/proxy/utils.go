package proxy

import (
	"fmt"
	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	runtimeservice "github.com/envoyproxy/go-control-plane/envoy/service/runtime/v3"
	secretservice "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"strconv"
	"strings"
)

func registerServer(grpcServer *grpc.Server, server server.Server) {
	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)
	endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, server)
	clusterservice.RegisterClusterDiscoveryServiceServer(grpcServer, server)
	routeservice.RegisterRouteDiscoveryServiceServer(grpcServer, server)
	listenerservice.RegisterListenerDiscoveryServiceServer(grpcServer, server)
	secretservice.RegisterSecretDiscoveryServiceServer(grpcServer, server)
	runtimeservice.RegisterRuntimeDiscoveryServiceServer(grpcServer, server)
}

func mustParseBindAddress(fullAddr string) (string, uint32, error) {
	bindAddr := strings.Split(fullAddr, ":")
	if len(bindAddr) < 2 {
		return "", 0, fmt.Errorf("wrong address format, expected: IP_OR_DNS:PORT, got: %s", fullAddr)
	}
	addr := bindAddr[0]
	port, err := strconv.ParseUint(strings.Split(fullAddr, ":")[1], 10, 32)
	if err != nil {
		return "", 0, err
	}
	return addr, uint32(port), nil
}
