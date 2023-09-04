package proxy

import (
	"context"
	"fmt"
	"github.com/AccessibleAI/cnvrg-cap/pkg/ingresscache"
	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	elistener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	stream "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	authz "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	eupstream "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/envoyproxy/go-control-plane/pkg/test/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"
)

type upstream struct {
	Enabled bool
	Name    string
	Address string
	Port    uint32
	Timeout int64
}

type listener struct {
	Name    string
	Address string
	Port    uint32
}

type EnvoyControlPlane struct {
	Address        string
	Port           uint
	NodeCluster    string
	NodeId         string
	XdsClusterName string
	cache          cache.SnapshotCache
	AuthzCluster   *upstream
	//DefaultCluster *upstream
	Listener     *listener
	Resources    map[resource.Type][]types.Resource
	ingressCache *ingresscache.IngressCache
}

const (
	ConfigTemplate   = "tmpl/dynamic.tpl"
	NodeCluster      = "cnvrg-cluster"
	NodeId           = "cnvrg"
	ClusterName      = "xds_cluster"
	ControlPlaneAddr = "0.0.0.0"
	ControlPlanePort = 18000
)

func NewEnvoyControlPlane(ingressCache *ingresscache.IngressCache, timeout int64, authzAddr, listenerAddr string) *EnvoyControlPlane {

	listenerAddress, listenerPort, err := mustParseBindAddress(listenerAddr)
	if err != nil {
		zap.S().Fatal(err)
	}

	authzAddress, authzPort, err := mustParseBindAddress(authzAddr)
	if err != nil {
		zap.S().Fatal(err)
	}

	cp := &EnvoyControlPlane{
		Address:        ControlPlaneAddr,
		Port:           ControlPlanePort,
		NodeCluster:    NodeCluster,
		NodeId:         NodeId,
		XdsClusterName: ClusterName,
		cache:          cache.NewSnapshotCache(false, cache.IDHash{}, zap.S()),
		ingressCache:   ingressCache,
		AuthzCluster: &upstream{
			Enabled: true,
			Name:    "cnvrg_ext_authz",
			Address: authzAddress,
			//Address: "127.0.0.1",
			Port: authzPort,
			//Port:    50052,
			Timeout: timeout,
		},
		Listener: &listener{
			Name:    "listener_0",
			Address: listenerAddress,
			//Address: "0.0.0.0",
			Port: listenerPort,
			//Port:    8888,
		},
		Resources: map[resource.Type][]types.Resource{
			resource.ClusterType:  {},
			resource.ListenerType: {},
			resource.RouteType:    {},
		},
	}
	return cp
}

func (p *EnvoyControlPlane) DumpConfig() {
	zap.S().Infof("authz enabled: %t", p.AuthzCluster.Enabled)
	zap.S().Infof("authz upstream: %s:%d", p.AuthzCluster.Address, p.AuthzCluster.Port)
	zap.S().Infof("listener: %s:%d", p.Listener.Address, p.Listener.Port)
	zap.S().Infof("control plane: %s:%d", p.Address, p.Port)
}

func (p *EnvoyControlPlane) EnabledAuthz() {
	p.AuthzCluster.Enabled = true
}

func (p *EnvoyControlPlane) DisabledAuthz() {
	p.AuthzCluster.Enabled = false
}

func (p *EnvoyControlPlane) Run() {

	go func() {

		p.RunSnapshotGenerator()

		srv := server.NewServer(context.Background(), p.cache, &test.Callbacks{})

		var grpcOptions []grpc.ServerOption
		grpcOptions = append(grpcOptions,
			grpc.MaxConcurrentStreams(1000000),
			grpc.KeepaliveParams(keepalive.ServerParameters{
				Time:    30 * time.Second,
				Timeout: 5 * time.Second,
			}),
			grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
				MinTime:             30 * time.Second,
				PermitWithoutStream: true,
			}),
		)

		grpcServer := grpc.NewServer(grpcOptions...)

		lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", p.Address, p.Port))
		if err != nil {
			zap.S().Fatal(err)
		}

		registerServer(grpcServer, srv)

		if err = grpcServer.Serve(lis); err != nil {
			zap.S().Fatal(err)
		}
	}()

}

func (p *EnvoyControlPlane) makeClustersAndRoutes() {
	var clusters []types.Resource
	var virtualHosts []*route.VirtualHost

	p.ingressCache.CacheStore().Range(func(host, dataCache any) bool {
		dc := dataCache.(*ingresscache.DataCache)
		addr, port, err := mustParseBindAddress(dc.UpstreamAddr)
		if err != nil {
			return true
		}
		clusters = append(clusters, p.cluster(dc.Name, addr, port))
		virtualHosts = append(virtualHosts, p.virtualHost(dc.Name, dc.Host))
		return true
	})

	// add authz cluster only if it is enabled
	if p.AuthzCluster.Enabled {
		clusters = append(clusters, p.makeAuthzCluster())
	}

	// reset clusters
	p.Resources[resource.ClusterType] = clusters
	// reset routes
	p.Resources[resource.RouteType] = []types.Resource{
		&route.RouteConfiguration{Name: "local_route", VirtualHosts: virtualHosts},
	}

}

func (p *EnvoyControlPlane) virtualHost(name, host string) *route.VirtualHost {
	return &route.VirtualHost{
		Name:    name,
		Domains: []string{host},
		Routes: []*route.Route{{
			Name: name,
			Match: &route.RouteMatch{
				PathSpecifier: &route.RouteMatch_Prefix{
					Prefix: "/",
				},
			},
			Action: &route.Route_Route{
				Route: &route.RouteAction{
					Timeout: durationpb.New(0 * time.Second), // zero meaning disabled
					ClusterSpecifier: &route.RouteAction_Cluster{
						Cluster: name,
					},
				},
			},
		}},
	}
}

func (p *EnvoyControlPlane) cluster(name, addr string, port uint32) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                 name,
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
		ConnectTimeout:       durationpb.New(20 * time.Second),
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		DnsLookupFamily:      cluster.Cluster_V4_ONLY,
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*endpoint.LocalityLbEndpoints{{
				LbEndpoints: []*endpoint.LbEndpoint{{
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{
						Endpoint: &endpoint.Endpoint{
							Address: &core.Address{
								Address: &core.Address_SocketAddress{
									SocketAddress: &core.SocketAddress{
										Protocol: core.SocketAddress_TCP,
										Address:  addr,
										PortSpecifier: &core.SocketAddress_PortValue{
											PortValue: port,
										},
									},
								},
							},
						},
					},
				}},
			}},
		},
	}
}

func (p *EnvoyControlPlane) buildHttpFilters() []*hcm.HttpFilter {

	var filters []*hcm.HttpFilter

	if p.AuthzCluster.Enabled {

		authzGrpcSvc, err := anypb.New(&authz.ExtAuthz{
			Services: &authz.ExtAuthz_GrpcService{
				GrpcService: &core.GrpcService{
					TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
							ClusterName: p.AuthzCluster.Name,
						},
					},
					Timeout: &duration.Duration{Seconds: p.AuthzCluster.Timeout},
				},
			},
			TransportApiVersion:    core.ApiVersion_V3,
			IncludePeerCertificate: false,
		})

		if err != nil {
			zap.S().Error(err)
		}

		filters = append(filters, &hcm.HttpFilter{
			Name:       wellknown.HTTPExternalAuthorization,
			ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: authzGrpcSvc},
		})
	}

	routerConfig, err := anypb.New(&router.Router{StartChildSpan: false})

	if err != nil {
		zap.S().Error(err)
	}

	filters = append(filters, &hcm.HttpFilter{
		Name:       wellknown.Router,
		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerConfig},
	})

	return filters
}

func (p *EnvoyControlPlane) buildHttpManager() *hcm.HttpConnectionManager {
	stdoutLogs, _ := anypb.New(&stream.StdoutAccessLog{})
	tracingConfig := &hcm.HttpConnectionManager_Tracing{}

	if viper.GetBool("tracing-enabled") {
		if viper.GetString("jaeger-addr") == "" {
			zap.S().Fatal("tracing is enabled by jaeger address is not set")
		}

		zipkinTracingConf := &tracev3.ZipkinConfig{
			CollectorCluster:  "jaeger",
			CollectorEndpoint: "/api/v2/spans",
			SharedSpanContext: &wrappers.BoolValue{
				Value: true,
			},
			CollectorEndpointVersion: 1,
		}

		zipkinConfMarshalled, err := anypb.New(zipkinTracingConf)
		if err != nil {
			zap.S().Error(err)
		}
		tracingConfig = &hcm.HttpConnectionManager_Tracing{
			Verbose: true,
			Provider: &tracev3.Tracing_Http{
				Name: "envoy.tracers.zipkin",
				ConfigType: &tracev3.Tracing_Http_TypedConfig{
					TypedConfig: zipkinConfMarshalled,
				},
			},
		}
	}

	return &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_AUTO,
		StatPrefix: "http",
		GenerateRequestId: &wrappers.BoolValue{
			Value: true,
		},
		AccessLog: []*accesslog.AccessLog{
			{
				Name: "envoy.access_loggers.stdout",
				ConfigType: &accesslog.AccessLog_TypedConfig{
					TypedConfig: stdoutLogs,
				},
			},
		},
		Tracing:        tracingConfig,
		HttpFilters:    p.buildHttpFilters(),
		UpgradeConfigs: []*hcm.HttpConnectionManager_UpgradeConfig{{UpgradeType: "websocket"}},
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				RouteConfigName: "local_route",
				ConfigSource: &core.ConfigSource{
					ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
						ApiConfigSource: &core.ApiConfigSource{
							ApiType:                   core.ApiConfigSource_GRPC,
							TransportApiVersion:       resource.DefaultAPIVersion,
							SetNodeOnFirstMessageOnly: true,
							GrpcServices: []*core.GrpcService{{
								TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
									EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
										ClusterName: p.XdsClusterName,
									},
								},
							}},
						}},
					ResourceApiVersion: resource.DefaultAPIVersion,
				},
			},
		},
	}
}

func (p *EnvoyControlPlane) makeListener() {

	mgr, _ := anypb.New(p.buildHttpManager())

	l := &elistener.Listener{
		Name: p.Listener.Name,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  p.Listener.Address,
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: p.Listener.Port,
					},
				},
			}},
		FilterChains: []*elistener.FilterChain{{
			Filters: []*elistener.Filter{{
				Name:       wellknown.HTTPConnectionManager,
				ConfigType: &elistener.Filter_TypedConfig{TypedConfig: mgr},
			}},
		}},
	}
	p.Resources[resource.ListenerType] = []types.Resource{l}
}

func (p *EnvoyControlPlane) makeAuthzCluster() *cluster.Cluster {

	protoOptions, _ := anypb.New(&eupstream.HttpProtocolOptions{
		UpstreamProtocolOptions: &eupstream.HttpProtocolOptions_ExplicitHttpConfig_{
			ExplicitHttpConfig: &eupstream.HttpProtocolOptions_ExplicitHttpConfig{
				ProtocolConfig: &eupstream.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{},
			},
		},
	})

	return &cluster.Cluster{
		Name:                 p.AuthzCluster.Name,
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
		ConnectTimeout:       durationpb.New(20 * time.Second),
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": protoOptions},
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: "cnvrg_svc_cluster",
			Endpoints: []*endpoint.LocalityLbEndpoints{{
				LbEndpoints: []*endpoint.LbEndpoint{{
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{
						Endpoint: &endpoint.Endpoint{
							Address: &core.Address{
								Address: &core.Address_SocketAddress{
									SocketAddress: &core.SocketAddress{
										Protocol: core.SocketAddress_TCP,
										Address:  p.AuthzCluster.Address,
										PortSpecifier: &core.SocketAddress_PortValue{
											PortValue: p.AuthzCluster.Port,
										},
									},
								},
							},
						},
					},
				}},
			}},
		},
	}

}

func (p *EnvoyControlPlane) makeJaegerCluster() {
	jaegerHost, jaegerPortStr, err := net.SplitHostPort(viper.GetString("jaeger-addr"))
	if err != nil {
		zap.S().Errorf("failed to parse jaeger address %v", err)
	}
	jaegerPort, err := strconv.Atoi(jaegerPortStr)
	if err != nil {
		zap.S().Errorf("failed to parse jaeger port %v", err)
	}

	c := &cluster.Cluster{
		Name:                 "jaeger",
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
		ConnectTimeout:       durationpb.New(20 * time.Second),
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: "jaeger",
			Endpoints: []*endpoint.LocalityLbEndpoints{{
				LbEndpoints: []*endpoint.LbEndpoint{{
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{
						Endpoint: &endpoint.Endpoint{
							Address: &core.Address{
								Address: &core.Address_SocketAddress{
									SocketAddress: &core.SocketAddress{
										Protocol: core.SocketAddress_TCP,
										Address:  jaegerHost,
										PortSpecifier: &core.SocketAddress_PortValue{
											PortValue: uint32(jaegerPort),
										},
									},
								},
							},
						},
					},
				}},
			}},
		},
	}

	p.Resources[resource.ClusterType] = append(p.Resources[resource.ClusterType], c)

}

func (p *EnvoyControlPlane) RunSnapshotGenerator() {

	go func() {
		// static configuration
		p.makeListener()
		p.makeAuthzCluster()
		// dynamic configs
		for _ = range p.ingressCache.Notifier() {
			if viper.GetBool("tracing-enabled") {
				p.makeJaegerCluster()
			}

			p.makeClustersAndRoutes()

			snap, _ := cache.NewSnapshot(fmt.Sprintf("%d", rand.Int()), p.Resources)

			if err := snap.Consistent(); err != nil {
				zap.S().Errorf("snapshot inconsistency: %+v\n%+v", snap, err)
				os.Exit(1)
			}

			if err := p.cache.SetSnapshot(context.Background(), p.NodeId, snap); err != nil {
				zap.S().Error(err)
				os.Exit(1)
			}
		}
	}()

}
