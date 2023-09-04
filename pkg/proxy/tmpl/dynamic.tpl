node:
  cluster: {{ .NodeCluster }}
  id: {{ .NodeId }}

dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services:
    - envoy_grpc:
        cluster_name: {{ .ClusterName }}
  cds_config:
    resource_api_version: V3
    ads: {}
  lds_config:
    resource_api_version: V3
    ads: {}

static_resources:
  clusters:
  - type: STRICT_DNS
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
    name: {{ .ClusterName }}
    load_assignment:
      cluster_name: {{ .ClusterName }}
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: {{ .Address }}
                port_value: {{ .Port }}
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 19000