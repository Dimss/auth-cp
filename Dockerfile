FROM envoyproxy/envoy:v1.26-latest as envoy

# Build the manager binary
FROM golang:1.20.1 as builder
ARG buildsha
WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/ cmd/
COPY pkg/ pkg/

# Build
RUN go build -ldflags="-X 'main.Build=${buildsha}'"  -o proxy cmd/proxy/main.go
RUN go build -ldflags="-X 'main.Build=${buildsha}'"  -o authz cmd/authz/main.go

FROM debian:bookworm-slim
USER 1000
WORKDIR /opt/app-root
COPY --from=envoy /usr/local/bin/envoy /usr/local/bin/envoy
COPY --from=builder /workspace/proxy .
COPY --from=builder /workspace/authz .