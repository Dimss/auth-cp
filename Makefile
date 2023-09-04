build:
	go build -o bin/proxy cmd/proxy/main.go
	go build -o bin/authz cmd/authz/main.go

docker-dev:
	docker buildx build --platform linux/amd64 --push -t cnvrg/cap-dvl:latest -f Dockerfile.dev .

remote-sync:
	kubectl cp go.mod $(shell kubectl get pods -lapp=cnvrg-authz -A -ojson | jq -r '.items[] | .metadata.namespace + "/" + .metadata.name'):/opt/workdir --no-preserve=true
	kubectl cp go.sum $(shell kubectl get pods -lapp=cnvrg-authz -A -ojson | jq -r '.items[] | .metadata.namespace + "/" + .metadata.name'):/opt/workdir --no-preserve=true
	kubectl cp cmd $(shell kubectl get pods -lapp=cnvrg-authz -A -ojson | jq -r '.items[] | .metadata.namespace + "/" + .metadata.name'):/opt/workdir --no-preserve=true
	kubectl cp pkg $(shell kubectl get pods -lapp=cnvrg-authz -A -ojson | jq -r '.items[] | .metadata.namespace + "/" + .metadata.name'):/opt/workdir --no-preserve=true

debug-remote:
	dlv debug --headless --listen=:2345 --api-version=2 --accept-multiclient ./cmd/authz/main.go

docker:
	docker buildx build --platform linux/amd64 --build-arg buildsha=$$(git rev-parse --short HEAD) --push -t cnvrg/cnvrg-proxy:$$(git rev-parse --short HEAD) .

run-proxy:
	bin/proxy -u 127.0.0.1:8000 -z proxy.cnvrg-proxy.azops.cnvrg.io:50052