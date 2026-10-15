VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= bmcgrab:$(VERSION)
LDFLAGS  = -s -w -X main.version=$(VERSION)

.PHONY: all build test lint vet fmt docker helm-lint clean run-lab

all: fmt vet test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/bmcgrab ./cmd/bmcgrab

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run gofmt -w ." && exit 1)

lint:
	golangci-lint run ./...

docker:
	docker build -f deploy/docker/Dockerfile --build-arg VERSION=$(VERSION) -t $(IMAGE) .

helm-lint:
	helm lint deploy/helm/bmcgrab

run-lab:
	docker compose -f deploy/docker/docker-compose.lab.yml up --build

clean:
	rm -rf bin
