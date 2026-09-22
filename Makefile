.PHONY: all build test clean run-server run-agent package-deb package-rpm

export PATH := $(HOME)/go/bin:/usr/local/go/bin:$(PATH)

all: build test

build: build-server build-agent

build-server:
	@echo "==> Compilando fw-server..."
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/fw-server ./cmd/fw-server

build-agent:
	@echo "==> Compilando fw-agent..."
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/fw-agent ./cmd/fw-agent

build-web:
	@echo "==> Compilando frontend SPA React..."
	cd web && npm install && npm run build

test:
	@echo "==> Executando testes unitários..."
	go test -v ./internal/parser/...
	go test -v ./...

package-deb: build
	@echo "==> Gerando pacotes .deb com nfpm..."
	nfpm package --config packaging/nfpm-agent.yaml --packager deb --target dist/
	nfpm package --config packaging/nfpm-server.yaml --packager deb --target dist/

package-rpm: build
	@echo "==> Gerando pacotes .rpm com nfpm..."
	nfpm package --config packaging/nfpm-agent.yaml --packager rpm --target dist/
	nfpm package --config packaging/nfpm-server.yaml --packager rpm --target dist/

clean:
	rm -rf bin/ dist/ data/ certs_data/ agent_certs/ agent_state/ web/dist/
