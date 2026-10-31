# Adarve · tareas de desarrollo
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
PKG     := github.com/Ruby570bocadito/adarve/internal/version
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: build test lint rules-lint fmt cross scan report clean set-repo help

help: ## Mostrar esta ayuda
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Compilar bin/adarve
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/adarve ./cmd/adarve

test: ## Ejecutar los tests
	go test ./...

lint: ## gofmt + go vet (Linux y Windows)
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...
	GOOS=windows go vet ./...

rules-lint: ## Validar el paquete de reglas
	go run ./cmd/adarve rules lint

fmt: ## Formatear el código
	gofmt -w .

cross: ## Compilar para todas las plataformas en dist/
	@for t in linux/amd64 linux/arm64 windows/amd64 windows/arm64; do \
	  os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  echo "→ $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/adarve_$${os}_$${arch}/adarve$$ext ./cmd/adarve; \
	done

scan: build ## Escanear este equipo (requiere sudo)
	sudo ./bin/adarve scan

report: build ## Escanear y abrir el informe HTML
	sudo ./bin/adarve scan --save --open

set-repo: ## Cambiar el repositorio: make set-repo REPO=usuario/adarve
	@test -n "$(REPO)" || (echo "uso: make set-repo REPO=usuario/adarve" && exit 1)
	./scripts/set-repo.sh $(REPO)

clean: ## Borrar artefactos
	rm -rf bin dist .release
