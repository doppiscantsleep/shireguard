.PHONY: all dev build test clean

# Control Plane
.PHONY: cp-dev cp-deploy cp-migrate

cp-dev:
	cd control-plane && npx wrangler dev

cp-deploy:
	cd control-plane && npx wrangler deploy

cp-migrate:
	cd control-plane && npx wrangler d1 migrations apply shireguard-db

cp-migrate-local:
	cd control-plane && npx wrangler d1 migrations apply shireguard-db --local

cp-install:
	cd control-plane && npm install

# Client
.PHONY: client-build client-build-all

client-build:
	cd client && go build -o bin/shireguard ./cmd/shireguard

client-build-all:
	cd client && GOOS=darwin GOARCH=arm64 go build -o bin/shireguard-darwin-arm64 ./cmd/shireguard
	cd client && GOOS=linux GOARCH=arm64 go build -o bin/shireguard-linux-arm64 ./cmd/shireguard

# Relay
.PHONY: relay-build

relay-build:
	cd relay && go build -o bin/shireguard-relay ./cmd/shireguard-relay

# Meta
dev: cp-dev

build: client-build relay-build

test:
	cd client && go test ./...
	cd relay && go test ./...

clean:
	rm -rf client/bin relay/bin control-plane/dist
