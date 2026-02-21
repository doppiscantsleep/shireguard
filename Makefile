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
# Usage:
#   make relay-build
#   make relay-setup              RELAY_HOST=ubuntu@1.2.3.4 RELAY_HOST_IP=1.2.3.4 RELAY_TOKEN=<secret>
#   make relay-deploy             RELAY_HOST=ubuntu@1.2.3.4
#   make relay-lightsail-firewall LIGHTSAIL_INSTANCE=shireguard-relay
#   make relay-register           RELAY_HOST=1.2.3.4 RELAY_TOKEN=<secret>
.PHONY: relay-build relay-deploy relay-setup relay-lightsail-firewall relay-register

RELAY_HOST  ?= $(error RELAY_HOST is required, e.g. RELAY_HOST=ubuntu@1.2.3.4)
RELAY_TOKEN ?= $(error RELAY_TOKEN is required)

relay-build:
	cd relay && GOOS=linux GOARCH=amd64 go build -o bin/shireguard-relay-linux-amd64 ./cmd/shireguard-relay

# First-time server setup (creates user, config, systemd service, ufw rules)
relay-setup:
	scp deploy/shireguard-relay.service deploy/relay-setup.sh $(RELAY_HOST):/tmp/
	ssh $(RELAY_HOST) "bash /tmp/relay-setup.sh $(RELAY_HOST_IP) $(RELAY_TOKEN)"

# Build and push binary, then restart the service
# Uses /tmp staging because Lightsail's ubuntu user can't scp directly to /usr/local/bin
relay-deploy: relay-build
	scp relay/bin/shireguard-relay-linux-amd64 $(RELAY_HOST):/tmp/shireguard-relay
	ssh $(RELAY_HOST) "sudo install -m 755 /tmp/shireguard-relay /usr/local/bin/shireguard-relay \
	  && sudo systemctl restart shireguard-relay \
	  && sudo systemctl status shireguard-relay --no-pager"

# Open ports in the Lightsail instance firewall (separate from ufw)
# Requires AWS CLI configured with credentials that can manage Lightsail
LIGHTSAIL_INSTANCE ?= $(error LIGHTSAIL_INSTANCE is required, e.g. LIGHTSAIL_INSTANCE=shireguard-relay)
relay-lightsail-firewall:
	aws lightsail open-instance-public-ports \
	  --instance-name $(LIGHTSAIL_INSTANCE) \
	  --port-info fromPort=8080,toPort=8080,protocol=TCP
	aws lightsail open-instance-public-ports \
	  --instance-name $(LIGHTSAIL_INSTANCE) \
	  --port-info fromPort=51821,toPort=52820,protocol=UDP
	@echo "Lightsail firewall: opened TCP 8080 and UDP 51821-52820"

# Insert relay into D1 (run after relay-deploy and relay-lightsail-firewall)
RELAY_NAME   ?= us-east-1
RELAY_REGION ?= us-east
relay-register:
	cd control-plane && npx wrangler d1 execute shireguard-db --remote \
	  --command "INSERT OR REPLACE INTO relays (id, name, region, host, port, public_key, auth_token, status) \
	             VALUES (lower(hex(randomblob(16))), '$(RELAY_NAME)', '$(RELAY_REGION)', \
	                     '$(RELAY_HOST)', 8080, '', '$(RELAY_TOKEN)', 'active')"

# Meta
dev: cp-dev

build: client-build relay-build

test:
	cd client && go test ./...
	cd relay && go test ./...

clean:
	rm -rf client/bin relay/bin control-plane/dist
