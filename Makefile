# VPN9 Control Plane Docker Build and Push

# Load environment variables from .env and .env.local if present
ifneq (,$(wildcard .env))
include .env
endif
ifneq (,$(wildcard .env.local))
include .env.local
endif
# Export all variables to subprocesses (docker, ansible, etc.)
export

REGISTRY := ghcr.io
IMAGE_NAME := vpn9labs/vpn9-control-plane
TAG := latest

# Ansible configuration
ANSIBLE_DIR := ansible
ANSIBLE_INVENTORY := inventory.yml
ANSIBLE_PLAYBOOK := ansible-playbook
ANSIBLE_OPTS := -i $(ANSIBLE_INVENTORY) -v

# Docker Compose configuration
COMPOSE_FILE := docker-compose.yml
COMPOSE_PROJECT := vpn9-dev

# TLS Certificate configuration
CERTS_DIR := certs
CERT_DOMAIN := vpn9-control-plane
CERT_DAYS := 365
CERT_KEY_SIZE := 2048
VAULT_CERTS_DIR := $(CERTS_DIR)/vault
VAULT_CERT_DOMAIN := $(if $(VAULT_DOMAIN),$(VAULT_DOMAIN),vpn9-vault)
VAULT_CERT_DAYS := 825
VAULT_CERT_KEY_SIZE := 4096

.PHONY: login-ghcr build-control-plane push-control-plane deploy-control-plane
.PHONY: ansible-check ansible-deps ansible-setup ansible-deploy ansible-docker-setup
.PHONY: ansible-ping ansible-facts ansible-clean full-deploy help
.PHONY: dev-build dev-up dev-down dev-logs dev-status dev-clean dev-restart
.PHONY: ansible-pop-setup ansible-pop-deploy ansible-pop-status ansible-pop-logs ansible-pop-restart
.PHONY: ansible-vault-setup ansible-vault-status ansible-vault-logs ansible-vault-restart
.PHONY: certs-generate certs-clean certs-verify certs-info certs-install certs-vault
.PHONY: dev-env tls-test

login-ghcr:
	docker login $(REGISTRY)

build-control-plane:
	docker build --platform linux/amd64 -f Dockerfile.control-plane -t $(REGISTRY)/$(IMAGE_NAME):$(TAG) .

push-control-plane: build-control-plane
	docker push $(REGISTRY)/$(IMAGE_NAME):$(TAG)

deploy-control-plane: push-control-plane
	@echo "Control plane image pushed to $(REGISTRY)/$(IMAGE_NAME):$(TAG)"

# Ansible Tasks

ansible-check:
	@command -v ansible >/dev/null 2>&1 || { echo >&2 "Ansible is required but not installed. Run 'make ansible-deps' first."; exit 1; }
	@command -v ansible-playbook >/dev/null 2>&1 || { echo >&2 "ansible-playbook is required but not installed. Run 'make ansible-deps' first."; exit 1; }
	@echo "Ansible is installed and ready to use"

ansible-deps:
	@echo "Installing Ansible dependencies..."
	ansible-galaxy collection install community.docker
	@echo "Ansible installation complete"

ansible-ping: ansible-check
	@echo "Testing connectivity to all hosts..."
	cd $(ANSIBLE_DIR) && ansible all $(ANSIBLE_OPTS) -m ping

ansible-facts: ansible-check
	@echo "Gathering facts from all hosts..."
	cd $(ANSIBLE_DIR) && ansible all $(ANSIBLE_OPTS) -m setup

ansible-docker-setup: ansible-check
	@echo "Setting up Docker on target hosts..."
	cd $(ANSIBLE_DIR) && $(ANSIBLE_PLAYBOOK) $(ANSIBLE_OPTS) docker-setup.yml

ansible-deploy: ansible-check
	@echo "Deploying VPN9 control plane..."
	@if [ -z "$(DOCKER_REGISTRY_USERNAME)" ] || [ -z "$(DOCKER_REGISTRY_PASSWORD)" ]; then \
		echo "Info: DOCKER_REGISTRY_USERNAME/PASSWORD not set. Registry login will be skipped."; \
	fi
	cd $(ANSIBLE_DIR) && $(ANSIBLE_PLAYBOOK) $(ANSIBLE_OPTS) \
		$(if $(DOCKER_REGISTRY_USERNAME),-e docker_registry_username="$(DOCKER_REGISTRY_USERNAME)") \
		$(if $(DOCKER_REGISTRY_PASSWORD),-e docker_registry_password="$(DOCKER_REGISTRY_PASSWORD)") \
		$(if $(REDIS_PASSWORD),-e redis_password="$(REDIS_PASSWORD)") \
		deploy-control-plane.yml

ansible-setup: ansible-check
	@echo "Running complete setup (Docker + Control Plane)..."
	@if [ -z "$(DOCKER_REGISTRY_USERNAME)" ] || [ -z "$(DOCKER_REGISTRY_PASSWORD)" ]; then \
		echo "Info: DOCKER_REGISTRY_USERNAME/PASSWORD not set. Registry login will be skipped."; \
	fi
	cd $(ANSIBLE_DIR) && $(ANSIBLE_PLAYBOOK) $(ANSIBLE_OPTS) \
		$(if $(DOCKER_REGISTRY_USERNAME),-e docker_registry_username="$(DOCKER_REGISTRY_USERNAME)") \
		$(if $(DOCKER_REGISTRY_PASSWORD),-e docker_registry_password="$(DOCKER_REGISTRY_PASSWORD)") \
		$(if $(REDIS_PASSWORD),-e redis_password="$(REDIS_PASSWORD)") \
		site.yml

ansible-clean: ansible-check
	@echo "Stopping and removing VPN9 control plane containers..."
	cd $(ANSIBLE_DIR) && ansible control_plane $(ANSIBLE_OPTS) -b -m docker_container -a "name=vpn9-control-plane state=absent"

# POP Server Management Tasks

ansible-pop-setup: ansible-check
	@echo "Provisioning VPN9 POP servers..."
	cd $(ANSIBLE_DIR) && $(ANSIBLE_PLAYBOOK) $(ANSIBLE_OPTS) pop-server-setup.yml

ansible-pop-deploy: ansible-check
	@echo "Deploying VPN9 agent to POP servers..."
	cd $(ANSIBLE_DIR) && $(ANSIBLE_PLAYBOOK) $(ANSIBLE_OPTS) deploy-agent.yml

ansible-pop-status: ansible-check
	@echo "Checking VPN9 agent status on POP servers..."
	cd $(ANSIBLE_DIR) && ansible pop_servers $(ANSIBLE_OPTS) -b -m systemd -a "name=vpn9-agent"

ansible-pop-logs: ansible-check
	@echo "Getting VPN9 agent logs from POP servers..."
	cd $(ANSIBLE_DIR) && ansible pop_servers $(ANSIBLE_OPTS) -b -a "journalctl -u vpn9-agent -n 20 --no-pager"

ansible-pop-restart: ansible-check
	@echo "Restarting VPN9 agent on POP servers..."
	cd $(ANSIBLE_DIR) && ansible pop_servers $(ANSIBLE_OPTS) -b -m systemd -a "name=vpn9-agent state=restarted"

# Vault Server Management Tasks

ansible-vault-setup: ansible-check
	@echo "Provisioning HashiCorp Vault servers..."
	cd $(ANSIBLE_DIR) && $(ANSIBLE_PLAYBOOK) $(ANSIBLE_OPTS) vault-server-setup.yml

ansible-vault-status: ansible-check
	@echo "Checking Vault service status..."
	cd $(ANSIBLE_DIR) && ansible vault_servers $(ANSIBLE_OPTS) -b -m systemd -a "name=vault"

ansible-vault-logs: ansible-check
	@echo "Retrieving Vault service logs..."
	cd $(ANSIBLE_DIR) && ansible vault_servers $(ANSIBLE_OPTS) -b -a "journalctl -u vault -n 50 --no-pager"

ansible-vault-restart: ansible-check
	@echo "Restarting Vault service..."
	cd $(ANSIBLE_DIR) && ansible vault_servers $(ANSIBLE_OPTS) -b -m systemd -a "name=vault state=restarted"

# Development Environment Tasks

dev-build:
	@echo "Building development containers..."
	USERID=$(shell id -u) GROUPID=$(shell id -g) docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) build

dev-up: dev-env dev-build
	@echo "Starting development environment..."
	USERID=$(shell id -u) GROUPID=$(shell id -g) docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) --profile testing up -d
	@echo "Development environment started. Control plane available at https://$(CERT_DOMAIN):50051"
	@echo "Note: Add '127.0.0.1 $(CERT_DOMAIN)' to /etc/hosts for local testing"

dev-down:
	@echo "Stopping development environment..."
	USERID=$(shell id -u) GROUPID=$(shell id -g) docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) down

dev-logs:
	@echo "Showing logs from development environment..."
	USERID=$(shell id -u) GROUPID=$(shell id -g) docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) logs -f

dev-status:
	@echo "Development environment status:"
	USERID=$(shell id -u) GROUPID=$(shell id -g) docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) ps

dev-clean:
	@echo "Cleaning up development environment..."
	USERID=$(shell id -u) GROUPID=$(shell id -g) docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) down -v --remove-orphans
	USERID=$(shell id -u) GROUPID=$(shell id -g) docker-compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) rm -f

dev-restart: dev-down dev-up
	@echo "Development environment restarted"

# TLS Certificate Management Tasks

certs-generate:
	@echo "Generating TLS certificates for domain: $(CERT_DOMAIN)"
	@echo "Certificate validity: $(CERT_DAYS) days"
	@echo "Key size: $(CERT_KEY_SIZE) bits"
	VPN9_TLS_DOMAIN=$(CERT_DOMAIN) VPN9_KEY_SIZE=$(CERT_KEY_SIZE) VPN9_CERT_DAYS=$(CERT_DAYS) ./scripts/generate-certs.sh

certs-vault:
	@echo "Generating TLS certificates for Vault: $(VAULT_CERT_DOMAIN)"
	@echo "Certificate validity: $(VAULT_CERT_DAYS) days"
	@echo "Key size: $(VAULT_CERT_KEY_SIZE) bits"
	VAULT_TLS_DOMAIN=$(VAULT_CERT_DOMAIN) VAULT_TLS_KEY_SIZE=$(VAULT_CERT_KEY_SIZE) VAULT_TLS_CERT_DAYS=$(VAULT_CERT_DAYS) ./scripts/generate-vault-certs.sh

certs-clean:
	@echo "Removing all generated certificates..."
	rm -rf $(CERTS_DIR)
	@echo "Certificates removed from $(CERTS_DIR)/"

certs-verify:
	@echo "Verifying certificate validity..."
	@if [ ! -f "$(CERTS_DIR)/server.crt" ]; then \
		echo "Error: Server certificate not found at $(CERTS_DIR)/server.crt"; \
		echo "Run 'make certs-generate' first"; \
		exit 1; \
	fi
	@echo "Checking certificate chain..."
	openssl verify -CAfile $(CERTS_DIR)/ca.crt $(CERTS_DIR)/server.crt
	@echo "Checking certificate expiration..."
	openssl x509 -in $(CERTS_DIR)/server.crt -noout -dates
	@echo "Certificate verification complete"

certs-info:
	@echo "Certificate Information:"
	@if [ ! -f "$(CERTS_DIR)/server.crt" ]; then \
		echo "No certificates found. Run 'make certs-generate' first"; \
		exit 1; \
	fi
	@echo "CA Certificate:"
	openssl x509 -in $(CERTS_DIR)/ca.crt -noout -subject -issuer -dates
	@echo ""
	@echo "Server Certificate:"
	openssl x509 -in $(CERTS_DIR)/server.crt -noout -subject -issuer -dates
	@echo ""
	@echo "Subject Alternative Names:"
	openssl x509 -in $(CERTS_DIR)/server.crt -noout -ext subjectAltName
	@echo ""
	@echo "Client Certificate:"
	openssl x509 -in $(CERTS_DIR)/client.crt -noout -subject -issuer -dates

certs-install: certs-generate
	@echo "Installing certificates for Docker deployment..."
	@mkdir -p ansible/roles/vpn9-control-plane/files/certs
	cp $(CERTS_DIR)/server.crt ansible/roles/vpn9-control-plane/files/certs/
	cp $(CERTS_DIR)/server.key ansible/roles/vpn9-control-plane/files/certs/
	cp $(CERTS_DIR)/ca.crt ansible/roles/vpn9-control-plane/files/certs/
	@echo "Certificates copied to Ansible deployment directory"

# Development Environment Setup

dev-env: certs-generate
	@echo "Setting up development environment..."
	@echo "Loading TLS environment variables..."
	@echo "# TLS Environment Variables" > .env.local
	@echo "export VPN9_TLS_CERT_PATH=./$(CERTS_DIR)/server.crt" >> .env.local
	@echo "export VPN9_TLS_KEY_PATH=./$(CERTS_DIR)/server.key" >> .env.local
	@echo "export VPN9_TLS_CA_CERT_PATH=./$(CERTS_DIR)/ca.crt" >> .env.local
	@echo "export VPN9_TLS_DOMAIN=$(CERT_DOMAIN)" >> .env.local
	@echo "export VPN9_CONTROL_PLANE_URL=https://$(CERT_DOMAIN):50051" >> .env.local
	@echo "Development environment configured in .env.local"
	@echo "Run 'source .env.local' to load environment variables"

tls-test: certs-verify
	@echo "Testing TLS connection to control plane..."
	@echo "Checking if control plane is running..."
	@if ! ss -tln | grep -q :50051; then \
		echo "Error: Control plane not running on port 50051"; \
		echo "Start it with 'make dev-up' or run manually"; \
		exit 1; \
	fi
	@echo "Testing TLS handshake..."
	@timeout 5 openssl s_client -connect localhost:50051 -servername $(CERT_DOMAIN) -CAfile $(CERTS_DIR)/ca.crt < /dev/null
	@echo "TLS connection test completed"

# Complete deployment pipeline
full-deploy: push-control-plane ansible-setup
	@echo "Complete deployment finished: Docker image built, pushed, and deployed via Ansible"

# Help target
help:
	@echo "VPN9 Makefile"
	@echo ""
	@echo "Docker Tasks:"
	@echo "  login-ghcr          - Login to GitHub Container Registry"
	@echo "  build-control-plane - Build control plane Docker image for x86_64"
	@echo "  push-control-plane  - Build and push control plane image"
	@echo "  deploy-control-plane- Push image and display completion message"
	@echo ""
	@echo "Development Environment:"
	@echo "  dev-env             - Generate certificates and create development environment config"
	@echo "  dev-build           - Build development containers"
	@echo "  dev-up              - Start development environment (TLS-enabled)"
	@echo "  dev-down            - Stop development environment"
	@echo "  dev-logs            - Show logs from all containers"
	@echo "  dev-status          - Show container status"
	@echo "  dev-clean           - Clean up development environment and volumes"
	@echo "  dev-restart         - Restart development environment"
	@echo "  tls-test            - Test TLS connection to control plane"
	@echo ""
	@echo "TLS Certificate Management:"
	@echo "  certs-generate      - Generate self-signed certificates for development"
	@echo "  certs-vault         - Generate dedicated certificates for Vault"
	@echo "  certs-clean         - Remove all generated certificates"
	@echo "  certs-verify        - Verify certificate validity and chain"
	@echo "  certs-info          - Display certificate information"
	@echo "  certs-install       - Generate and install certificates for Ansible deployment"
	@echo ""
	@echo "Ansible Tasks - Control Plane:"
	@echo "  ansible-deps        - Install Ansible and required collections"
	@echo "  ansible-check       - Verify Ansible installation"
	@echo "  ansible-ping        - Test connectivity to all hosts"
	@echo "  ansible-facts       - Gather system facts from hosts"
	@echo "  ansible-docker-setup- Install and configure Docker on hosts"
	@echo "  ansible-deploy      - Deploy control plane containers"
	@echo "  ansible-setup       - Complete setup (Docker + Control Plane + POP Servers)"
	@echo "  ansible-clean       - Remove control plane containers"
	@echo ""
	@echo "Ansible Tasks - POP Servers:"
	@echo "  ansible-pop-setup   - Provision POP servers (install packages, configure system)"
	@echo "  ansible-pop-deploy  - Deploy VPN9 agent as systemd service"
	@echo "  ansible-pop-status  - Check agent service status on all POP servers"
	@echo "  ansible-pop-logs    - View recent agent logs from all POP servers"
	@echo "  ansible-pop-restart - Restart agent service on all POP servers"
	@echo ""
	@echo "Ansible Tasks - Vault:"
	@echo "  ansible-vault-setup   - Provision and harden Vault servers"
	@echo "  ansible-vault-status  - Check Vault systemd service"
	@echo "  ansible-vault-logs    - Tail recent Vault journal entries"
	@echo "  ansible-vault-restart - Restart Vault service"
	@echo ""
	@echo "Environment Variables for Registry Authentication:"
	@echo "  DOCKER_REGISTRY_USERNAME - Docker registry username"
	@echo "  DOCKER_REGISTRY_PASSWORD - Docker registry password"
	@echo ""
	@echo "Certificate Configuration Variables:"
	@echo "  CERT_DOMAIN         - Domain name for certificates (default: $(CERT_DOMAIN))"
	@echo "  CERT_DAYS           - Certificate validity in days (default: $(CERT_DAYS))"
	@echo "  CERT_KEY_SIZE       - RSA key size in bits (default: $(CERT_KEY_SIZE))"
	@echo "  CERTS_DIR           - Certificate output directory (default: $(CERTS_DIR))"
	@echo "  VAULT_CERT_DOMAIN   - Domain used for Vault certificates (default: $(VAULT_CERT_DOMAIN))"
	@echo "  VAULT_CERT_DAYS     - Vault certificate validity days (default: $(VAULT_CERT_DAYS))"
	@echo "  VAULT_CERT_KEY_SIZE - Vault key size in bits (default: $(VAULT_CERT_KEY_SIZE))"
	@echo ""
	@echo "Complete Pipeline:"
	@echo "  full-deploy         - Build, push image and deploy via Ansible"
	@echo "  help               - Show this help message"
