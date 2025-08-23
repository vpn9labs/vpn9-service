# VPN9 - Secure VPN Infrastructure with Rust

VPN9 is a high-performance, secure VPN infrastructure built in Rust, featuring a modular control plane architecture, distributed POP (Point of Presence) servers, and automated deployment capabilities.

## 🏗️ Architecture

### Control Plane
The control plane exposes two interfaces and manages VPN state:
- **gRPC (TLS)**: agent subscription, update checks, and streaming updates
- **REST (8080)**: JWT-authenticated peer registration for WireGuard
- **WireGuard**: interface setup and peer lifecycle
- **Config via env**: sane defaults with runtime validation

**Key Components:**
- `config.rs` - Env-driven configuration and validation
- `service.rs` - gRPC `ControlPlane` implementation
- `agent_manager.rs` - Agent subscription and lifecycle
- `update_manager.rs` - Update checks, chunked downloads, SHA256 verification
- `server.rs` - TLS gRPC server + builder
- `rest_server.rs` - JWT-verified `POST /register` endpoint
- `wireguard_manager.rs` - WireGuard interface and peer management
- `lib.rs` - Public API and in-memory key/agent registry

### VPN9 Agent
Lightweight agent that runs on POP servers and client endpoints, handling:
- Control plane communication
- WireGuard tunnel management
- System integration
- Automatic updates

Example REST registration (requires a valid JWT signed by the configured public key; if using docker-compose, expose `8080:8080` first):
```bash
curl -X POST http://localhost:8080/register \
  -H 'Content-Type: application/json' \
  -d '{"pubkey":"<base64-public-key>","token":"<jwt>"}'
```

### VPN9 Core
Shared protocol definitions and common utilities used across all components.

## 🚀 Quick Start

### Prerequisites
- Rust 1.89+ with Cargo
- Docker and Docker Compose
- Make
- Ansible (for deployment)

### Development Environment

1. **Generate TLS certificates**:
   ```bash
   make certs-generate
   ```

2. **Build and start development environment**:
   ```bash
   make dev-build
   make dev-up
   ```

3. **Test TLS connectivity**:
   ```bash
   make tls-test
   ```

4. **View logs**:
   ```bash
   make dev-logs
   ```

### Production Deployment

1. **Install Ansible dependencies**:
   ```bash
   make ansible-deps
   ```

2. **Configure inventory** in `ansible/inventory.yml`

3. **Deploy complete infrastructure**:
   ```bash
   make full-deploy
   ```

## 📋 Available Commands

```
VPN9 Control Plane Makefile

Docker Tasks:
  login-ghcr          - Login to GitHub Container Registry
  build-control-plane - Build control plane Docker image for x86_64
  push-control-plane  - Build and push control plane image
  deploy-control-plane- Push image and display completion message

Development Environment:
  dev-env             - Generate certificates and create development environment config
  dev-build           - Build development containers
  dev-up              - Start development environment (TLS-enabled)
  dev-down            - Stop development environment
  dev-logs            - Show logs from all containers
  dev-status          - Show container status
  dev-clean           - Clean up development environment and volumes
  dev-restart         - Restart development environment
  tls-test            - Test TLS connection to control plane

TLS Certificate Management:
  certs-generate      - Generate self-signed certificates for development
  certs-clean         - Remove all generated certificates
  certs-verify        - Verify certificate validity and chain
  certs-info          - Display certificate information
  certs-install       - Generate and install certificates for Ansible deployment

Ansible Tasks - Control Plane:
  ansible-deps        - Install Ansible and required collections
  ansible-check       - Verify Ansible installation
  ansible-ping        - Test connectivity to all hosts
  ansible-facts       - Gather system facts from hosts
  ansible-docker-setup- Install and configure Docker on hosts
  ansible-deploy      - Deploy control plane containers
  ansible-setup       - Complete setup (Docker + Control Plane + POP Servers)
  ansible-clean       - Remove control plane containers

Ansible Tasks - POP Servers:
  ansible-pop-setup   - Provision POP servers (install packages, configure system)
  ansible-pop-deploy  - Deploy VPN9 agent as systemd service
  ansible-pop-status  - Check agent service status on all POP servers
  ansible-pop-logs    - View recent agent logs from all POP servers
  ansible-pop-restart - Restart agent service on all POP servers

Environment Variables for Registry Authentication:
  DOCKER_REGISTRY_USERNAME - Docker registry username
  DOCKER_REGISTRY_PASSWORD - Docker registry password

Certificate Configuration Variables:
  CERT_DOMAIN         - Domain name for certificates (default: vpn9-control-plane)
  CERT_DAYS           - Certificate validity in days (default: 365)
  CERT_KEY_SIZE       - RSA key size in bits (default: 2048)
  CERTS_DIR           - Certificate output directory (default: certs)

Complete Pipeline:
  full-deploy         - Build, push image and deploy via Ansible
  help               - Show this help message
```

## ⚙️ Configuration

### Control Plane Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VPN9_BIND_ADDRESS` | gRPC bind address | `0.0.0.0:50051` |
| `VPN9_CONTROL_PLANE_VERSION` | Reported version string | `1.0.0` |
| `VPN9_UPDATE_PATH` | Directory for update artifacts | `./updates/` |
| `VPN9_TLS_CERT_PATH` | TLS certificate (PEM) | `./certs/server.crt` |
| `VPN9_TLS_KEY_PATH` | TLS private key (PEM) | `./certs/server.key` |
| `VPN9_TLS_DOMAIN` | Expected SNI/server name | `vpn9-control-plane` |
| `VPN9_REST_BIND_ADDRESS` | REST bind address | `0.0.0.0:8080` |
| `VPN9_JWT_PUBLIC_KEY_PATH` | JWT RSA public key (PEM) | `./certs/jwt_public.pem` |
| `VPN9_WIREGUARD_INTERFACE` | WireGuard interface name | `wg0` |
| `VPN9_WIREGUARD_PRIVATE_KEY` | Base64 private key (optional) | generated/empty |
| `VPN9_WIREGUARD_LISTEN_PORT` | WireGuard UDP port | `51820` |
| `VPN9_WIREGUARD_INTERFACE_ADDRESS` | CIDR for interface | `10.0.0.1/24` |

### Certificate Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `CERT_DOMAIN` | Certificate domain | `vpn9-control-plane` |
| `CERT_DAYS` | Certificate validity | `365` |
| `CERT_KEY_SIZE` | RSA key size | `2048` |
| `CERTS_DIR` | Certificate directory | `certs` |

## 🔧 Development

### Project Structure
```
vpn9-rs/
├── vpn9-control-plane/     # Control plane service
│   ├── src/
│   │   ├── lib.rs          # Module organization & key management
│   │   ├── main.rs         # Application entry point
│   │   ├── config.rs       # Configuration management
│   │   ├── service.rs      # gRPC service (ControlPlane)
│   │   ├── agent_manager.rs # Agent subscription handling
│   │   ├── update_manager.rs # Update distribution
│   │   ├── wireguard_manager.rs # WireGuard interface/peers
│   │   ├── rest_server.rs  # JWT-auth REST /register
│   │   └── server.rs       # TLS server setup
│   └── Dockerfile
├── vpn9-agent/            # VPN agent for POP servers
├── vpn9-core/             # Shared protocol definitions
├── ansible/               # Deployment automation
└── docker-compose.yml     # Development environment
```

### Building from Source

```bash
# Build all components
cargo build --workspace --release

# Build specific component
cargo build --package vpn9-control-plane --release

# Run tests
cargo test --workspace

# Check code
cargo check --workspace
```

### Testing TLS Connection

```bash
# Using grpcurl with the dev CA and correct service path
grpcurl -cacert certs/ca.crt -authority vpn9-control-plane \
  -d '{"agent_id":"test","current_version":"1.0.0"}' \
  localhost:50051 VPN9.ControlPlane/CheckForUpdate

# Alternatively (dev only), skip verification
# grpcurl -insecure -d '{"agent_id":"test","current_version":"1.0.0"}' \
#   localhost:50051 VPN9.ControlPlane/CheckForUpdate
```

## 🛡️ Security

- **TLS 1.3**: gRPC secured with server-side TLS (self-signed CA in dev)
- **JWT validation**: REST `/register` verifies RS256/384/512-signed tokens
- **SHA256 checksums**: Update integrity verification
- **WireGuard**: Interface + peers managed by control plane
- **Rust memory safety**: `rustls`, `tonic`, `tokio` throughout

## 📝 Logging

Configure logging levels with the `RUST_LOG` environment variable:

```bash
# Debug level for VPN9 components, warnings for dependencies
export RUST_LOG="vpn9_control_plane=debug,vpn9_agent=debug,tonic=warn"

# Info level (default)
export RUST_LOG="vpn9_control_plane=info,tonic=warn"
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `cargo test --workspace`
6. Submit a pull request

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only).

- See `LICENSE` for the full text.
- Copyleft applies to network use: if you modify VPN9 and provide it as a service, you must publish your changes under the same license.

## 🆘 Troubleshooting

### Common Issues

**Certificate Errors**:
```bash
make certs-clean
make certs-generate
```

**Docker Build Issues**:
```bash
make dev-clean
make dev-build
```

**Agent Connection Issues**:
```bash
# Check control plane logs
make dev-logs

# Verify certificates
make certs-verify

# Test TLS connection
make tls-test
```

**Ansible Deployment Issues**:
```bash
# Test connectivity
make ansible-ping

# Check facts gathering
make ansible-facts
```

For more detailed troubleshooting, check the logs using `make dev-logs` or `make ansible-pop-logs`.
