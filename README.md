# VPN9 - Secure VPN Infrastructure with Rust

VPN9 is a high-performance, secure VPN infrastructure built in Rust, featuring a modular control plane architecture, distributed POP (Point of Presence) servers, and automated deployment capabilities.

## 🏗️ Architecture

### Control Plane
The control plane is a modular gRPC-based service that manages:
- **Agent Registration**: WireGuard key management and agent lifecycle
- **Update Distribution**: Secure update delivery with SHA256 verification
- **TLS Communication**: Certificate-based secure communication
- **Configuration Management**: Environment-based configuration

**Key Components:**
- `config.rs` - Configuration management and environment variables
- `agent_manager.rs` - Agent subscription and WireGuard key handling
- `update_manager.rs` - Update distribution with checksums and streaming
- `service.rs` - Main gRPC service implementing the ControlPlane interface
- `server.rs` - TLS server setup with builder pattern
- `lib.rs` - Module organization, key management, and public API

### VPN9 Agent
Lightweight agent that runs on POP servers and client endpoints, handling:
- Control plane communication
- WireGuard tunnel management
- System integration
- Automatic updates

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
  login-gitea         - Login to Gitea Docker registry
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
| `VPN9_BIND_ADDRESS` | Server bind address | `0.0.0.0:50051` |
| `VPN9_CURRENT_VERSION` | Current software version | `1.0.0` |
| `VPN9_UPDATE_PATH` | Path to update files | `./updates/` |
| `VPN9_TLS_CERT_PATH` | TLS certificate path | `./certs/server.crt` |
| `VPN9_TLS_KEY_PATH` | TLS private key path | `./certs/server.key` |
| `VPN9_TLS_DOMAIN` | TLS domain name | `vpn9-control-plane` |

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
│   │   ├── service.rs      # Main gRPC service
│   │   ├── agent_manager.rs # Agent subscription handling
│   │   ├── update_manager.rs # Update distribution
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
# Test with grpcurl (install: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest)
grpcurl -insecure -d '{"agent_id":"test","current_version":"1.0.0"}' \
  localhost:50051 \
  vpn9.control_plane.ControlPlane/CheckForUpdate
```

## 🛡️ Security

- **TLS 1.3**: All communication encrypted with modern TLS
- **Certificate Verification**: Mutual TLS authentication
- **SHA256 Checksums**: Update integrity verification
- **WireGuard**: Industry-standard VPN protocol
- **Rust Memory Safety**: Memory-safe implementation

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

This project is licensed under the MIT License - see the LICENSE file for details.

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
