# VPN9 Alpine Build

A Docker-based build system for creating custom Alpine Linux ISOs with WireGuard VPN and networking support.

## Overview

This project builds a minimal Alpine Linux ISO (`alpine-vpn9-pop-3.22-x86_64.iso`) that includes:

- WireGuard VPN tools
- SSH server with pre-configured authorized keys
- Essential networking utilities (iptables, iproute2)
- Hardware support (CPU microcode, drivers)
- Long-term support kernel

## Project Structure

```
vpn9-alpine-build/
├── mkimage.sh                    # Main build script
├── Dockerfile.build-vpn9-pop     # Docker build environment
├── profiles/
│   ├── mkimg.vpn9-pop.sh        # Alpine profile configuration
│   ├── genapkovl-vpn9-pop.sh    # System overlay generator
│   └── authorized_keys          # SSH public keys
├── keys/
│   ├── build-6888fcb3.rsa       # Package signing private key
│   └── build-6888fcb3.rsa.pub   # Package signing public key
└── artifacts/
    └── alpine-vpn9-pop-3.22-x86_64.iso  # Generated ISO
```

## Prerequisites

- Docker
- Bash shell

## Quick Start

1. **Configure SSH access** (optional):
   ```bash
   # Add your SSH public keys to enable remote access
   echo "ssh-ed25519 AAAAC3NzaC1... user@hostname" >> profiles/authorized_keys
   ```

2. **Build the ISO**:
   ```bash
   ./mkimage.sh
   ```

3. **Find the generated ISO**:
   ```bash
   ls -la artifacts/alpine-vpn9-pop-3.22-x86_64.iso
   ```

## Configuration

### SSH Access

The build includes SSH server configuration with authorized key support:

- Keys are read from `profiles/authorized_keys`
- SSH daemon starts automatically on boot
- Root login is enabled with key-based authentication

### Network Configuration

The generated system includes:
- DHCP client for automatic IP configuration on eth0
- WireGuard tools for VPN setup
- iptables for firewall configuration
- Essential networking utilities

### Packages Included

Core packages in the ISO:
- `linux-lts` - Long-term support kernel
- `wireguard-tools` - WireGuard VPN utilities
- `openssh` - SSH server and client
- `iptables` - Firewall utilities
- `iproute2` - Advanced networking tools
- `haveged` - Entropy daemon
- `intel-ucode` & `amd-ucode` - CPU microcode updates

## Build Process

The build process:

1. Creates a Docker container with Alpine 3.22 and build tools
2. Downloads Alpine aports (package build scripts)
3. Copies custom profile and overlay scripts
4. Generates system overlay with SSH keys and configuration
5. Builds the final ISO using Alpine's mkimage.sh

## Customization

### Adding Packages

Edit `profiles/mkimg.vpn9-pop.sh` and add packages to the `apks` variable:

```bash
apks="$apks
      your-package-name
      another-package
      "
```

### System Configuration

Modify `profiles/genapkovl-vpn9-pop.sh` to:
- Change hostname
- Modify network settings
- Add custom configuration files
- Configure additional services

### Build Environment

Update `Dockerfile.build-vpn9-pop` to:
- Change Alpine base version
- Add build dependencies
- Modify build environment

## Usage

Boot the generated ISO to get a minimal Alpine Linux system with:
- SSH access (if keys configured)
- WireGuard ready for VPN configuration
- DHCP networking on eth0
- Essential system services

## Security Notes

- SSH root login is enabled by default
- System uses key-based authentication only
- Keep `profiles/authorized_keys` secure
- Private signing keys in `keys/` directory should be protected
- Generated ISO includes your SSH public keys

## Troubleshooting

### Build Issues

- Ensure Docker is running and accessible
- Check network connectivity for package downloads
- Verify SSH key format in `authorized_keys`

### Permission Errors

The build script uses Docker volumes and may require appropriate permissions on the host system.

### Package Errors

If packages fail to install, check:
- Package names are correct for Alpine 3.22
- Network access to Alpine repositories
- Package dependencies are satisfied