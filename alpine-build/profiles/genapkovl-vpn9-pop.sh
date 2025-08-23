#!/bin/sh -e

HOSTNAME="$1"
if [ -z "$HOSTNAME" ]; then
  echo "usage: $0 hostname"
  exit 1
fi

cleanup() {
  rm -rf "$tmp"
}

makefile() {
  OWNER="$1"
  PERMS="$2"
  FILENAME="$3"
  cat >"$FILENAME"
  chown "$OWNER" "$FILENAME"
  chmod "$PERMS" "$FILENAME"
}

rc_add() {
  mkdir -p "$tmp"/etc/runlevels/"$2"
  ln -sf /etc/init.d/"$1" "$tmp"/etc/runlevels/"$2"/"$1"
}

tmp="$(mktemp -d)"
trap cleanup EXIT

mkdir -p "$tmp"/etc
makefile root:root 0644 "$tmp"/etc/hostname <<EOF
$HOSTNAME
EOF

mkdir -p "$tmp"/etc/network
makefile root:root 0644 "$tmp"/etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

mkdir -p "$tmp"/etc/apk
makefile root:root 0644 "$tmp"/etc/apk/world <<EOF
alpine-base
openssh
wireguard-tools
EOF

echo "Setting up centralized SSH authorized keys"

# Get the directory where this script is located
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
echo "Script directory: $SCRIPT_DIR"

# Create centralized SSH authorized keys directory
mkdir -p "$tmp"/etc/ssh/authorized_keys
echo "Created /etc/ssh/authorized_keys directory"

# Set up sshd_config to use centralized authorized keys
mkdir -p "$tmp"/etc/ssh
makefile root:root 0644 "$tmp"/etc/ssh/sshd_config <<EOF
# Custom SSH configuration for centralized authorized keys
AuthorizedKeysFile /etc/ssh/authorized_keys/%u

# Basic SSH security settings
PermitRootLogin yes
PasswordAuthentication no
PubkeyAuthentication yes
EOF

# Copy root's authorized keys if available
if [ -f "$SCRIPT_DIR/authorized_keys" ]; then
  echo "Root authorized keys found at $SCRIPT_DIR/authorized_keys"
  makefile root:root 0644 "$tmp"/etc/ssh/authorized_keys/root <"$SCRIPT_DIR/authorized_keys"
else
  echo "No root authorized_keys file found in $SCRIPT_DIR"
  makefile root:root 0644 "$tmp"/etc/ssh/authorized_keys/root <<EOF
# No authorized_keys file found for root
# Create an 'authorized_keys' file in the same directory as this script
# and add your SSH public keys there
EOF
fi

# Set proper permissions for the authorized_keys directory
makefile root:root 0755 "$tmp"/etc/ssh/authorized_keys/.keep <<EOF
# This file ensures the directory is created with correct permissions
EOF

# Copy vpn9-agent binary to /usr/local/bin in the overlay
echo "Adding vpn9-agent binary to overlay"
mkdir -p "$tmp"/usr/local/bin
if [ -f /usr/local/bin/vpn9-agent ]; then
  cp /usr/local/bin/vpn9-agent "$tmp"/usr/local/bin/vpn9-agent
  chmod 755 "$tmp"/usr/local/bin/vpn9-agent
  echo "vpn9-agent binary added to overlay"
else
  echo "Warning: vpn9-agent binary not found at /usr/local/bin/vpn9-agent"
fi

rc_add devfs sysinit
rc_add dmesg sysinit
rc_add mdev sysinit
rc_add hwdrivers sysinit
rc_add modloop sysinit

rc_add hwclock boot
rc_add modules boot
rc_add sysctl boot
rc_add hostname boot
rc_add bootmisc boot
rc_add syslog boot
# custom
rc_add networking boot
rc_add local boot

# default level
rc_add sshd default

rc_add mount-ro shutdown
rc_add killprocs shutdown
rc_add savecache shutdown

tar -c -C "$tmp" etc usr | gzip -9n >$HOSTNAME.apkovl.tar.gz
