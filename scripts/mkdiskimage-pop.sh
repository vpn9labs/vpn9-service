#!/bin/bash

set -euo pipefail

# Convert existing ISO to cloud-compatible disk image
# This reuses your existing ISO build and converts it to a bootable disk image

OUTPUT_DIR="$(pwd)/alpine-build/artifacts"
ISO_FILE="$OUTPUT_DIR/alpine-vpn9-pop-3.22-x86_64.iso"
IMAGE_NAME="alpine-vpn9-pop-cloud-3.22-x86_64"
IMAGE_SIZE="2G"

echo "Converting ISO to cloud disk image..."

# Check if ISO exists
if [ ! -f "$ISO_FILE" ]; then
    echo "❌ ISO not found: $ISO_FILE"
    echo "Run ./scripts/mkimage-pop.sh first to create the ISO"
    exit 1
fi

echo "📀 Found ISO: $ISO_FILE"
echo "☁️  Creating cloud disk image: ${IMAGE_NAME}.raw.gz"

# Use Docker with privileged access for loop device operations
docker run --rm --privileged \
  -v "$OUTPUT_DIR":/artifacts \
  -e IMAGE_NAME="$IMAGE_NAME" \
  -e IMAGE_SIZE="$IMAGE_SIZE" \
  alpine:3.22 sh -c '
    # Install required tools
    apk add --no-cache e2fsprogs util-linux parted syslinux cloud-init squashfs-tools

    cd /artifacts
    ISO_FILE="alpine-vpn9-pop-3.22-x86_64.iso"
    
    echo "🔍 Extracting ISO contents..."
    
    # Mount ISO
    mkdir -p /mnt/iso /mnt/squashfs /mnt/disk
    mount -o loop "$ISO_FILE" /mnt/iso
    
    # Extract squashfs (contains the Alpine system)
    if [ -f /mnt/iso/boot/modloop-lts ]; then
        SQUASHFS_FILE="/mnt/iso/boot/modloop-lts"
    else
        # Find the squashfs file
        SQUASHFS_FILE=$(find /mnt/iso -name "*.squashfs" -o -name "modloop*" | head -1)
    fi
    
    if [ -z "$SQUASHFS_FILE" ]; then
        echo "❌ No squashfs file found in ISO"
        exit 1
    fi
    
    echo "📦 Found system image: $SQUASHFS_FILE"
    
    # Create raw disk image
    IMAGE_FILE="${IMAGE_NAME}.raw"
    echo "💿 Creating ${IMAGE_SIZE} disk image..."
    dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=2000
    
    # Create filesystem directly with offset (skip partitioning issues)
    echo "🔧 Creating filesystem..."
    LOOP_DEV=$(losetup -f --show "$IMAGE_FILE")
    echo "Using loop device: $LOOP_DEV"
    
    # Calculate partition offset (1MiB = 1048576 bytes)
    OFFSET=1048576
    SIZE_SECTORS=$((2000 * 1024 * 1024 / 512 - 2048))  # Total sectors minus partition start
    
    # Create partition table
    echo "Creating partition table..."
    parted "$LOOP_DEV" mklabel msdos
    parted "$LOOP_DEV" mkpart primary ext4 1MiB 100%
    parted "$LOOP_DEV" set 1 boot on
    
    # Create loop device for the partition with offset
    echo "Creating filesystem with offset..."
    PART_LOOP=$(losetup -f --show --offset $OFFSET "$IMAGE_FILE")
    echo "Using partition loop device: $PART_LOOP"
    
    # Format the partition
    mkfs.ext4 -F "$PART_LOOP"
    
    # Mount the partition
    mount "$PART_LOOP" /mnt/disk
    
    echo "📋 Copying system files from ISO..."
    
    # Copy boot files from ISO
    mkdir -p /mnt/disk/boot
    cp -r /mnt/iso/boot/* /mnt/disk/boot/ || true
    
    # Extract and copy the Alpine system
    echo "📂 Extracting system from ISO..."
    
    # First try to extract from squashfs/modloop
    EXTRACTED=false
    if [ -n "$SQUASHFS_FILE" ]; then
        echo "Attempting to extract from: $SQUASHFS_FILE"
        
        # Try different extraction methods
        if unsquashfs -d /mnt/disk "$SQUASHFS_FILE" 2>/dev/null; then
            echo "✅ Successfully extracted with unsquashfs"
            EXTRACTED=true
        elif mount -t squashfs "$SQUASHFS_FILE" /mnt/squashfs 2>/dev/null; then
            echo "✅ Successfully mounted squashfs, copying files..."
            cp -a /mnt/squashfs/* /mnt/disk/ 2>/dev/null || {
                echo "⚠️  Failed to copy, trying selective copy..."
                for dir in bin sbin etc usr lib var opt; do
                    if [ -d "/mnt/squashfs/$dir" ]; then
                        cp -a "/mnt/squashfs/$dir" "/mnt/disk/" 2>/dev/null && echo "Copied /$dir"
                    fi
                done
            }
            umount /mnt/squashfs 2>/dev/null || true
            EXTRACTED=true
        fi
    fi
    
    # If extraction failed, create from scratch using apkovl + packages
    if [ "$EXTRACTED" = "false" ]; then
        echo "📦 Building system from packages..."
        
        # Create essential directory structure
        mkdir -p /mnt/disk/{bin,sbin,etc,proc,sys,dev,tmp,var,usr,root,home,boot}
        mkdir -p /mnt/disk/etc/{init.d,conf.d,runlevels/{sysinit,boot,default,shutdown}}
        mkdir -p /mnt/disk/var/{log,cache/apk,lib/apk}
        mkdir -p /mnt/disk/usr/{bin,sbin,lib,share}
        
        # Copy APK configuration
        mkdir -p /mnt/disk/etc/apk/keys
        cp -r /etc/apk/keys/* /mnt/disk/etc/apk/keys/ 2>/dev/null || true
        cp /etc/apk/repositories /mnt/disk/etc/apk/repositories 2>/dev/null || true
        
        # Install base Alpine system with all packages
        echo "Installing Alpine packages..."
        apk add --root /mnt/disk --initdb \
            alpine-base alpine-conf busybox busybox-suid \
            linux-lts linux-lts-dev \
            wireguard-tools iptables iproute2 \
            openssh openssh-client openssh-keygen \
            cloud-init py3-configobj py3-jinja2 py3-yaml \
            haveged dhcpcd ifupdown-ng \
            e2fsprogs util-linux syslinux \
            libgcc musl || {
                echo "⚠️  Some packages failed to install, continuing..."
            }
        
        # Copy any existing overlay files from ISO
        if [ -d "/mnt/iso/apks" ]; then
            echo "Copying overlay packages..."
            cp -r /mnt/iso/apks/* /mnt/disk/var/cache/apk/ 2>/dev/null || true
        fi
        
        EXTRACTED=true
    fi
    
    # Verify we have essential files
    ESSENTIAL_SIZE=$(du -sm /mnt/disk 2>/dev/null | cut -f1)
    echo "📊 System size: ${ESSENTIAL_SIZE}MB"
    
    if [ "$ESSENTIAL_SIZE" -lt 50 ]; then
        echo "⚠️  System seems too small (${ESSENTIAL_SIZE}MB), trying to add more content..."
        
        # Try to copy more files from the running Alpine container
        for dir in lib usr/lib usr/share; do
            if [ -d "/$dir" ] && [ ! -d "/mnt/disk/$dir" ]; then
                echo "Adding /$dir..."
                cp -a "/$dir" "/mnt/disk/" 2>/dev/null || true
            fi
        done
    fi
    
    # Add cloud-init configuration for DigitalOcean
    echo "☁️  Configuring cloud-init..."
    mkdir -p /mnt/disk/etc/cloud/cloud.cfg.d
    cat > /mnt/disk/etc/cloud/cloud.cfg.d/10-digitalocean.cfg << EOF
datasource_list: [ DigitalOcean, None ]
datasource:
  DigitalOcean:
    retries: 3
    timeout: 10
manage_etc_hosts: true
preserve_hostname: false
EOF
    
    # Enable cloud-init services if not already enabled
    mkdir -p /mnt/disk/etc/runlevels/default
    for service in cloud-init cloud-config cloud-final; do
        if [ -f /mnt/disk/etc/init.d/$service ]; then
            ln -sf /etc/init.d/$service /mnt/disk/etc/runlevels/default/ 2>/dev/null || true
        fi
    done
    
    # Install bootloader
    echo "🥾 Installing bootloader..."
    
    # Find the correct MBR file
    MBR_FILE=""
    for mbr_path in /usr/share/syslinux/mbr.bin /mnt/disk/usr/share/syslinux/mbr.bin; do
        if [ -f "$mbr_path" ]; then
            MBR_FILE="$mbr_path"
            break
        fi
    done
    
    if [ -n "$MBR_FILE" ]; then
        # Install syslinux to MBR (use main loop device, not partition)
        dd bs=440 count=1 conv=notrunc if="$MBR_FILE" of="$LOOP_DEV"
        echo "✅ MBR installed to $LOOP_DEV"
    else
        echo "⚠️  MBR file not found, bootloader may not work"
    fi
    
    # Setup syslinux config
    mkdir -p /mnt/disk/boot/syslinux
    cat > /mnt/disk/boot/syslinux/syslinux.cfg << EOF
DEFAULT linux
TIMEOUT 10
PROMPT 0

LABEL linux
  KERNEL /boot/vmlinuz-lts
  INITRD /boot/initramfs-lts
  APPEND root=/dev/sda1 modules=sd-mod,usb-storage,ext4 quiet rootfstype=ext4
EOF
    
    # Install syslinux to partition - check if extlinux exists
    if command -v extlinux >/dev/null 2>&1; then
        extlinux --install /mnt/disk/boot/syslinux
    elif [ -f /mnt/disk/usr/bin/extlinux ]; then
        chroot /mnt/disk /usr/bin/extlinux --install /boot/syslinux
    else
        echo "⚠️  extlinux not found, manual bootloader setup required"
    fi
    
    # Cleanup mounts
    echo "🧹 Cleaning up..."
    umount /mnt/iso 2>/dev/null || true
    umount /mnt/disk 2>/dev/null || true
    if [ -n "$PART_LOOP" ]; then
        losetup -d "$PART_LOOP" 2>/dev/null || true
    fi
    if [ -n "$LOOP_DEV" ]; then
        losetup -d "$LOOP_DEV" 2>/dev/null || true
    fi
    
    # Compress the image
    echo "🗜️  Compressing image..."
    if [ -f "$IMAGE_FILE" ]; then
        gzip -9 "$IMAGE_FILE"
        echo "✅ Cloud disk image created: ${IMAGE_FILE}.gz"
    else
        echo "❌ Image file not found: $IMAGE_FILE"
        exit 1
    fi
'

echo ""
echo "✅ Conversion complete!"
echo "📁 Cloud image: $OUTPUT_DIR/${IMAGE_NAME}.raw.gz"
echo ""
echo "🚀 Upload to DigitalOcean:"
echo "   1. Control Panel > Images > Custom Images"
echo "   2. Upload the .raw.gz file"
echo "   3. Select 'Alpine Linux' as distribution"