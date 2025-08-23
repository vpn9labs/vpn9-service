#!/bin/bash

set -euo pipefail

echo "🚀 Building VPN9 Pop Images (ISO + Cloud Disk Image)"
echo "================================================="

# Build ISO (existing workflow)
echo ""
echo "📀 Building ISO image..."
./scripts/mkimage-pop.sh

# Build cloud disk image (new workflow)  
echo ""
echo "☁️  Building cloud disk image..."
./scripts/mkdiskimage-pop.sh

echo ""
echo "✅ Build complete!"
echo ""
echo "Artifacts created:"
echo "  📀 ISO: alpine-build/artifacts/alpine-vpn9-pop-3.22-x86_64.iso"
echo "  ☁️  Cloud: alpine-build/artifacts/alpine-vpn9-pop-cloud-3.22-x86_64.raw.gz"
echo ""
echo "Usage:"
echo "  • ISO: Boot from USB/CD, or use in VirtualBox/VMware"
echo "  • Cloud: Upload to DigitalOcean Custom Images (supports raw.gz format)"