#!/bin/bash

set -euo pipefail
docker build -t vpn9-pop-builder -f Dockerfile.build-vpn9-pop .
docker run --rm \
  -v "$(pwd)/alpine-build/profiles":/profiles:ro \
  -v "$(pwd)/alpine-build/artifacts":/out \
  -v "$(pwd)/alpine-build/keys":/keys:ro \
  -e PROFILENAME=vpn9-pop \
  vpn9-pop-builder -c '
        echo "Profiles directory:" && \
        ls -la /profiles && \
        echo "Keys directory:" && \
        ls -la /keys && \
        echo "Aports scripts directory before copy:" && \
        ls -la /root/aports/scripts && \
        cp /profiles/mkimg.vpn9-pop.sh /root/aports/scripts/ && \
        chmod +x /root/aports/scripts/mkimg.vpn9-pop.sh && \
        echo "Copied mkimg.vpn9-pop.sh" && \
        cp /profiles/genapkovl-vpn9-pop.sh /root/aports/scripts/ && \
        chmod +x /root/aports/scripts/genapkovl-vpn9-pop.sh && \
        cp /profiles/authorized_keys /root/aports/scripts/ && \
        echo "Copied genapkovl-vpn9-pop.sh and authorized_keys" && \
        export PATH="/root/aports/scripts:$PATH" && \
        echo "Aports scripts directory after copy:" && \
        ls -la /root/aports/scripts && \
        echo "Running mkimage.sh with verbose output..." && \
        PACKAGER_PRIVKEY=/keys/build-6888fcb3.rsa /root/aports/scripts/mkimage.sh --tag 3.22 --arch x86_64 \
             --profile "$PROFILENAME" --outdir /out \
             --repository https://dl-cdn.alpinelinux.org/alpine/v3.22/main \
             --repository https://dl-cdn.alpinelinux.org/alpine/v3.22/community'
