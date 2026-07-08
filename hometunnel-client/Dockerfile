ARG BUILD_FROM=ghcr.io/hassio-addons/base:14.0.1
FROM ${BUILD_FROM}

ENV LANG=C.UTF-8
ENV NETBIRD_VERSION=0.74.2

# Pinned upstream NetBird release checksums for netbird_${NETBIRD_VERSION}_linux_<arch>.tar.gz.
# Source of truth (verify when bumping NETBIRD_VERSION):
#   https://github.com/netbirdio/netbird/releases/download/v${NETBIRD_VERSION}/netbird_${NETBIRD_VERSION}_checksums.txt
ARG NETBIRD_SHA256_AMD64=c29f83efbc54c082323857ef99853971703e6230d3d7de9e045fc63cc4ebe135
ARG NETBIRD_SHA256_ARM64=ebdf52104f50602963d7248a4e5efdc2a92c3f459e2188ad75d44e01d2758e50

RUN apk add --no-cache \
    bash \
    python3 \
    py3-pip \
    curl \
    iproute2 \
    wireguard-tools \
    tar \
    jq \
    coreutils

# Install NetBird from a version-pinned, checksum-verified upstream release binary.
# No package-manager "latest" and no curl|sh: builds are reproducible and the
# artifact is verified against the pinned SHA256 before it is trusted.
RUN set -eux; \
    case "$(uname -m)" in \
      x86_64) NB_ARCH="amd64"; NB_SHA256="${NETBIRD_SHA256_AMD64}" ;; \
      aarch64) NB_ARCH="arm64"; NB_SHA256="${NETBIRD_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;; \
    esac; \
    NB_TARBALL="netbird_${NETBIRD_VERSION}_linux_${NB_ARCH}.tar.gz"; \
    curl -fsSL -o "/tmp/${NB_TARBALL}" \
      "https://github.com/netbirdio/netbird/releases/download/v${NETBIRD_VERSION}/${NB_TARBALL}"; \
    echo "${NB_SHA256}  /tmp/${NB_TARBALL}" | sha256sum -c -; \
    tar -xzf "/tmp/${NB_TARBALL}" -C /tmp netbird; \
    install -o root -g root -m 0755 /tmp/netbird /usr/bin/netbird; \
    rm -f "/tmp/${NB_TARBALL}" /tmp/netbird; \
    netbird version

COPY rootfs/ /

RUN pip3 install --break-system-packages --no-cache-dir -r /opt/hometunnel/requirements.txt
RUN chmod +x /start.sh

CMD [ "/start.sh" ]
