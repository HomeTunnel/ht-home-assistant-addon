ARG BUILD_FROM=ghcr.io/hassio-addons/base:21.0.5
FROM ${BUILD_FROM}

ENV LANG=C.UTF-8
ENV NETBIRD_VERSION=0.78.2

# Pinned upstream NetBird release checksums for netbird_${NETBIRD_VERSION}_linux_<arch>.tar.gz.
# Source of truth (verify when bumping NETBIRD_VERSION):
#   https://github.com/netbirdio/netbird/releases/download/v${NETBIRD_VERSION}/netbird_${NETBIRD_VERSION}_checksums.txt
ARG NETBIRD_SHA256_AMD64=6413c2b29d9a91c6adf3ea16c7b2dcc1faec1d463d47f01ad1a98c1cc49e1cc3
ARG NETBIRD_SHA256_ARM64=11ec3dd9f647bfdef43db38a43c019f93118a220c63e85947344a7b0516d14fe

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
# No package-manager "latest" and no curl|sh: the NetBird version is fixed and the
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
COPY LICENSE /usr/share/licenses/hometunnel/LICENSE
COPY LICENSES/ /usr/share/licenses/hometunnel/third-party/

RUN PIP_EXTRA_INDEX_URL= PIP_FIND_LINKS= pip3 install --break-system-packages --no-cache-dir --require-hashes -r /opt/hometunnel/requirements.txt
RUN chmod +x /start.sh

CMD [ "/start.sh" ]
