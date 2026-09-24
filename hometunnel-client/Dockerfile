ARG BUILD_FROM=ghcr.io/hassio-addons/base:21.0.5

# Rebuild the pinned client with the reviewed dependency lock: upstream 0.78.2
# binaries still contain gRPC 1.80.0, which has fixed high-severity advisories.
FROM golang:1.26.8-alpine3.24 AS netbird-build
ARG NETBIRD_VERSION=0.78.2
ARG NETBIRD_SOURCE_SHA256=e54b73c09653a533b719ec7e275d9af05f0ffaae548d697570bf6b5d71b13fc8
ENV GOTOOLCHAIN=local
RUN apk add --no-cache curl ca-certificates git python3
WORKDIR /src
RUN curl -fsSL "https://api.github.com/repos/netbirdio/netbird/tarball/v${NETBIRD_VERSION}" -o /tmp/netbird.tar.gz \
    && echo "${NETBIRD_SOURCE_SHA256}  /tmp/netbird.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/netbird.tar.gz --strip-components=1 -C /src \
    && rm /tmp/netbird.tar.gz
COPY netbird-build/go.mod netbird-build/go.sum ./
COPY netbird-build/prepare_overlay.py netbird-build/*_security_test.go /tmp/
COPY netbird-build/collect_licenses.py /tmp/collect_licenses.py
RUN go mod download github.com/pion/stun/v3@v3.1.5 github.com/pion/stun/v2@v2.0.0 github.com/pion/dtls/v2@v2.2.10 \
    && python3 /tmp/prepare_overlay.py /src/netbird-compat
RUN go mod download && go mod verify
RUN CGO_ENABLED=0 go test -mod=readonly github.com/pion/stun/v2 github.com/pion/dtls/v2/pkg/crypto/ciphersuite -run TestHomeTunnel
RUN CGO_ENABLED=0 python3 /tmp/collect_licenses.py /out/licenses
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -tags load_wgnt_from_rsrc \
    -ldflags "-s -w -X github.com/netbirdio/netbird/version.version=${NETBIRD_VERSION}-hometunnel.1 -X main.builtBy=HomeTunnel" \
    -o /out/netbird ./client

FROM ${BUILD_FROM}
ENV LANG=C.UTF-8
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
# No add-on or base startup script uses tempio. Remove the inherited template
# binary rather than ship its unused vulnerable Go/SSH dependencies.
RUN rm -f /usr/bin/tempio
COPY --from=netbird-build /out/netbird /usr/bin/netbird
COPY --from=netbird-build /out/licenses/ /usr/share/licenses/hometunnel/netbird-dependencies/
RUN netbird version

COPY rootfs/ /
COPY LICENSE /usr/share/licenses/hometunnel/LICENSE
COPY LICENSES/ /usr/share/licenses/hometunnel/third-party/
RUN PIP_EXTRA_INDEX_URL= PIP_FIND_LINKS= pip3 install --break-system-packages --no-cache-dir --require-hashes -r /opt/hometunnel/requirements.txt
RUN chmod +x /start.sh
CMD [ "/start.sh" ]
