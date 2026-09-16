module github.com/netbirdio/netbird

go 1.26.0

// Pin the toolchain to a patch release >= go1.26.2
// See https://go.dev/issue/77875.
toolchain go1.26.7

require (
	cunicu.li/go-rosenpass v0.5.42
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/golang/protobuf v1.5.4
	github.com/google/uuid v1.6.0
	github.com/kardianos/service v1.2.3-0.20240613133416-becf2eb62b83
	github.com/sirupsen/logrus v1.9.4
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/crypto v0.56.0
	golang.org/x/sys v0.47.0
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/DeRuina/timberjack v1.4.2
	github.com/awnumar/memguard v0.23.0
	github.com/aws/aws-sdk-go-v2 v1.38.3
	github.com/aws/aws-sdk-go-v2/config v1.31.6
	github.com/aws/aws-sdk-go-v2/credentials v1.18.10
	github.com/caddyserver/certmagic v0.21.3
	github.com/cilium/ebpf v0.22.0
	github.com/coder/websocket v1.8.14
	github.com/coreos/go-iptables v0.7.0
	github.com/creack/pty v1.1.24
	github.com/fsnotify/fsnotify v1.9.0
	github.com/gliderlabs/ssh v0.3.8
	github.com/goccy/go-yaml v1.18.0
	github.com/godbus/dbus/v5 v5.2.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/gopacket v1.1.19
	github.com/google/nftables v0.3.0
	github.com/gopacket/gopacket v1.6.1
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.3
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-version v1.7.0
	github.com/libdns/route53 v1.5.0
	github.com/libp2p/go-netroute v0.4.0
	github.com/lrh3321/ipset-go v0.0.0-20250619021614-54a0a98ace81
	github.com/mdlayher/socket v0.5.1
	github.com/mdp/qrterminal/v3 v3.2.1
	github.com/miekg/dns v1.1.72
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/netbirdio/go-nat v0.0.0-20260821095157-6b2c8c5c74e8
	github.com/pion/ice/v4 v4.0.0-00010101000000-000000000000
	github.com/pion/logging v0.2.4
	github.com/pion/randutil v0.1.0
	github.com/pion/stun/v2 v2.0.0
	github.com/pion/stun/v3 v3.1.5
	github.com/pion/transport/v3 v3.1.1
	github.com/pion/turn/v3 v3.0.1
	github.com/pkg/sftp v1.13.9
	github.com/prometheus/client_golang v1.23.2
	github.com/prometheus/client_model v0.6.2
	github.com/quic-go/quic-go v0.62.0
	github.com/shirou/gopsutil/v4 v4.25.8
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966
	github.com/things-go/go-socks5 v0.0.4
	github.com/ti-mo/conntrack v0.5.1
	github.com/ti-mo/netfilter v0.5.2
	github.com/zcalusic/sysinfo v1.1.3
	go.uber.org/zap v1.27.0
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f
	golang.org/x/net v0.58.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sync v0.22.0
	golang.org/x/term v0.45.0
	golang.org/x/time v0.15.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa
	gopkg.in/yaml.v3 v3.0.1
	gvisor.dev/gvisor v0.0.0-20260219192049-0f2374377e89
)

require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/awnumar/memcall v0.4.0 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/route53 v1.42.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.29.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.34.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.38.2 // indirect
	github.com/aws/smithy-go v1.23.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/caddyserver/zerossl v0.1.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/huin/goupnp v1.2.0 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/compress v1.18.7 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/koron/go-ssdp v0.0.4 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/libdns/libdns v0.2.2 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mholt/acmez/v2 v2.0.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pion/dtls/v2 v2.2.10 // indirect
	github.com/pion/dtls/v3 v3.1.4 // indirect
	github.com/pion/mdns/v2 v2.0.7 // indirect
	github.com/pion/transport/v2 v2.2.4 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/pion/turn/v4 v4.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.19.2 // indirect
	github.com/tklauser/go-sysconf v0.3.15 // indirect
	github.com/tklauser/numcpus v0.10.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	rsc.io/qr v0.2.0 // indirect
)

replace github.com/kardianos/service => github.com/netbirdio/service v0.0.0-20240911161631-f62744f42502

replace github.com/getlantern/systray => github.com/netbirdio/systray v0.0.0-20231030152038-ef1ed2a27949

replace golang.zx2c4.com/wireguard => github.com/netbirdio/wireguard-go v0.0.0-20260914123147-8bf8fa968f1a

replace github.com/cloudflare/circl => codeberg.org/cunicu/circl v0.0.0-20230801113412-fec58fc7b5f6

replace github.com/pion/ice/v4 => github.com/netbirdio/ice/v4 v4.0.0-20250908184934-6202be846b51

replace github.com/dexidp/dex => github.com/netbirdio/dex v0.244.1-0.20260716205454-a163de3129e5

replace github.com/dexidp/dex/api/v2 => github.com/netbirdio/dex/api/v2 v2.0.0-20260512110716-8d70ad8647c1

replace github.com/mailru/easyjson => github.com/netbirdio/easyjson v0.9.0

replace github.com/wailsapp/wails/v3 => github.com/netbirdio/wails/v3 v3.0.0-beta.3.0.20260825085513-5f07a01f7a78

tool go.uber.org/mock/mockgen

replace github.com/pion/stun/v3 => ./netbird-compat/stun

replace github.com/pion/dtls/v2 => ./netbird-compat/dtls2

replace github.com/pion/stun/v2 => ./netbird-compat/stun2
