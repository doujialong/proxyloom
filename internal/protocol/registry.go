package protocol

import "fmt"

type Kind string

const (
	KindProxy         Kind = "proxy"
	KindRawOnly       Kind = "raw_only"
	KindNonProxy      Kind = "non_proxy"
	KindUnknown       Kind = "unknown"
	UnknownID              = "opaque.unknown"
	RegistryVersion        = "protocol-registry-v6"
	FormatSingBoxJSON      = "sing-box-json"
	FormatURIList          = "uri-list"
	FormatMihomoYAML       = "mihomo-yaml"
	FormatClientText       = "client-text"
)

type Definition struct {
	ID                 string
	Kind               Kind
	CanonicalPhase     string
	IdentityProjection string
	RequiredString     []string
	RequiresServerPort bool
}

type Registry struct {
	definitions map[registryKey]Definition
}

type registryKey struct {
	formatID string
	rawType  string
}

func NewRegistry() *Registry {
	definitions := []Definition{
		{ID: "socks", Kind: KindProxy, CanonicalPhase: "M1", IdentityProjection: IdentityProjectionVersion, RequiredString: []string{"server"}, RequiresServerPort: true},
		{ID: "http", Kind: KindProxy, CanonicalPhase: "M1", IdentityProjection: IdentityProjectionVersion, RequiredString: []string{"server"}, RequiresServerPort: true},
		{ID: "shadowsocks", Kind: KindProxy, CanonicalPhase: "M1", IdentityProjection: IdentityProjectionVersion, RequiredString: []string{"server", "method", "password"}, RequiresServerPort: true},
		{ID: "vmess", Kind: KindProxy, CanonicalPhase: "M1", IdentityProjection: IdentityProjectionVersion, RequiredString: []string{"server", "uuid", "security"}, RequiresServerPort: true},
		{ID: "vless", Kind: KindProxy, CanonicalPhase: "M1", IdentityProjection: IdentityProjectionVersion, RequiredString: []string{"server", "uuid"}, RequiresServerPort: true},
		{ID: "trojan", Kind: KindProxy, CanonicalPhase: "M1", IdentityProjection: IdentityProjectionVersion, RequiredString: []string{"server", "password"}, RequiresServerPort: true},
		{ID: "hysteria2", Kind: KindProxy, CanonicalPhase: "M1", IdentityProjection: IdentityProjectionVersion, RequiredString: []string{"server"}, RequiresServerPort: true},
		{ID: "tuic", Kind: KindProxy, CanonicalPhase: "M1", IdentityProjection: IdentityProjectionVersion, RequiredString: []string{"server"}, RequiresServerPort: true},
		{ID: "anytls", Kind: KindProxy, CanonicalPhase: "M1", IdentityProjection: IdentityProjectionVersion, RequiredString: []string{"server"}, RequiresServerPort: true},
		{ID: "wireguard", Kind: KindProxy, CanonicalPhase: "M4", RequiredString: []string{"server"}, RequiresServerPort: true},
		{ID: "hysteria", Kind: KindProxy, CanonicalPhase: "M4", RequiredString: []string{"server"}, RequiresServerPort: true},
		{ID: "shadowtls", Kind: KindProxy, CanonicalPhase: "M4", RequiredString: []string{"server"}, RequiresServerPort: true},
		{ID: "ssh", Kind: KindProxy, CanonicalPhase: "M4", RequiredString: []string{"server"}, RequiresServerPort: true},
		{ID: "tor", Kind: KindProxy, CanonicalPhase: "M4"},
		{ID: "shadowsocksr", Kind: KindRawOnly, CanonicalPhase: "M5", RequiredString: []string{"server"}, RequiresServerPort: true},
		{ID: "direct", Kind: KindNonProxy},
		{ID: "block", Kind: KindNonProxy},
		{ID: "dns", Kind: KindNonProxy},
		{ID: "selector", Kind: KindNonProxy},
		{ID: "urltest", Kind: KindNonProxy},
	}

	registry := &Registry{definitions: make(map[registryKey]Definition, len(definitions))}
	for _, definition := range definitions {
		if err := registry.Register(FormatSingBoxJSON, definition.ID, definition); err != nil {
			panic(err)
		}
	}
	uriDefinitions := []struct {
		rawType    string
		protocolID string
		kind       Kind
	}{
		{rawType: "socks", protocolID: "socks", kind: KindProxy},
		{rawType: "socks4", protocolID: "socks", kind: KindProxy},
		{rawType: "socks4a", protocolID: "socks", kind: KindProxy},
		{rawType: "socks5", protocolID: "socks", kind: KindProxy},
		{rawType: "http", protocolID: "http", kind: KindProxy},
		{rawType: "https", protocolID: "http", kind: KindProxy},
		{rawType: "ss", protocolID: "shadowsocks", kind: KindProxy},
		{rawType: "vmess", protocolID: "vmess", kind: KindProxy},
		{rawType: "vless", protocolID: "vless", kind: KindProxy},
		{rawType: "trojan", protocolID: "trojan", kind: KindProxy},
		{rawType: "hysteria2", protocolID: "hysteria2", kind: KindProxy},
		{rawType: "hy2", protocolID: "hysteria2", kind: KindProxy},
		{rawType: "tuic", protocolID: "tuic", kind: KindProxy},
		{rawType: "anytls", protocolID: "anytls", kind: KindProxy},
		{rawType: "wireguard", protocolID: "wireguard", kind: KindProxy},
		{rawType: "wg", protocolID: "wireguard", kind: KindProxy},
		{rawType: "hysteria", protocolID: "hysteria", kind: KindProxy},
		{rawType: "hy1", protocolID: "hysteria", kind: KindProxy},
		{rawType: "shadowtls", protocolID: "shadowtls", kind: KindProxy},
		{rawType: "ssh", protocolID: "ssh", kind: KindProxy},
		{rawType: "tor", protocolID: "tor", kind: KindProxy},
		{rawType: "naive", protocolID: "naive", kind: KindProxy},
		{rawType: "naive+https", protocolID: "naive", kind: KindProxy},
		{rawType: "snell", protocolID: "snell", kind: KindProxy},
		{rawType: "ssr", protocolID: "shadowsocksr", kind: KindRawOnly},
		{rawType: "mieru", protocolID: "mieru", kind: KindProxy},
		{rawType: "gost", protocolID: "gost-relay", kind: KindProxy},
		{rawType: "sudoku", protocolID: "sudoku", kind: KindProxy},
		{rawType: "masque", protocolID: "masque", kind: KindProxy},
		{rawType: "trusttunnel", protocolID: "trusttunnel", kind: KindProxy},
		{rawType: "openvpn", protocolID: "openvpn", kind: KindProxy},
		{rawType: "tailscale", protocolID: "tailscale", kind: KindProxy},
		{rawType: "juicity", protocolID: "juicity", kind: KindProxy},
	}
	for _, item := range uriDefinitions {
		if err := registry.Register(FormatURIList, item.rawType, Definition{
			ID: item.protocolID, Kind: item.kind, CanonicalPhase: "continuous",
		}); err != nil {
			panic(err)
		}
	}
	mihomoDefinitions := []struct {
		rawType    string
		protocolID string
		kind       Kind
	}{
		{rawType: "ss", protocolID: "shadowsocks", kind: KindProxy},
		{rawType: "ssr", protocolID: "shadowsocksr", kind: KindRawOnly},
		{rawType: "socks5", protocolID: "socks", kind: KindProxy},
		{rawType: "http", protocolID: "http", kind: KindProxy},
		{rawType: "vmess", protocolID: "vmess", kind: KindProxy},
		{rawType: "vless", protocolID: "vless", kind: KindProxy},
		{rawType: "snell", protocolID: "snell", kind: KindProxy},
		{rawType: "trojan", protocolID: "trojan", kind: KindProxy},
		{rawType: "hysteria", protocolID: "hysteria", kind: KindProxy},
		{rawType: "hysteria2", protocolID: "hysteria2", kind: KindProxy},
		{rawType: "wireguard", protocolID: "wireguard", kind: KindProxy},
		{rawType: "tuic", protocolID: "tuic", kind: KindProxy},
		{rawType: "gost-relay", protocolID: "gost-relay", kind: KindProxy},
		{rawType: "ssh", protocolID: "ssh", kind: KindProxy},
		{rawType: "mieru", protocolID: "mieru", kind: KindProxy},
		{rawType: "anytls", protocolID: "anytls", kind: KindProxy},
		{rawType: "sudoku", protocolID: "sudoku", kind: KindProxy},
		{rawType: "masque", protocolID: "masque", kind: KindProxy},
		{rawType: "trusttunnel", protocolID: "trusttunnel", kind: KindProxy},
		{rawType: "openvpn", protocolID: "openvpn", kind: KindProxy},
		{rawType: "tailscale", protocolID: "tailscale", kind: KindProxy},
		{rawType: "direct", protocolID: "direct", kind: KindNonProxy},
		{rawType: "dns", protocolID: "dns", kind: KindNonProxy},
		{rawType: "reject", protocolID: "block", kind: KindNonProxy},
		{rawType: "rematch", protocolID: "selector", kind: KindNonProxy},
	}
	for _, item := range mihomoDefinitions {
		if err := registry.Register(FormatMihomoYAML, item.rawType, Definition{
			ID: item.protocolID, Kind: item.kind, CanonicalPhase: "M5",
		}); err != nil {
			panic(err)
		}
	}
	clientDefinitions := []struct {
		rawType    string
		protocolID string
		kind       Kind
	}{
		{rawType: "ss", protocolID: "shadowsocks", kind: KindProxy},
		{rawType: "shadowsocks", protocolID: "shadowsocks", kind: KindProxy},
		{rawType: "ssr", protocolID: "shadowsocksr", kind: KindRawOnly},
		{rawType: "shadowsocksr", protocolID: "shadowsocksr", kind: KindRawOnly},
		{rawType: "socks", protocolID: "socks", kind: KindProxy},
		{rawType: "socks5", protocolID: "socks", kind: KindProxy},
		{rawType: "http", protocolID: "http", kind: KindProxy},
		{rawType: "https", protocolID: "http", kind: KindProxy},
		{rawType: "vmess", protocolID: "vmess", kind: KindProxy},
		{rawType: "vless", protocolID: "vless", kind: KindProxy},
		{rawType: "trojan", protocolID: "trojan", kind: KindProxy},
		{rawType: "hysteria", protocolID: "hysteria", kind: KindProxy},
		{rawType: "hysteria2", protocolID: "hysteria2", kind: KindProxy},
		{rawType: "hy2", protocolID: "hysteria2", kind: KindProxy},
		{rawType: "tuic", protocolID: "tuic", kind: KindProxy},
		{rawType: "anytls", protocolID: "anytls", kind: KindProxy},
		{rawType: "wireguard", protocolID: "wireguard", kind: KindProxy},
		{rawType: "snell", protocolID: "snell", kind: KindProxy},
		{rawType: "ssh", protocolID: "ssh", kind: KindProxy},
		{rawType: "mieru", protocolID: "mieru", kind: KindProxy},
	}
	for _, item := range clientDefinitions {
		if err := registry.Register(FormatClientText, item.rawType, Definition{
			ID: item.protocolID, Kind: item.kind, CanonicalPhase: "P2",
		}); err != nil {
			panic(err)
		}
	}
	return registry
}

// Register adds a format-specific raw type mapping. A registry is configured
// during application setup and treated as immutable by concurrent processors.
func (r *Registry) Register(formatID, rawType string, definition Definition) error {
	if r == nil {
		return fmt.Errorf("protocol registry is nil")
	}
	if formatID == "" || rawType == "" || definition.ID == "" {
		return fmt.Errorf("format ID, raw type and protocol ID are required")
	}
	if r.definitions == nil {
		r.definitions = make(map[registryKey]Definition)
	}
	key := registryKey{formatID: formatID, rawType: rawType}
	if _, exists := r.definitions[key]; exists {
		return fmt.Errorf("protocol mapping %q/%q is already registered", formatID, rawType)
	}
	r.definitions[key] = definition
	return nil
}

func (r *Registry) Lookup(formatID, rawType string) Definition {
	if r != nil {
		if definition, exists := r.definitions[registryKey{formatID: formatID, rawType: rawType}]; exists {
			return definition
		}
	}
	return Definition{ID: UnknownID, Kind: KindUnknown}
}
