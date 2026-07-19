package protocol

import "testing"

func TestRegistryClassifications(t *testing.T) {
	registry := NewRegistry()
	for _, id := range []string{
		"socks", "http", "shadowsocks", "vmess", "vless", "trojan", "wireguard",
		"hysteria", "shadowtls", "tuic", "hysteria2", "anytls", "tor", "ssh",
	} {
		if definition := registry.Lookup(FormatSingBoxJSON, id); definition.ID != id || definition.Kind != KindProxy {
			t.Fatalf("Lookup(%q) = %+v", id, definition)
		}
	}
	if definition := registry.Lookup(FormatSingBoxJSON, "shadowsocksr"); definition.Kind != KindRawOnly {
		t.Fatalf("SSR definition = %+v", definition)
	}
	for _, id := range []string{"direct", "block", "dns", "selector", "urltest"} {
		if definition := registry.Lookup(FormatSingBoxJSON, id); definition.Kind != KindNonProxy {
			t.Fatalf("Lookup(%q) = %+v", id, definition)
		}
	}
	if definition := registry.Lookup(FormatSingBoxJSON, "future-protocol"); definition.ID != UnknownID || definition.Kind != KindUnknown {
		t.Fatalf("unknown definition = %+v", definition)
	}
}

func TestRegistrySeparatesSameRawTypeAcrossFormats(t *testing.T) {
	registry := NewRegistry()
	err := registry.Register("example-format", "vless", Definition{ID: "example.vless", Kind: KindProxy})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if got := registry.Lookup("example-format", "vless"); got.ID != "example.vless" {
		t.Fatalf("example definition = %+v", got)
	}
	if got := registry.Lookup(FormatSingBoxJSON, "vless"); got.ID != "vless" {
		t.Fatalf("sing-box definition = %+v", got)
	}
	if err := registry.Register("example-format", "vless", Definition{ID: "duplicate", Kind: KindProxy}); err == nil {
		t.Fatal("duplicate registration was accepted")
	}
}

func TestRegistryClassifiesURIFormatsIndependently(t *testing.T) {
	registry := NewRegistry()
	tests := map[string]string{
		"socks": "socks", "socks4": "socks", "socks4a": "socks", "socks5": "socks",
		"http": "http", "https": "http", "ss": "shadowsocks", "vmess": "vmess",
		"vless": "vless", "trojan": "trojan", "hy2": "hysteria2", "hysteria2": "hysteria2",
		"tuic": "tuic", "anytls": "anytls", "wireguard": "wireguard", "wg": "wireguard",
		"hysteria": "hysteria", "hy1": "hysteria", "shadowtls": "shadowtls", "ssh": "ssh",
		"tor": "tor", "naive": "naive", "naive+https": "naive", "snell": "snell",
		"ssr": "shadowsocksr", "mieru": "mieru", "gost": "gost-relay", "sudoku": "sudoku",
		"masque": "masque", "trusttunnel": "trusttunnel", "openvpn": "openvpn",
		"tailscale": "tailscale", "juicity": "juicity",
	}
	for rawType, protocolID := range tests {
		definition := registry.Lookup(FormatURIList, rawType)
		if definition.ID != protocolID {
			t.Fatalf("Lookup(uri-list, %q) = %+v", rawType, definition)
		}
	}
	if definition := registry.Lookup(FormatURIList, "future"); definition.ID != UnknownID || definition.Kind != KindUnknown {
		t.Fatalf("unknown URI definition = %+v", definition)
	}
	if definition := registry.Lookup(FormatSingBoxJSON, "ss"); definition.ID != UnknownID {
		t.Fatalf("URI alias leaked into sing-box registry: %+v", definition)
	}
}
