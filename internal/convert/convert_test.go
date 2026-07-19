package convert

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/doujialong/proxyloom/internal/format/clienttext"
	"github.com/doujialong/proxyloom/internal/format/mihomo"
	"github.com/doujialong/proxyloom/internal/format/urilist"
	"github.com/doujialong/proxyloom/internal/protocol"
)

func TestMihomoToSingBoxCoversCurrentPanelProtocols(t *testing.T) {
	input := []byte(`proxies:
  - {name: TUIC, type: tuic, server: tuic.example, port: 443, uuid: 00000000-0000-4000-8000-000000000001, password: pass, sni: edge.example, alpn: [h3], congestion-controller: bbr, udp-relay-mode: native}
  - {name: VLESS WS, type: vless, server: ws.example, port: 443, uuid: 00000000-0000-4000-8000-000000000002, tls: true, servername: edge.example, network: ws, ws-opts: {path: /ws, headers: {Host: edge.example}}, client-fingerprint: chrome}
  - {name: VLESS Reality, type: vless, server: reality.example, port: 443, uuid: 00000000-0000-4000-8000-000000000003, flow: xtls-rprx-vision, tls: true, servername: edge.example, reality-opts: {public-key: public, short-id: abcd}}
  - {name: VMess, type: vmess, server: vmess.example, port: 443, uuid: 00000000-0000-4000-8000-000000000004, alterId: 0, cipher: auto, tls: true, network: ws, ws-opts: {path: /vmess}}
  - {name: HY2, type: hysteria2, server: hy2.example, port: 443, password: pass, ports: "20000,21000-21010", hop-interval: 30, obfs: salamander, obfs-password: obfs, sni: edge.example}
  - {name: AnyTLS, type: anytls, server: anytls.example, port: 443, password: pass, sni: edge.example, skip-cert-verify: true, client-fingerprint: chrome, udp: true}
`)
	document, err := mihomo.Parse(input, protocol.NewRegistry(), mihomo.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[int]string)
	for _, node := range document.Nodes {
		names[node.Ordinal] = node.DisplayName
	}
	artifact, err := MihomoToSingBox(document.Nodes, names)
	if err != nil {
		t.Fatal(err)
	}
	outbounds := decodeOutbounds(t, artifact)
	if len(outbounds) != 6 {
		t.Fatalf("outbound count = %d", len(outbounds))
	}
	byTag := indexByTag(outbounds)
	if nestedString(byTag["VLESS WS"], "transport", "type") != "ws" || nestedString(byTag["VLESS WS"], "tls", "server_name") != "edge.example" {
		t.Fatalf("VLESS WS conversion = %#v", byTag["VLESS WS"])
	}
	if nestedString(byTag["VLESS Reality"], "tls", "reality", "public_key") != "public" ||
		!nestedBool(byTag["VLESS Reality"], "tls", "utls", "enabled") {
		t.Fatalf("VLESS Reality conversion = %#v", byTag["VLESS Reality"])
	}
	if byTag["HY2"]["password"] != "pass" || nestedString(byTag["HY2"], "obfs", "type") != "salamander" {
		t.Fatalf("HY2 conversion = %#v", byTag["HY2"])
	}
	ports, portsOK := byTag["HY2"]["server_ports"].([]interface{})
	if !portsOK || len(ports) != 2 || ports[0] != "20000:20000" || ports[1] != "21000:21010" || byTag["HY2"]["hop_interval"] != "30s" {
		t.Fatalf("HY2 port hopping conversion = %#v", byTag["HY2"])
	}
	if nestedString(byTag["AnyTLS"], "tls", "utls", "fingerprint") != "chrome" {
		t.Fatalf("AnyTLS conversion = %#v", byTag["AnyTLS"])
	}
}

func TestClientTextToSingBoxCoversSurgeLoonAndQuantumultX(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name: "Surge",
			input: "[Proxy]\n" +
				"HY2 = hysteria2, hy.example, 443, password=pass, sni=edge.example, udp-relay=true, port-hopping=20000;21000-21010, port-hopping-interval=30, salamander-password=obfs\n" +
				"SS = ss, ss.example, 443, encrypt-method=2022-blake3-aes-128-gcm, password=pass, shadow-tls-password=shadow, shadow-tls-version=3, shadow-tls-sni=edge.example\n" +
				"VMess = vmess, vmess.example, 443, username=00000000-0000-4000-8000-000000000001, vmess-aead=true, tls=true, sni=edge.example, ws=true, ws-path=/ws, ws-headers=Host:edge.example\n",
			want: 4,
		},
		{
			name: "Loon",
			input: "[Proxy]\n" +
				"VLESS = vless, vless.example, 443, 00000000-0000-4000-8000-000000000002, transport=ws, over-tls=true, path=/ws, host=edge.example, tls-name=edge.example, skip-cert-verify=false\n" +
				"VMess = vmess, vmess.example, 443, auto, 00000000-0000-4000-8000-000000000003, transport=ws, alterid=0, over-tls=true, path=/vmess, host=edge.example\n" +
				"AnyTLS = anytls, any.example, 443, pass, skip-cert-verify=true, sni=edge.example, udp=true\n" +
				"Trojan = trojan, trojan.example, 443, pass, tls-name=edge.example, alpn=http1.1, skip-cert-verify=false, udp=true\n",
			want: 4,
		},
		{
			name: "Quantumult X",
			input: "[server_local]\n" +
				"anytls=any.example:443, password=pass, over-tls=true, tls-host=edge.example, udp-relay=true, reality-base64-pubkey=public, reality-hex-shortid=abcd, tag=AnyTLS\n" +
				"vless=ws.example:443, method=none, password=00000000-0000-4000-8000-000000000004, fast-open=true, udp-relay=true, obfs=wss, obfs-host=edge.example, obfs-uri=/ws, tag=VLESS\n" +
				"trojan=trojan.example:443, password=pass, over-tls=true, tls-host=edge.example, tls-verification=false, tag=Trojan\n",
			want: 3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, err := clienttext.Parse([]byte(test.input), protocol.NewRegistry(), clienttext.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			names := make(map[int]string)
			for _, node := range document.Nodes {
				names[node.Ordinal] = node.DisplayName
			}
			artifact, err := ClientTextToSingBox(document.Nodes, names)
			if err != nil {
				t.Fatal(err)
			}
			outbounds := decodeOutbounds(t, artifact)
			if len(outbounds) != test.want {
				t.Fatalf("outbound count = %d, want %d\n%s", len(outbounds), test.want, artifact)
			}
			if test.name == "Surge" {
				byTag := indexByTag(outbounds)
				if byTag["SS"]["detour"] == nil || nestedString(byTag["VMess"], "transport", "type") != "ws" {
					t.Fatalf("Surge conversion = %#v", byTag)
				}
				ports, portsOK := byTag["HY2"]["server_ports"].([]interface{})
				if !portsOK || len(ports) != 2 || ports[0] != "20000:20000" || ports[1] != "21000:21010" || byTag["HY2"]["hop_interval"] != "30s" {
					t.Fatalf("Surge HY2 port hopping conversion = %#v", byTag["HY2"])
				}
			}
			if test.name == "Loon" {
				byTag := indexByTag(outbounds)
				tls, tlsOK := byTag["Trojan"]["tls"].(map[string]interface{})
				got, alpnOK := tls["alpn"].([]interface{})
				if !tlsOK || !alpnOK || len(got) != 1 || got[0] != "http/1.1" {
					t.Fatalf("Loon Trojan ALPN conversion = %#v", byTag["Trojan"])
				}
			}
			if test.name == "Quantumult X" {
				byTag := indexByTag(outbounds)
				if nestedString(byTag["VLESS"], "tls", "server_name") != "edge.example" ||
					nestedString(byTag["VLESS"], "transport", "headers", "Host") != "edge.example" {
					t.Fatalf("Quantumult X VLESS obfs-host conversion = %#v", byTag["VLESS"])
				}
				tls, tlsOK := byTag["Trojan"]["tls"].(map[string]interface{})
				if !tlsOK || tls["insecure"] != true {
					t.Fatalf("Quantumult X Trojan TLS conversion = %#v", byTag["Trojan"])
				}
				if !nestedBool(byTag["AnyTLS"], "tls", "utls", "enabled") {
					t.Fatalf("Quantumult X Reality uTLS conversion = %#v", byTag["AnyTLS"])
				}
			}
		})
	}
}

func TestURIToSingBoxCoversCommonSchemes(t *testing.T) {
	vmessPayload := base64.RawStdEncoding.EncodeToString([]byte(`{"v":"2","ps":"VMess","add":"vmess.example","port":"443","id":"00000000-0000-4000-8000-000000000005","aid":"0","scy":"auto","net":"ws","host":"edge.example","path":"/ws","tls":"tls","sni":"edge.example"}`))
	input := fmt.Sprintf("vless://00000000-0000-4000-8000-000000000001@vless.example:443?security=reality&sni=edge.example&fp=chrome&pbk=public&sid=abcd&type=ws&host=edge.example&path=%%2Fws#VLESS\n"+
		"hysteria2://pass@hy.example:443?sni=edge.example&obfs=salamander&obfs-password=obfs&ports=20000-21000#HY2\n"+
		"tuic://00000000-0000-4000-8000-000000000002:pass@tuic.example:443?sni=edge.example&alpn=h3&congestion_control=bbr&udp_relay_mode=native#TUIC\n"+
		"ss://YWVzLTEyOC1nY206cGFzcw@ss.example:443#SS\nvmess://%s\n", vmessPayload)
	document, err := urilist.Parse([]byte(input), protocol.NewRegistry(), urilist.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[int]string)
	for _, node := range document.Nodes {
		name := node.DisplayName
		if name == "" {
			name = "VMess"
		}
		names[node.Ordinal] = name
	}
	artifact, err := URIToSingBox(document.Nodes, names)
	if err != nil {
		t.Fatal(err)
	}
	outbounds := decodeOutbounds(t, artifact)
	if len(outbounds) != 5 {
		t.Fatalf("outbound count = %d\n%s", len(outbounds), artifact)
	}
	byTag := indexByTag(outbounds)
	if nestedString(byTag["VLESS"], "tls", "reality", "public_key") != "public" || byTag["SS"]["method"] != "aes-128-gcm" {
		t.Fatalf("URI conversion = %#v", byTag)
	}
}

func TestURIToSingBoxAppliesHTTPSProxyDefaults(t *testing.T) {
	document, err := urilist.Parse([]byte("https://proxy.example#HTTPS\n"), protocol.NewRegistry(), urilist.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := URIToSingBox(document.Nodes, map[int]string{0: "HTTPS"})
	if err != nil {
		t.Fatal(err)
	}
	outbounds := decodeOutbounds(t, artifact)
	if len(outbounds) != 1 || outbounds[0]["type"] != "http" || outbounds[0]["server_port"] != float64(443) {
		t.Fatalf("HTTPS proxy conversion = %#v", outbounds)
	}
	tls, ok := outbounds[0]["tls"].(map[string]interface{})
	if !ok || tls["enabled"] != true {
		t.Fatalf("HTTPS proxy TLS = %#v", outbounds[0]["tls"])
	}
}

func TestURIToSingBoxEnablesUTLSForRealityWithoutFingerprint(t *testing.T) {
	document, err := urilist.Parse([]byte("vless://00000000-0000-4000-8000-000000000001@vless.example:443?security=reality&sni=edge.example&pbk=public&sid=abcd#VLESS\n"), protocol.NewRegistry(), urilist.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := URIToSingBox(document.Nodes, map[int]string{0: "VLESS"})
	if err != nil {
		t.Fatal(err)
	}
	outbound := indexByTag(decodeOutbounds(t, artifact))["VLESS"]
	if !nestedBool(outbound, "tls", "utls", "enabled") {
		t.Fatalf("VLESS Reality uTLS conversion = %#v", outbound)
	}
}

func TestURIToSingBoxMapsCurrentQUICAndPortHoppingFields(t *testing.T) {
	input := []byte("vless://00000000-0000-4000-8000-000000000001@vless.example:443?type=quic&quicSecurity=none&headerType=none#VLESS\n" +
		"hysteria2://pass@hy.example:443?mport=20000-21000&sni=edge.example#HY2\n")
	document, err := urilist.Parse(input, protocol.NewRegistry(), urilist.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := URIToSingBox(document.Nodes, map[int]string{0: "VLESS", 1: "HY2"})
	if err != nil {
		t.Fatal(err)
	}
	outbounds := indexByTag(decodeOutbounds(t, artifact))
	if nestedString(outbounds["VLESS"], "transport", "type") != "quic" {
		t.Fatalf("VLESS QUIC conversion = %#v", outbounds["VLESS"])
	}
	ports, ok := outbounds["HY2"]["server_ports"].([]interface{})
	if !ok || len(ports) != 1 || ports[0] != "20000:21000" {
		t.Fatalf("Hysteria2 port hopping conversion = %#v", outbounds["HY2"])
	}
}

func TestURIToSingBoxRejectsNonEquivalentSecurityFields(t *testing.T) {
	tests := []string{
		"vless://00000000-0000-4000-8000-000000000001@vless.example:443?type=quic&quicSecurity=aes-128-gcm#VLESS\n",
		"hysteria2://pass@hy.example:443?pinSHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef#HY2\n",
		"hysteria2://pass@hy.example:443?mport=70000#HY2\n",
	}
	for _, input := range tests {
		document, err := urilist.Parse([]byte(input), protocol.NewRegistry(), urilist.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := URIToSingBox(document.Nodes, map[int]string{0: "Node"}); err == nil {
			t.Fatalf("unsafe URI conversion succeeded for %q", input)
		}
	}
}

func decodeOutbounds(t *testing.T, artifact []byte) []map[string]interface{} {
	t.Helper()
	var document struct {
		Outbounds []map[string]interface{} `json:"outbounds"`
	}
	if err := json.Unmarshal(artifact, &document); err != nil {
		t.Fatal(err)
	}
	return document.Outbounds
}

func indexByTag(outbounds []map[string]interface{}) map[string]map[string]interface{} {
	result := make(map[string]map[string]interface{}, len(outbounds))
	for _, outbound := range outbounds {
		result[outbound["tag"].(string)] = outbound
	}
	return result
}

func nestedString(root map[string]interface{}, path ...string) string {
	var current interface{} = root
	for _, part := range path {
		mapping, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current = mapping[part]
	}
	value, _ := current.(string)
	return value
}

func nestedBool(root map[string]interface{}, path ...string) bool {
	var current interface{} = root
	for _, part := range path {
		mapping, ok := current.(map[string]interface{})
		if !ok {
			return false
		}
		current = mapping[part]
	}
	value, _ := current.(bool)
	return value
}
