package protocol

import (
	"fmt"

	"github.com/doujialong/proxyloom/internal/jsonlossless"
)

const IdentityProjectionVersion = "singbox-connection-v2"

type projectionSpec map[string]projectionSpec

var (
	domainResolverIdentitySpec = fields("server", "strategy", "disable_cache", "rewrite_ttl", "client_subnet")
	tlsIdentitySpec            = projectionSpec{
		"enabled":                 nil,
		"disable_sni":             nil,
		"server_name":             nil,
		"insecure":                nil,
		"alpn":                    nil,
		"min_version":             nil,
		"max_version":             nil,
		"cipher_suites":           nil,
		"certificate":             nil,
		"certificate_path":        nil,
		"fragment":                nil,
		"fragment_fallback_delay": nil,
		"record_fragment":         nil,
		"ech": fields(
			"enabled",
			"config",
			"config_path",
			"pq_signature_schemes_enabled",
			"dynamic_record_sizing_disabled",
		),
		"utls":    fields("enabled", "fingerprint"),
		"reality": fields("enabled", "public_key", "short_id"),
	}
	transportIdentitySpec = projectionSpec{
		"type":                   nil,
		"host":                   nil,
		"path":                   nil,
		"method":                 nil,
		"headers":                nil,
		"idle_timeout":           nil,
		"ping_timeout":           nil,
		"max_early_data":         nil,
		"early_data_header_name": nil,
		"service_name":           nil,
		"permit_without_stream":  nil,
	}
	multiplexIdentitySpec = projectionSpec{
		"enabled":         nil,
		"protocol":        nil,
		"max_connections": nil,
		"min_streams":     nil,
		"max_streams":     nil,
		"padding":         nil,
		"brutal":          fields("enabled", "up_mbps", "down_mbps"),
	}
	udpOverTCPIdentitySpec = fields("enabled", "version")
	protocolIdentitySpecs  = buildProtocolIdentitySpecs()
)

// ProjectIdentity selects the connection-affecting fields declared by the
// pinned sing-box adapter. The returned AST is derived data and never replaces
// the lossless Raw Node.
func ProjectIdentity(definition Definition, raw *jsonlossless.Node) (*jsonlossless.Node, error) {
	if definition.IdentityProjection != IdentityProjectionVersion {
		return nil, fmt.Errorf("protocol %q has no semantic identity projection", definition.ID)
	}
	if raw == nil || raw.Kind != jsonlossless.KindObject {
		return nil, fmt.Errorf("identity projection requires an object")
	}
	spec, exists := protocolIdentitySpecs[definition.ID]
	if !exists {
		return nil, fmt.Errorf("identity projection %q is not registered", definition.ID)
	}
	return projectObject(raw, spec), nil
}

func buildProtocolIdentitySpecs() map[string]projectionSpec {
	protocolFields := map[string]projectionSpec{
		"socks": {
			"version": nil, "username": nil, "password": nil, "network": nil,
			"udp_over_tcp": udpOverTCPIdentitySpec,
		},
		"http": {
			"username": nil, "password": nil, "tls": tlsIdentitySpec, "path": nil, "headers": nil,
		},
		"shadowsocks": {
			"method": nil, "password": nil, "plugin": nil, "plugin_opts": nil, "network": nil,
			"udp_over_tcp": udpOverTCPIdentitySpec, "multiplex": multiplexIdentitySpec,
		},
		"vmess": {
			"uuid": nil, "security": nil, "alter_id": nil, "global_padding": nil,
			"authenticated_length": nil, "network": nil, "tls": tlsIdentitySpec,
			"packet_encoding": nil, "multiplex": multiplexIdentitySpec, "transport": transportIdentitySpec,
		},
		"vless": {
			"uuid": nil, "flow": nil, "network": nil, "tls": tlsIdentitySpec,
			"multiplex": multiplexIdentitySpec, "transport": transportIdentitySpec, "packet_encoding": nil,
		},
		"trojan": {
			"password": nil, "network": nil, "tls": tlsIdentitySpec,
			"multiplex": multiplexIdentitySpec, "transport": transportIdentitySpec,
		},
		"hysteria2": {
			"server_ports": nil, "hop_interval": nil, "up_mbps": nil, "down_mbps": nil,
			"obfs": fields("type", "password"), "password": nil, "network": nil, "tls": tlsIdentitySpec,
		},
		"tuic": {
			"uuid": nil, "password": nil, "congestion_control": nil, "udp_relay_mode": nil,
			"udp_over_stream": nil, "zero_rtt_handshake": nil, "heartbeat": nil, "network": nil,
			"tls": tlsIdentitySpec,
		},
		"anytls": {
			"tls": tlsIdentitySpec, "password": nil, "idle_session_check_interval": nil,
			"idle_session_timeout": nil, "min_idle_session": nil,
		},
	}
	common := projectionSpec{
		"type":                  nil,
		"detour":                nil,
		"bind_interface":        nil,
		"inet4_bind_address":    nil,
		"inet6_bind_address":    nil,
		"protect_path":          nil,
		"routing_mark":          nil,
		"reuse_addr":            nil,
		"netns":                 nil,
		"connect_timeout":       nil,
		"tcp_fast_open":         nil,
		"tcp_multi_path":        nil,
		"udp_fragment":          nil,
		"domain_resolver":       domainResolverIdentitySpec,
		"network_strategy":      nil,
		"network_type":          nil,
		"fallback_network_type": nil,
		"fallback_delay":        nil,
		"domain_strategy":       nil,
		"server":                nil,
		"server_port":           nil,
	}
	result := make(map[string]projectionSpec, len(protocolFields))
	for protocolID, specific := range protocolFields {
		combined := make(projectionSpec, len(common)+len(specific))
		for name, nested := range common {
			combined[name] = nested
		}
		for name, nested := range specific {
			combined[name] = nested
		}
		result[protocolID] = combined
	}
	return result
}

func fields(names ...string) projectionSpec {
	spec := make(projectionSpec, len(names))
	for _, name := range names {
		spec[name] = nil
	}
	return spec
}

func projectObject(raw *jsonlossless.Node, spec projectionSpec) *jsonlossless.Node {
	projection := jsonlossless.NewObject()
	for _, member := range raw.Members {
		nested, included := spec[member.Key]
		if !included {
			continue
		}
		value := member.Value.Clone()
		if nested != nil && member.Value.Kind == jsonlossless.KindObject {
			value = projectObject(member.Value, nested)
		}
		projection.Members = append(projection.Members, jsonlossless.Member{
			Key:    member.Key,
			KeyRaw: member.KeyRaw,
			Value:  value,
		})
	}
	return projection
}
