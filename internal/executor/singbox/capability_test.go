package singbox

import "testing"

func TestContainsECH(t *testing.T) {
	withECH := []byte(`[{"type":"vless","tls":{"enabled":true,"ech":{"enabled":true,"config":["abc"]}}}]`)
	withoutECH := []byte(`[{"type":"vless","tls":{"enabled":true,"server_name":"example.com"}}]`)
	if !ContainsECH(withECH) {
		t.Fatal("ECH configuration was not detected")
	}
	if ContainsECH(withoutECH) || ContainsECH([]byte(`not-json`)) {
		t.Fatal("non-ECH configuration was detected as ECH")
	}
}
