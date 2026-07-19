package singbox

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/doujialong/proxyloom/internal/protocol"
)

func BenchmarkParse20000Outbounds(b *testing.B) {
	input := benchmarkOutbounds(20_000)
	limits := DefaultLimits()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		document, err := Parse(input, protocol.NewRegistry(), limits)
		if err != nil {
			b.Fatalf("Parse() error = %v", err)
		}
		if len(document.Nodes) != 20_000 {
			b.Fatalf("node count = %d", len(document.Nodes))
		}
	}
}

func benchmarkOutbounds(count int) []byte {
	var output bytes.Buffer
	output.Grow(count * 180)
	output.WriteByte('[')
	for index := 0; index < count; index++ {
		if index > 0 {
			output.WriteByte(',')
		}
		output.WriteString(`{"type":"vless","tag":"Node `)
		output.WriteString(strconv.Itoa(index))
		output.WriteString(`","server":"198.51.100.1","server_port":443,"uuid":"00000000-0000-0000-0000-`)
		serial := strconv.Itoa(1_000_000_000_000 + index)
		output.WriteString(serial)
		output.WriteString(`","future":{"number":900719925474099312345,"ratio":1.2300}}`)
	}
	output.WriteByte(']')
	return output.Bytes()
}
