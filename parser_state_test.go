package gopacket_test

import (
	"reflect"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func regressionTCPPacket(t *testing.T) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 0, 2, 1},
		DstIP:    []byte{198, 51, 100, 1},
	}
	tcp := &layers.TCP{
		SrcPort:    12345,
		DstPort:    80,
		Seq:        1,
		Ack:        1,
		DataOffset: 5,
		ACK:        true,
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, ip4, tcp); err != nil {
		t.Fatalf("serialize TCP packet: %v", err)
	}
	return buf.Bytes()
}

func TestDecodingLayerParserClearsStaleLayerTypes(t *testing.T) {
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet)
	decoded := []gopacket.LayerType{layers.LayerTypeTCP}

	err := parser.DecodeLayers(nil, &decoded)
	if _, ok := err.(gopacket.UnsupportedLayerType); !ok {
		t.Fatalf("expected UnsupportedLayerType, got %T (%v)", err, err)
	}
	if len(decoded) != 0 {
		t.Fatalf("failed decode retained stale layer identities: %v", decoded)
	}
}

func TestDecodingLayerParserFailureThenTCPPacket(t *testing.T) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet, &eth, &ip4, &tcp,
	)
	decoded := []gopacket.LayerType{layers.LayerTypeTCP}

	if err := parser.DecodeLayers(nil, &decoded); err == nil {
		t.Fatal("expected short Ethernet packet to fail")
	}
	if len(decoded) != 0 {
		t.Fatalf("failed decode retained stale layer identities: %v", decoded)
	}

	if err := parser.DecodeLayers(regressionTCPPacket(t), &decoded); err != nil {
		t.Fatalf("normal Ethernet/IPv4/TCP packet failed: %v", err)
	}

	want := []gopacket.LayerType{
		layers.LayerTypeEthernet,
		layers.LayerTypeIPv4,
		layers.LayerTypeTCP,
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("decoded layers = %v, want %v", decoded, want)
	}

	truncatedIPv4 := regressionTCPPacket(t)[:14+10]
	if err := parser.DecodeLayers(truncatedIPv4, &decoded); err == nil {
		t.Fatal("expected truncated IPv4 packet to fail")
	}
	if !parser.Truncated {
		t.Fatal("truncated IPv4 packet did not set Truncated")
	}
	wantPrefix := []gopacket.LayerType{layers.LayerTypeEthernet}
	if !reflect.DeepEqual(decoded, wantPrefix) {
		t.Fatalf("truncated decode = %v, want current prefix %v", decoded, wantPrefix)
	}

	if err := parser.DecodeLayers(regressionTCPPacket(t), &decoded); err != nil {
		t.Fatalf("retry with normal Ethernet/IPv4/TCP packet failed: %v", err)
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("retried decoded layers = %v, want %v", decoded, want)
	}
}
