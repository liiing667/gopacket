package ip4defrag

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

func extra39158Frag(proto layers.IPProtocol, id uint16, src, dst net.IP, off uint16, payload []byte) *layers.IPv4 {
	return &layers.IPv4{
		BaseLayer:  layers.BaseLayer{Payload: payload},
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     uint16(20 + len(payload)),
		Id:         id,
		Flags:      layers.IPv4MoreFragments,
		FragOffset: off,
		TTL:        64,
		Protocol:   proto,
		SrcIP:      src,
		DstIP:      dst,
	}
}

func extra39158Final(f *layers.IPv4) *layers.IPv4 {
	f.Flags = 0
	return f
}

func TestExtraProtocolIsolation(t *testing.T) {
	d := NewIPv4Defragmenter()
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)

	udp0 := extra39158Frag(layers.IPProtocolUDP, 7, src, dst, 0, []byte("udp-0001"))
	udp1 := extra39158Final(extra39158Frag(layers.IPProtocolUDP, 7, src, dst, 1, []byte("udp-0002")))
	tcp0 := extra39158Frag(layers.IPProtocolTCP, 7, src, dst, 0, []byte("tcp-0001"))
	tcp1 := extra39158Final(extra39158Frag(layers.IPProtocolTCP, 7, src, dst, 1, []byte("tcp-0002")))

	if out, err := d.DefragIPv4(udp0); out != nil || err != nil {
		t.Fatalf("udp first: out=%v err=%v", out, err)
	}
	if out, err := d.DefragIPv4(tcp0); out != nil || err != nil {
		t.Fatalf("tcp first: out=%v err=%v", out, err)
	}
	if d.ActiveGenerations() != 2 {
		t.Fatalf("active generations = %d, want 2", d.ActiveGenerations())
	}
	out, err := d.DefragIPv4(tcp1)
	if err != nil || out == nil {
		t.Fatalf("tcp final: out=%v err=%v", out, err)
	}
	if got, want := out.Payload, []byte("tcp-0001tcp-0002"); !bytes.Equal(got, want) {
		t.Fatalf("tcp payload = %q, want %q", got, want)
	}
	out, err = d.DefragIPv4(udp1)
	if err != nil || out == nil {
		t.Fatalf("udp final: out=%v err=%v", out, err)
	}
	if got, want := out.Payload, []byte("udp-0001udp-0002"); !bytes.Equal(got, want) {
		t.Fatalf("udp payload = %q, want %q", got, want)
	}
	if d.ActiveGenerations() != 0 {
		t.Fatalf("active generations after completion = %d, want 0", d.ActiveGenerations())
	}
}

func TestExtraSourceIsolation(t *testing.T) {
	d := NewIPv4Defragmenter()
	dst := net.IPv4(10, 0, 0, 2)
	srcA := net.IPv4(10, 0, 0, 1)
	srcB := net.IPv4(10, 0, 0, 3)

	a0 := extra39158Frag(layers.IPProtocolUDP, 9, srcA, dst, 0, []byte("aaaaaaaa"))
	b0 := extra39158Frag(layers.IPProtocolUDP, 9, srcB, dst, 0, []byte("bbbbbbbb"))
	a1 := extra39158Final(extra39158Frag(layers.IPProtocolUDP, 9, srcA, dst, 1, []byte("AAAAAAA1")))
	b1 := extra39158Final(extra39158Frag(layers.IPProtocolUDP, 9, srcB, dst, 1, []byte("BBBBBBB1")))

	for _, f := range []*layers.IPv4{a0, b0} {
		if out, err := d.DefragIPv4(f); out != nil || err != nil {
			t.Fatalf("first fragment: out=%v err=%v", out, err)
		}
	}
	out, err := d.DefragIPv4(a1)
	if err != nil || out == nil || string(out.Payload) != "aaaaaaaaAAAAAAA1" {
		t.Fatalf("flow A: out=%v err=%v payload=%q", out, err, extra39158Payload(out))
	}
	out, err = d.DefragIPv4(b1)
	if err != nil || out == nil || string(out.Payload) != "bbbbbbbbBBBBBBB1" {
		t.Fatalf("flow B: out=%v err=%v payload=%q", out, err, extra39158Payload(out))
	}
}

func extra39158Payload(ip *layers.IPv4) []byte {
	if ip == nil {
		return nil
	}
	return ip.Payload
}

func TestExtraOutOfOrder(t *testing.T) {
	d := NewIPv4Defragmenter()
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	f0 := extra39158Frag(layers.IPProtocolUDP, 11, src, dst, 0, []byte("0123456789abcdef"))
	f1 := extra39158Frag(layers.IPProtocolUDP, 11, src, dst, 2, []byte("ghijklmnopqrstuv"))
	f2 := extra39158Final(extra39158Frag(layers.IPProtocolUDP, 11, src, dst, 4, []byte("wxyz1234")))
	for _, f := range []*layers.IPv4{f2, f1} {
		if out, err := d.DefragIPv4(f); out != nil || err != nil {
			t.Fatalf("out-of-order fragment: out=%v err=%v", out, err)
		}
	}
	out, err := d.DefragIPv4(f0)
	if err != nil || out == nil {
		t.Fatalf("final out-of-order fragment: out=%v err=%v", out, err)
	}
	if got, want := out.Payload, []byte("0123456789abcdefghijklmnopqrstuvwxyz1234"); !bytes.Equal(got, want) {
		t.Fatalf("payload = %q, want %q", got, want)
	}
	if out.TTL != 64 || out.Protocol != layers.IPProtocolUDP || out.Id != 11 {
		t.Fatalf("identity not retained: %+v", out)
	}
}

func TestExtraOverlapFirstFragmentWins(t *testing.T) {
	d := NewIPv4Defragmenter()
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)

	old := extra39158Frag(layers.IPProtocolUDP, 13, src, dst, 0, []byte("OLD-OLD-OLD-OLD!"))
	if out, err := d.DefragIPv4(old); out != nil || err != nil {
		t.Fatalf("old fragment: out=%v err=%v", out, err)
	}
	// Overlaps [8,16) with different bytes.  The first (lower-offset)
	// fragment wins the overlap, while the non-overlapping tail is kept.
	conflict := extra39158Frag(layers.IPProtocolUDP, 13, src, dst, 1, []byte("NEW-NEW-NEW-NEW!"))
	if out, err := d.DefragIPv4(conflict); out != nil || err != nil {
		t.Fatalf("conflicting fragment: out=%v err=%v", out, err)
	}
	last := extra39158Final(extra39158Frag(layers.IPProtocolUDP, 13, src, dst, 3, []byte("tail0000")))
	out, err := d.DefragIPv4(last)
	if err != nil || out == nil {
		t.Fatalf("last: out=%v err=%v", out, err)
	}
	if got, want := string(out.Payload), "OLD-OLD-OLD-OLD!"+"NEW-NEW!"+"tail0000"; got != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}
	if d.ActiveGenerations() != 0 {
		t.Fatalf("active generations = %d, want 0", d.ActiveGenerations())
	}
}

func TestExtraIDReuseConflictingFirstFragment(t *testing.T) {
	d := NewIPv4Defragmenter()
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)

	old := extra39158Frag(layers.IPProtocolUDP, 14, src, dst, 0, []byte("old-0001"))
	if out, err := d.DefragIPv4(old); out != nil || err != nil {
		t.Fatalf("old first: out=%v err=%v", out, err)
	}
	// Same key, different first fragment: this starts over instead of
	// retaining the old bytes.
	newFirst := extra39158Frag(layers.IPProtocolUDP, 14, src, dst, 0, []byte("new-0001"))
	if out, err := d.DefragIPv4(newFirst); out != nil || err != nil {
		t.Fatalf("new first: out=%v err=%v", out, err)
	}
	last := extra39158Final(extra39158Frag(layers.IPProtocolUDP, 14, src, dst, 1, []byte("new-0002")))
	out, err := d.DefragIPv4(last)
	if err != nil || out == nil {
		t.Fatalf("new last: out=%v err=%v", out, err)
	}
	if got, want := string(out.Payload), "new-0001new-0002"; got != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}

func TestExtraIDReuseAfterCompletion(t *testing.T) {
	d := NewIPv4Defragmenter()
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	for round, chunk := range []string{"first---", "second--"} {
		f0 := extra39158Frag(layers.IPProtocolUDP, 15, src, dst, 0, []byte(chunk))
		f1 := extra39158Final(extra39158Frag(layers.IPProtocolUDP, 15, src, dst, 1, []byte("end00000")))
		if out, err := d.DefragIPv4(f0); out != nil || err != nil {
			t.Fatalf("round %d first: out=%v err=%v", round, out, err)
		}
		out, err := d.DefragIPv4(f1)
		if err != nil || out == nil {
			t.Fatalf("round %d final: out=%v err=%v", round, out, err)
		}
		if got, want := string(out.Payload), chunk+"end00000"; got != want {
			t.Fatalf("round %d payload = %q, want %q", round, got, want)
		}
	}
}

func TestExtraDiscardLeavesNoState(t *testing.T) {
	d := NewIPv4Defragmenter()
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)

	old := extra39158Frag(layers.IPProtocolUDP, 17, src, dst, 0, []byte("old-old-"))
	if _, err := d.DefragIPv4(old); err != nil {
		t.Fatal(err)
	}
	if n := d.DiscardOlderThan(time.Now()); n != 1 {
		t.Fatalf("discarded = %d, want 1", n)
	}
	if d.ActiveGenerations() != 0 {
		t.Fatalf("active generations = %d, want 0", d.ActiveGenerations())
	}
	first := extra39158Frag(layers.IPProtocolUDP, 17, src, dst, 0, []byte("new-new-"))
	last := extra39158Final(extra39158Frag(layers.IPProtocolUDP, 17, src, dst, 1, []byte("end00000")))
	if out, err := d.DefragIPv4(first); out != nil || err != nil {
		t.Fatalf("new first: out=%v err=%v", out, err)
	}
	out, err := d.DefragIPv4(last)
	if err != nil || out == nil || string(out.Payload) != "new-new-end00000" {
		t.Fatalf("new datagram: out=%v err=%v payload=%q", out, err, extra39158Payload(out))
	}
}

func TestExtraPayloadCopied(t *testing.T) {
	d := NewIPv4Defragmenter()
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	payload := []byte("01234567")
	f0 := extra39158Frag(layers.IPProtocolUDP, 19, src, dst, 0, payload)
	if _, err := d.DefragIPv4(f0); err != nil {
		t.Fatal(err)
	}
	copy(payload, "XXXXXXXX")
	f1 := extra39158Final(extra39158Frag(layers.IPProtocolUDP, 19, src, dst, 1, []byte("tail0000")))
	out, err := d.DefragIPv4(f1)
	if err != nil || out == nil {
		t.Fatalf("final: out=%v err=%v", out, err)
	}
	if got, want := string(out.Payload), "01234567tail0000"; got != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}

func TestExtraByteBudgetDiscardsGeneration(t *testing.T) {
	d := NewIPv4Defragmenter()
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)

	first := extra39158Frag(layers.IPProtocolUDP, 21, src, dst, 0, make([]byte, 40000))
	if _, err := d.DefragIPv4(first); err != nil {
		t.Fatal(err)
	}
	// This fragment fits the IPv4 offset/size checks but pushes the total
	// buffered bytes past the reassembly budget.
	second := extra39158Frag(layers.IPProtocolUDP, 21, src, dst, 500, make([]byte, 40000))
	if _, err := d.DefragIPv4(second); err == nil {
		t.Fatal("expected byte budget error")
	}
	if d.ActiveGenerations() != 0 {
		t.Fatalf("active generations = %d, want 0", d.ActiveGenerations())
	}
}
