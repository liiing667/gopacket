// Copyright 2025 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package reassembly

import (
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestSequenceDifferenceAcrossWrap(t *testing.T) {
	if got, want := Sequence(0xFFFFFFF6).Difference(Sequence(10)), 20; got != want {
		t.Fatalf("Difference across wrap = %d, want %d", got, want)
	}
	if got, want := Sequence(10).Difference(Sequence(0xFFFFFFF6)), -20; got != want {
		t.Fatalf("reverse Difference across wrap = %d, want %d", got, want)
	}
}

type identityFactory struct {
	mu      sync.Mutex
	created int
	bytes   int
}

func (f *identityFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac AssemblerContext) Stream {
	f.mu.Lock()
	f.created++
	f.mu.Unlock()
	return f
}

func (f *identityFactory) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir TCPFlowDirection, nextSeq Sequence, start *bool, ac AssemblerContext) bool {
	return true
}

func (f *identityFactory) ReassembledSG(sg ScatterGather, ac AssemblerContext) {
	n, _ := sg.Lengths()
	f.mu.Lock()
	f.bytes += n
	f.mu.Unlock()
}

func (f *identityFactory) ReassemblyComplete(ac AssemblerContext) bool {
	return true
}

func (f *identityFactory) stats() (created, bytes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.created, f.bytes
}

// TestStreamPoolStaleRemoveKeepsCurrentConnection guards against a late
// cleanup deleting (or recycling) the connection that currently owns a key.
func TestStreamPoolStaleRemoveKeepsCurrentConnection(t *testing.T) {
	fact := &identityFactory{}
	pool := NewStreamPool(fact)
	tcp := &layers.TCP{SrcPort: 1, DstPort: 2, SYN: true, Seq: 1000}
	tcp.SetInternalPortsForTesting()
	k := key{netFlow, tcp.TransportFlow()}
	ctx := &testMemoryContext{}

	first, _, _ := pool.getConnection(k, false, time.Now(), tcp, ctx)
	if first == nil {
		t.Fatal("failed to create first connection")
	}
	pool.remove(first)

	second, _, _ := pool.getConnection(k, false, time.Now(), tcp, ctx)
	if second == nil {
		t.Fatal("failed to create second connection")
	}
	if second == first {
		t.Fatal("connection object was recycled for a different flow identity")
	}

	// Simulate a flusher that still holds the old connection and calls
	// remove after the key has been re-used.
	pool.remove(first)
	pool.mu.RLock()
	current := pool.conns[k]
	pool.mu.RUnlock()
	if current != second {
		t.Fatal("stale remove deleted the current connection")
	}
}

// TestConcurrentBidirectionalCreatesOneStream checks that two assemblers
// seeing the first packets of a connection in opposite directions agree on a
// single Stream.
func TestConcurrentBidirectionalCreatesOneStream(t *testing.T) {
	fact := &identityFactory{}
	pool := NewStreamPool(fact)
	ctx := &testMemoryContext{}

	c2s := &layers.TCP{
		SrcPort:   1,
		DstPort:   2,
		SYN:       true,
		Seq:       1000,
		BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
	}
	s2c := &layers.TCP{
		SrcPort:   2,
		DstPort:   1,
		SYN:       true,
		ACK:       true,
		Seq:       2000,
		BaseLayer: layers.BaseLayer{Payload: []byte{4, 5, 6}},
	}
	c2s.SetInternalPortsForTesting()
	s2c.SetInternalPortsForTesting()

	type packet struct {
		flow gopacket.Flow
		tcp  *layers.TCP
	}
	packets := []packet{
		{netFlow, c2s},
		{netFlow.Reverse(), s2c},
	}
	assemblers := []*Assembler{NewAssembler(pool), NewAssembler(pool)}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range packets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			assemblers[i].AssembleWithContext(packets[i].flow, packets[i].tcp, ctx)
		}(i)
	}
	close(start)
	wg.Wait()

	created, bytes := fact.stats()
	if created != 1 {
		t.Fatalf("created %d streams for one connection, want 1", created)
	}
	if bytes != 6 {
		t.Fatalf("delivered %d bytes, want 6", bytes)
	}
}

// TestOverlapAcrossSequenceWrap makes sure wraparound arithmetic doesn't make
// a retransmitted, overlapping segment get emitted twice.
func TestOverlapAcrossSequenceWrap(t *testing.T) {
	test(t, []testSequence{
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				SYN:       true,
				Seq:       0xFFFFFFFE,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3, 4}},
			},
			want: []Reassembly{
				{
					Start: true,
					Bytes: []byte{1, 2, 3, 4},
				},
			},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       3,
				BaseLayer: layers.BaseLayer{Payload: []byte{5, 6, 7}},
			},
			want: []Reassembly{
				{
					Bytes: []byte{5, 6, 7},
				},
			},
		},
		{
			// Starts 7 bytes before nextSeq (across the wrap) and
			// extends 2 bytes past it.
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       0xFFFFFFFF,
				BaseLayer: layers.BaseLayer{Payload: []byte{9, 5, 6, 7, 8, 9, 10, 11, 12}},
			},
			want: []Reassembly{
				{
					Bytes: []byte{11, 12},
				},
			},
		},
	})
}

// TestCloseReleasesAllPages ensures a timed out half-connection doesn't leave
// pages (including kept pages) dangling in its lists.
func TestCloseReleasesAllPages(t *testing.T) {
	fact := &identityFactory{}
	pool := NewStreamPool(fact)
	a := NewAssembler(pool)
	tcp := &layers.TCP{SrcPort: 1, DstPort: 2, SYN: true, Seq: 1000}
	tcp.SetInternalPortsForTesting()
	k := key{netFlow, tcp.TransportFlow()}
	ctx := &testMemoryContext{}
	conn, half, _ := pool.getConnection(k, false, time.Now(), tcp, ctx)
	conn.mu.Lock()

	first := a.pc.next(time.Now())
	first.bytes = first.buf[:3]
	first.seq = 1001
	second := a.pc.next(time.Now())
	second.bytes = second.buf[:2]
	second.seq = 1004
	first.next = second
	second.prev = first
	half.first, half.last = first, second
	half.pages = 2

	saved := a.pc.next(time.Now())
	saved.bytes = saved.buf[:1]
	saved.seq = 1006
	half.saved = saved
	half.pages++

	a.closeHalfConnection(conn, half)
	conn.mu.Unlock()

	if half.first != nil || half.last != nil || half.saved != nil {
		t.Fatal("closed half-connection still references pages")
	}
	if half.pages != 0 {
		t.Fatalf("closed half-connection still accounts for %d pages", half.pages)
	}
	if a.pc.used != 0 {
		t.Fatalf("page cache still has %d pages in use", a.pc.used)
	}
}
