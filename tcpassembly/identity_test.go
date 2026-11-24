// Copyright 2025 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package tcpassembly

import (
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type identityFactory struct {
	mu      sync.Mutex
	created int
	bytes   int
}

func (f *identityFactory) New(netFlow, tcpFlow gopacket.Flow) Stream {
	f.mu.Lock()
	f.created++
	f.mu.Unlock()
	return f
}

func (f *identityFactory) Reassembled(rs []Reassembly) {
	n := 0
	for _, r := range rs {
		n += len(r.Bytes)
	}
	f.mu.Lock()
	f.bytes += n
	f.mu.Unlock()
}

func (f *identityFactory) ReassemblyComplete() {}

func (f *identityFactory) stats() (created, bytes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.created, f.bytes
}

// TestStreamPoolStaleRemoveKeepsCurrentConnection guards against a late
// cleanup deleting the connection that currently owns a key.
func TestStreamPoolStaleRemoveKeepsCurrentConnection(t *testing.T) {
	fact := &identityFactory{}
	pool := NewStreamPool(fact)
	tcp := &layers.TCP{SrcPort: 1, DstPort: 2, SYN: true, Seq: 1000}
	tcp.SetInternalPortsForTesting()
	k := key{netFlow, tcp.TransportFlow()}

	first := pool.getConnection(k, false, time.Now())
	if first == nil {
		t.Fatal("failed to create first connection")
	}
	pool.remove(first)

	second := pool.getConnection(k, false, time.Now())
	if second == nil {
		t.Fatal("failed to create second connection")
	}
	if second == first {
		t.Fatal("connection object was recycled for a different flow identity")
	}

	pool.remove(first)
	pool.mu.RLock()
	current := pool.conns[k]
	pool.mu.RUnlock()
	if current != second {
		t.Fatal("stale remove deleted the current connection")
	}
}

// TestConcurrentAssembleCreatesOneStream checks that concurrent assemblers
// sharing a pool don't create two Streams for one connection.
func TestConcurrentAssembleCreatesOneStream(t *testing.T) {
	fact := &identityFactory{}
	pool := NewStreamPool(fact)
	assemblers := []*Assembler{NewAssembler(pool), NewAssembler(pool)}

	tcp := &layers.TCP{
		SrcPort:   1,
		DstPort:   2,
		SYN:       true,
		Seq:       1000,
		BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
	}
	tcp.SetInternalPortsForTesting()

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range assemblers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			assemblers[i].Assemble(netFlow, tcp)
		}(i)
	}
	close(start)
	wg.Wait()

	created, bytes := fact.stats()
	if created != 1 {
		t.Fatalf("created %d streams for one connection, want 1", created)
	}
	if bytes != 3 {
		t.Fatalf("delivered %d bytes, want 3", bytes)
	}
}

// TestCloseReleasesAllPages ensures closing a connection doesn't leave pages
// dangling in its lists.
func TestCloseReleasesAllPages(t *testing.T) {
	fact := &identityFactory{}
	pool := NewStreamPool(fact)
	a := NewAssembler(pool)
	tcp := &layers.TCP{SrcPort: 1, DstPort: 2, SYN: true, Seq: 1000}
	tcp.SetInternalPortsForTesting()
	k := key{netFlow, tcp.TransportFlow()}
	conn := pool.getConnection(k, false, time.Now())
	conn.mu.Lock()

	first := a.pc.next(time.Now())
	first.Bytes = first.buf[:3]
	first.seq = 1001
	second := a.pc.next(time.Now())
	second.Bytes = second.buf[:2]
	second.seq = 1004
	first.next = second
	second.prev = first
	conn.first, conn.last = first, second
	conn.pages = 2

	a.closeConnection(conn)
	conn.mu.Unlock()

	if conn.first != nil || conn.last != nil {
		t.Fatal("closed connection still references pages")
	}
	if conn.pages != 0 {
		t.Fatalf("closed connection still accounts for %d pages", conn.pages)
	}
	if a.pc.used != 0 {
		t.Fatalf("page cache still has %d pages in use", a.pc.used)
	}
}
