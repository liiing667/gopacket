// Copyright 2013 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Package ip4defrag implements a IPv4 defragmenter
package ip4defrag

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Quick and Easy to use debug code to trace
// how defrag works.
var debug debugging = false // or flip to true
type debugging bool

func (d debugging) Printf(format string, args ...interface{}) {
	if d {
		log.Printf(format, args...)
	}
}

// Constants determining how to handle fragments.
// Reference RFC 791, page 25
const (
	IPv4MinimumFragmentSize    = 8     // Minimum size of a single fragment
	IPv4MaximumSize            = 65535 // Maximum size of a fragment (2^16)
	IPv4MaximumFragmentOffset  = 8183  // Maximum offset of a fragment
	IPv4MaximumFragmentListLen = 8192  // Back out if we get more than this many fragments
)

// DefragIPv4 takes in an IPv4 packet with a fragment payload.
//
// It do not modify the IPv4 layer in place, 'in' remains untouched
// It returns a ready-to be used IPv4 layer.
//
// If the passed-in IPv4 layer is NOT fragmented, it will
// immediately return it without modifying the layer.
//
// If the IPv4 layer is a fragment and we don't have all
// fragments, it will return nil and store whatever internal
// information it needs to eventually defrag the packet.
//
// If the IPv4 layer is the last fragment needed to reconstruct
// the packet, a new IPv4 layer will be returned, and will be set to
// the entire defragmented packet,
//
// # It use a map of all the running flows
//
// Usage example:
//
//	func HandlePacket(in *layers.IPv4) err {
//	    defragger := ip4defrag.NewIPv4Defragmenter()
//	    in, err := defragger.DefragIPv4(in)
//	    if err != nil {
//	        return err
//	    } else if in == nil {
//	        return nil  // packet fragment, we don't have whole packet yet.
//	    }
//	    // At this point, we know that 'in' is defragmented.
//	    //It may be the same 'in' passed to
//		   // HandlePacket, or it may not, but we don't really care :)
//		   ... do stuff to 'in' ...
//	}
func (d *IPv4Defragmenter) DefragIPv4(in *layers.IPv4) (*layers.IPv4, error) {
	return d.DefragIPv4WithTimestamp(in, time.Now())
}

// DefragIPv4WithTimestamp provides functionality of DefragIPv4 with
// an additional timestamp parameter which is used for discarding
// old fragments instead of time.Now()
//
// This is useful when operating on pcap files instead of live captured data
func (d *IPv4Defragmenter) DefragIPv4WithTimestamp(in *layers.IPv4, t time.Time) (*layers.IPv4, error) {
	// check if we need to defrag
	if st := d.dontDefrag(in); st == true {
		debug.Printf("defrag: do nothing, do not need anything")
		return in, nil
	}
	// perfom security checks
	if err := d.securityChecks(in); err != nil {
		debug.Printf("defrag: alert security check")
		return nil, err
	}

	// ok, got a fragment
	debug.Printf("defrag: got a new fragment in.Id=%d in.FragOffset=%d in.Flags=%d\n",
		in.Id, in.FragOffset*8, in.Flags)

	// have we already seen a flow between src/dst with that Id?
	ipf := newIPv4(in)
	d.Lock()
	fl, exist := d.ipFlows[ipf]
	if !exist {
		// Bound the number of independent reassembly generations.  Without
		// this, an attacker can keep creating new source/destination/protocol
		// ID tuples (or reuse IDs from many sources) and pin memory until an
		// external timeout happens to run.
		if len(d.ipFlows) >= IPv4MaximumFragmentListLen {
			d.Unlock()
			return nil, fmt.Errorf("defrag: active fragment generation budget "+
				"hits its maximum size(%d)", IPv4MaximumFragmentListLen)
		}
		debug.Printf("defrag: unknown flow, creating a new one\n")
		fl = new(fragmentList)
		d.ipFlows[ipf] = fl
	}
	// insert, and if final build it
	out, err2 := fl.insert(in, t)

	// A completed datagram is committed and its generation is retired.  Any
	// rejected fragment (budget/security/build failure) must not leave a
	// half-built generation behind either: otherwise a later fragment with a
	// reused ID could complete the old data.
	if out != nil || err2 != nil {
		delete(d.ipFlows, ipf)
	}
	d.Unlock()

	if out != nil {
		return out, nil
	}
	return nil, err2
}

// DiscardOlderThan forgets all packets without any activity since
// time t. It returns the number of FragmentList aka number of
// fragment packets it has discarded.
func (d *IPv4Defragmenter) DiscardOlderThan(t time.Time) int {
	var nb int
	d.Lock()
	for k, v := range d.ipFlows {
		if v.LastSeen.Before(t) {
			nb = nb + 1
			delete(d.ipFlows, k)
		}
	}
	d.Unlock()
	return nb
}

// flush retires the fragment list for a particular flow.
func (d *IPv4Defragmenter) flush(ipf ipv4) {
	d.Lock()
	delete(d.ipFlows, ipf)
	d.Unlock()
}

// ActiveGenerations returns the number of fragment reassembly generations
// currently held by the defragmenter.  A generation is identified by the
// complete IPv4 source/destination/protocol/ID tuple, so fragments addressed
// to different identities never share a generation.
//
// The value is bounded by the fragment budget and is useful for monitoring
// that completed, discarded and rejected flows have really been retired.
func (d *IPv4Defragmenter) ActiveGenerations() int {
	d.RLock()
	defer d.RUnlock()
	return len(d.ipFlows)
}

// dontDefrag returns true if the IPv4 packet do not need
// any defragmentation
func (d *IPv4Defragmenter) dontDefrag(ip *layers.IPv4) bool {
	// don't defrag packet with DF flag
	if ip.Flags&layers.IPv4DontFragment != 0 {
		return true
	}
	// don't defrag not fragmented ones
	if ip.Flags&layers.IPv4MoreFragments == 0 && ip.FragOffset == 0 {
		return true
	}
	return false
}

// securityChecks performs the needed security checks
func (d *IPv4Defragmenter) securityChecks(ip *layers.IPv4) error {
	headerLength := int(ip.IHL) * 4
	if headerLength < 20 {
		// Layers constructed programmatically sometimes leave IHL at zero.
		// Use the minimum header size for validation in that case.
		headerLength = 20
	}
	length := int(ip.Length)
	if length == 0 && len(ip.Payload) > 0 {
		// Programmatically constructed test layers may omit Length.
		length = headerLength + len(ip.Payload)
	}
	if length < headerLength {
		return fmt.Errorf("defrag: fragment length smaller than its header "+
			"(handcrafted? %d < %d)", length, headerLength)
	}
	fragSize := length - headerLength

	// don't allow small fragments outside of specification
	if fragSize < IPv4MinimumFragmentSize {
		return fmt.Errorf("defrag: fragment too small "+
			"(handcrafted? %d < %d)", fragSize, IPv4MinimumFragmentSize)
	}

	// don't allow too big fragment offset
	if ip.FragOffset > IPv4MaximumFragmentOffset {
		return fmt.Errorf("defrag: fragment offset too big "+
			"(handcrafted? %d > %d)", ip.FragOffset, IPv4MaximumFragmentOffset)
	}
	fragOffset := int(ip.FragOffset) * 8

	// don't allow fragment that would oversize an IP packet
	if fragOffset+length > IPv4MaximumSize {
		return fmt.Errorf("defrag: fragment will overrun "+
			"(handcrafted? %d > %d)", fragOffset+length, IPv4MaximumSize)
	}

	return nil
}

// fragmentList holds a container/list used to contains IP
// packets/fragments.  It stores internal counters to track the
// maximum total of byte, and the current length it has received.
// It also stores a flag to know if he has seen the last packet.
type fragmentList struct {
	List          list.List
	Highest       uint16
	Current       uint16
	FinalReceived bool
	LastSeen      time.Time
	bytes         int
}

// insert inserts an IPv4 fragment into the fragment list.
//
// Fragments are kept ordered by offset so that legitimate out-of-order
// delivery can be reassembled.  Overlapping bytes use the first (lowest
// offset) fragment, which keeps reassembly deterministic.  A conflicting
// offset-zero fragment, or a conflicting final boundary, means the ID was
// reused: the old generation is discarded and the incoming fragment starts a
// fresh one rather than being spliced into the previous datagram.
func (f *fragmentList) insert(in *layers.IPv4, t time.Time) (*layers.IPv4, error) {
	fragOffset := int(in.FragOffset) * 8
	// Copy the payload: the caller (or a capture buffer reused for the next
	// packet) may overwrite it before the datagram is complete.
	payload := append([]byte(nil), in.Payload...)
	fragEnd := fragOffset + len(payload)
	headerLength := int(in.IHL) * 4
	if headerLength < 20 {
		headerLength = 20
	}
	if fragEnd+headerLength > IPv4MaximumSize {
		return nil, fmt.Errorf("defrag: fragment will overrun "+
			"(handcrafted? %d > %d)", fragEnd+headerLength, IPv4MaximumSize)
	}
	isFinal := in.Flags&layers.IPv4MoreFragments == 0

	duplicate := false
	conflict := false
	firstConflict := false
	for e := f.List.Front(); e != nil; e = e.Next() {
		frag, _ := e.Value.(*layers.IPv4)
		start := int(frag.FragOffset) * 8
		end := start + len(frag.Payload)
		existingFinal := frag.Flags&layers.IPv4MoreFragments == 0

		// The offset-zero fragment owns the datagram identity (header and
		// initial bytes).  If a different first fragment shows up for the same
		// tuple, the ID has been reused: retire the previous generation rather
		// than combining the two datagrams.
		if in.FragOffset == 0 && frag.FragOffset == 0 &&
			!fragmentsAgree(fragOffset, payload, start, frag.Payload) {
			firstConflict = true
			break
		}

		// A datagram has exactly one final boundary.  A different final end,
		// or data beyond the final end, is a new generation rather than an
		// extension of the old one.
		if isFinal && existingFinal {
			if end != fragEnd {
				conflict = true
				break
			}
		} else if isFinal && end > fragEnd {
			conflict = true
			break
		} else if existingFinal && fragEnd > end {
			conflict = true
			break
		}

		if start == fragOffset && len(frag.Payload) == len(payload) &&
			existingFinal == isFinal && bytes.Equal(frag.Payload, payload) {
			duplicate = true
		}
	}

	if firstConflict || conflict {
		// Never retain the old generation next to the new fragment: that is
		// exactly how stale/attacker-controlled bytes get published.
		debug.Printf("defrag: conflicting fragment for flow, resetting generation\n")
		f.reset()
		f.LastSeen = t
		f.insertSorted(in, payload, fragEnd, isFinal)
		if f.complete() {
			return f.build(in)
		}
		return nil, nil
	}

	f.LastSeen = t

	if duplicate {
		debug.Printf("defrag: ignoring duplicate frag %d\n", fragOffset)
		if f.complete() {
			return f.build(in)
		}
		return nil, nil
	}

	f.insertSorted(in, payload, fragEnd, isFinal)

	debug.Printf("defrag: insert ListLen: %d Highest:%d Current:%d\n",
		f.List.Len(), f.Highest, f.Current)

	// Enforce the fragment budget as part of committing a generation.  A
	// datagram that needed more fragments or bytes than the budget is not
	// published.
	if f.List.Len() > IPv4MaximumFragmentListLen {
		return nil, fmt.Errorf("defrag: Fragment List hits its maximum"+
			"size(%d), without success. Flushing the list",
			IPv4MaximumFragmentListLen)
	}
	if f.bytes > IPv4MaximumSize {
		return nil, fmt.Errorf("defrag: Fragment List hits its maximum"+
			"size(%d bytes), without success. Flushing the list",
			IPv4MaximumSize)
	}

	if f.complete() {
		return f.build(in)
	}
	return nil, nil
}

// reset retires every fragment currently associated with this generation.
func (f *fragmentList) reset() {
	f.List.Init()
	f.Highest = 0
	f.Current = 0
	f.FinalReceived = false
	f.bytes = 0
}

// insertSorted inserts a copy of the fragment in offset order.  Equal offsets
// keep arrival order, so the first copy of a duplicate wins; conflicting
// overlaps have already reset the generation before reaching this point.
func (f *fragmentList) insertSorted(in *layers.IPv4, payload []byte, fragEnd int, isFinal bool) {
	frag := *in
	frag.Payload = payload
	frag.SrcIP = append([]byte(nil), in.SrcIP...)
	frag.DstIP = append([]byte(nil), in.DstIP...)
	frag.Padding = append([]byte(nil), in.Padding...)
	frag.Options = append([]layers.IPv4Option(nil), in.Options...)
	for i := range frag.Options {
		frag.Options[i].OptionData = append([]byte(nil), frag.Options[i].OptionData...)
	}

	inserted := false
	for e := f.List.Front(); e != nil; e = e.Next() {
		existing, _ := e.Value.(*layers.IPv4)
		if existing.FragOffset > frag.FragOffset {
			f.List.InsertBefore(&frag, e)
			inserted = true
			break
		}
	}
	if !inserted {
		f.List.PushBack(&frag)
	}

	if fragEnd > int(f.Highest) {
		f.Highest = uint16(fragEnd)
	}
	if int(f.Current)+len(payload) > IPv4MaximumSize {
		f.Current = IPv4MaximumSize
	} else {
		f.Current += uint16(len(payload))
	}
	f.bytes += len(payload)
	if isFinal {
		f.FinalReceived = true
	}
}

// fragmentsAgree reports whether the overlapping portion of two fragments has
// identical bytes.  Non-overlapping ranges always agree.
func fragmentsAgree(aStart int, a []byte, bStart int, b []byte) bool {
	aEnd := aStart + len(a)
	bEnd := bStart + len(b)
	if aStart >= bEnd || bStart >= aEnd {
		return true
	}
	start := aStart
	if bStart > start {
		start = bStart
	}
	end := aEnd
	if bEnd < end {
		end = bEnd
	}
	return bytes.Equal(a[start-aStart:end-aStart], b[start-bStart:end-bStart])
}

// complete reports whether the final boundary is known and every byte from
// offset zero through that boundary is covered by at least one fragment.
func (f *fragmentList) complete() bool {
	if !f.FinalReceived {
		return false
	}

	target := -1
	for e := f.List.Front(); e != nil; e = e.Next() {
		frag, _ := e.Value.(*layers.IPv4)
		if frag.Flags&layers.IPv4MoreFragments != 0 {
			continue
		}
		end := int(frag.FragOffset)*8 + len(frag.Payload)
		if end > target {
			target = end
		}
	}
	if target < 0 {
		return false
	}
	if target == 0 {
		return true
	}

	covered := 0
	for e := f.List.Front(); e != nil; e = e.Next() {
		frag, _ := e.Value.(*layers.IPv4)
		start := int(frag.FragOffset) * 8
		if start > covered {
			return false
		}
		if end := start + len(frag.Payload); end > covered {
			covered = end
		}
		if covered >= target {
			return true
		}
	}
	return false
}

// build builds the final datagram from the covered fragments.  The header is
// taken from the first fragment (offset zero), so the completed packet keeps
// the identity of the datagram that was admitted, not that of whichever
// fragment happened to arrive last.
func (f *fragmentList) build(_ *layers.IPv4) (*layers.IPv4, error) {
	var (
		final  []byte
		first  *layers.IPv4
		target int
	)

	debug.Printf("defrag: building the datagram\n")
	for e := f.List.Front(); e != nil; e = e.Next() {
		frag, _ := e.Value.(*layers.IPv4)
		if first == nil && frag.FragOffset == 0 {
			first = frag
		}
		if frag.Flags&layers.IPv4MoreFragments == 0 {
			if end := int(frag.FragOffset)*8 + len(frag.Payload); end > target {
				target = end
			}
		}
	}
	if first == nil {
		return nil, errors.New("defrag: building - missing first fragment")
	}

	final = make([]byte, 0, target)
	for e := f.List.Front(); e != nil; e = e.Next() {
		frag, _ := e.Value.(*layers.IPv4)
		start := int(frag.FragOffset) * 8
		if start > len(final) {
			debug.Printf("defrag: hole found while building, stopping\n")
			return nil, errors.New("defrag: building - hole found")
		}
		if end := start + len(frag.Payload); end > len(final) {
			skip := len(final) - start
			if skip < 0 {
				skip = 0
			}
			if skip < len(frag.Payload) {
				final = append(final, frag.Payload[skip:]...)
			}
		}
		if len(final) >= target {
			break
		}
	}
	if len(final) < target {
		debug.Printf("defrag: hole found while building, stopping\n")
		return nil, errors.New("defrag: building - hole found")
	}
	if len(final) > target {
		final = final[:target]
	}

	out := &layers.IPv4{
		Version: first.Version,
		IHL:     first.IHL,
		TOS:     first.TOS,
		// Keep the historical contract: Length is the reassembled payload
		// size, matching the previous implementation for well-formed input.
		Length:     uint16(len(final)),
		Id:         first.Id,
		Flags:      0,
		FragOffset: 0,
		TTL:        first.TTL,
		Protocol:   first.Protocol,
		Checksum:   0,
		SrcIP:      append([]byte(nil), first.SrcIP...),
		DstIP:      append([]byte(nil), first.DstIP...),
		Options:    append([]layers.IPv4Option(nil), first.Options...),
		Padding:    append([]byte(nil), first.Padding...),
	}
	for i := range out.Options {
		out.Options[i].OptionData = append([]byte(nil), out.Options[i].OptionData...)
	}
	out.Payload = final

	return out, nil
}

// ipv4 is a struct to be used as a key.
type ipv4 struct {
	ip4      gopacket.Flow
	protocol layers.IPProtocol
	id       uint16
}

// newIPv4 returns a new initialized IPv4 Flow
func newIPv4(ip *layers.IPv4) ipv4 {
	return ipv4{
		ip4:      ip.NetworkFlow(),
		protocol: ip.Protocol,
		id:       ip.Id,
	}
}

// IPv4Defragmenter is a struct which embedded a map of
// all fragment/packet.
type IPv4Defragmenter struct {
	sync.RWMutex
	ipFlows map[ipv4]*fragmentList
}

// NewIPv4Defragmenter returns a new IPv4Defragmenter
// with an initialized map.
func NewIPv4Defragmenter() *IPv4Defragmenter {
	return &IPv4Defragmenter{
		ipFlows: make(map[ipv4]*fragmentList),
	}
}
