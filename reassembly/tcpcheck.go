// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package reassembly

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
 * Check TCP packet against options (window, MSS)
 */

type tcpStreamOptions struct {
	mss           int
	scale         int
	receiveWindow uint

	// Sequence state for this direction.  It is kept here (and not only in
	// the assembler) so that an ACK can be checked against the packets seen
	// in the opposite direction.
	nextSeq Sequence
	seqSet  bool

	// Identity of the SYN seen for this direction.  Once a SYN has been
	// observed, a later SYN with another ISN or another option set belongs
	// to a different connection and must not replace the current state.
	synSeen bool
	synSeq  Sequence
}

// TCPOptionCheck contains options for the two directions
type TCPOptionCheck struct {
	options [2]tcpStreamOptions
}

func (t *TCPOptionCheck) getOptions(dir TCPFlowDirection) *tcpStreamOptions {
	if dir == TCPDirClientToServer {
		return &t.options[0]
	}
	return &t.options[1]
}

// NewTCPOptionCheck creates default options
func NewTCPOptionCheck() TCPOptionCheck {
	return TCPOptionCheck{
		options: [2]tcpStreamOptions{
			tcpStreamOptions{
				mss:           0,
				scale:         -1,
				receiveWindow: 0,
			}, tcpStreamOptions{
				mss:           0,
				scale:         -1,
				receiveWindow: 0,
			},
		},
	}
}

func withinWindow(diff int, window uint) bool {
	if diff < 0 {
		diff = -diff
	}
	return uint64(diff) <= uint64(window)
}

func (o *tcpStreamOptions) advance(tcp *layers.TCP) {
	n := len(tcp.Payload)
	if tcp.SYN {
		n++
	}
	if tcp.FIN {
		n++
	}
	end := Sequence(tcp.Seq).Add(n)
	if !o.seqSet {
		o.nextSeq = end
		o.seqSet = true
		return
	}
	// Only move forward.  Retransmitted data must not rewind the sequence
	// state used to validate acknowledgements from the peer.
	if o.nextSeq.Difference(Sequence(tcp.Seq)) >= 0 &&
		o.nextSeq.Difference(end) > 0 {
		o.nextSeq = end
	}
}

func parseSynOptions(tcp *layers.TCP) (mss, scale int, err error) {
	mss = -1
	scale = -1
	for _, o := range tcp.Options {
		switch o.OptionType {
		case 2: // MSS
			if len(o.OptionData) != 2 {
				return mss, scale, fmt.Errorf("MSS option data length expected 2, got %d", len(o.OptionData))
			}
			mss = int(binary.BigEndian.Uint16(o.OptionData[:2]))
		case 3: // Window scaling
			if len(o.OptionData) != 1 {
				return mss, scale, fmt.Errorf("Window scaling length expected: 1, got %d", len(o.OptionData))
			}
			scale = int(o.OptionData[0])
		}
	}
	return mss, scale, nil
}

// acceptSYN validates and applies a SYN (or SYN+ACK) for one direction.
func (t *TCPOptionCheck) acceptSYN(tcp *layers.TCP, dir TCPFlowDirection) error {
	options := t.getOptions(dir)
	revOptions := t.getOptions(dir.Reverse())
	mss, scale, err := parseSynOptions(tcp)
	if err != nil {
		return err
	}

	if options.synSeen {
		// A retransmitted SYN must describe the same connection.  In
		// particular it must not be allowed to change the window scaling
		// factor while data is in flight.
		if Sequence(tcp.Seq) != options.synSeq {
			return fmt.Errorf("SYN for %s changed ISN (got %d, current %d)",
				dir, tcp.Seq, options.synSeq)
		}
		if mss != options.mss || scale != options.scale {
			return fmt.Errorf("SYN for %s changed options (mss:%d/%d, scale:%d/%d)",
				dir, mss, options.mss, scale, options.scale)
		}
		if tcp.ACK && revOptions.seqSet && Sequence(tcp.Ack) != revOptions.nextSeq {
			return fmt.Errorf("SYN+ACK for %s has unexpected ack (got %d, expected %d)",
				dir, tcp.Ack, revOptions.nextSeq)
		}
		return nil
	}

	// A bare SYN from the peer while the peer direction already belongs to
	// this connection is a new (or stale) connection, not data for this one.
	if revOptions.synSeen && !tcp.ACK {
		return fmt.Errorf("unexpected SYN for %s after establishment", dir)
	}
	if tcp.ACK && revOptions.seqSet && Sequence(tcp.Ack) != revOptions.nextSeq {
		return fmt.Errorf("SYN+ACK for %s has unexpected ack (got %d, expected %d)",
			dir, tcp.Ack, revOptions.nextSeq)
	}

	options.mss = mss
	options.scale = scale
	options.synSeen = true
	options.synSeq = Sequence(tcp.Seq)
	options.nextSeq = Sequence(tcp.Seq).Add(1)
	options.seqSet = true
	return nil
}

// validateAck checks that an acknowledgement belongs to the packets seen in
// the opposite direction.
func (t *TCPOptionCheck) validateAck(tcp *layers.TCP, dir TCPFlowDirection) error {
	revOptions := t.getOptions(dir.Reverse())
	if !revOptions.seqSet {
		return nil
	}
	diff := revOptions.nextSeq.Difference(Sequence(tcp.Ack))
	// An ACK must name the next byte the opposite direction is expected to
	// send.  A capture that started after the SYN is one byte short of the
	// peer's view, so allow that single missing byte; nothing wider.
	if diff != 0 && !(diff == 1 && !revOptions.synSeen) {
		return fmt.Errorf("ACK %d does not match expected sequence %d",
			tcp.Ack, revOptions.nextSeq)
	}
	return nil
}

// Accept checks whether the packet should be accepted by checking TCP options
// and the sequence identity of the flow.
//
// State changes are committed only after every check succeeds, so a rejected
// packet cannot advance or corrupt the state used for later packets.
func (t *TCPOptionCheck) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir TCPFlowDirection, nextSeq Sequence, start *bool) error {
	candidate := *t
	options := candidate.getOptions(dir)

	if tcp.SYN {
		if err := candidate.acceptSYN(tcp, dir); err != nil {
			return err
		}
	} else {
		if tcp.ACK {
			if err := candidate.validateAck(tcp, dir); err != nil {
				return err
			}
		}
		if nextSeq != invalidSequence {
			revOptions := candidate.getOptions(dir.Reverse())
			length := len(tcp.Payload)

			// Check packet is in the correct window
			diff := nextSeq.Difference(Sequence(tcp.Seq))
			if diff == -1 && (length == 1 || length == 0) {
				// This is probably a Keep-alive
				// TODO: check byte is ok
			} else if diff < 0 {
				return fmt.Errorf("Re-emitted packet (diff:%d,seq:%d,rev-ack:%d)", diff,
					tcp.Seq, nextSeq)
			} else if revOptions.mss > 0 && length > revOptions.mss {
				return fmt.Errorf("%d > mss (%d)", length, revOptions.mss)
			} else if revOptions.receiveWindow != 0 && revOptions.scale < 0 && diff > int(revOptions.receiveWindow) {
				return fmt.Errorf("%d > receiveWindow(%d)", diff, revOptions.receiveWindow)
			}
		}
		options.advance(tcp)
	}

	// Compute receiveWindow
	options.receiveWindow = uint(tcp.Window)
	if options.scale > 0 {
		options.receiveWindow = options.receiveWindow << (uint(options.scale))
	}

	*t = candidate
	return nil
}

// TCPSimpleFSM implements a very simple TCP state machine
//
// Usage:
// When implementing a Stream interface and to avoid to consider packets that
// would be rejected due to client/server's TCP stack, the  Accept() can call
// TCPSimpleFSM.CheckState().
//
// Limitations:
//   - sequence and ACK checks are window based, so a capture that starts in the
//     middle of a connection can only validate the directions it has observed.
//   - window scaling is not interpreted by the FSM (use TCPOptionCheck for that).
type TCPSimpleFSM struct {
	dir     TCPFlowDirection
	state   int
	options TCPSimpleFSMOptions
	flows   [2]tcpFSMState
}

type tcpFSMState struct {
	nextSeq Sequence
	seqSet  bool
	synSeen bool
	synSeq  Sequence
	window  uint
}

// TCPSimpleFSMOptions holds options for TCPSimpleFSM
type TCPSimpleFSMOptions struct {
	SupportMissingEstablishment bool // Allow missing SYN, SYN+ACK, ACK
}

// Internal values of state machine
const (
	TCPStateClosed      = 0
	TCPStateSynSent     = 1
	TCPStateEstablished = 2
	TCPStateCloseWait   = 3
	TCPStateLastAck     = 4
	TCPStateReset       = 5
)

// NewTCPSimpleFSM creates a new TCPSimpleFSM
func NewTCPSimpleFSM(options TCPSimpleFSMOptions) *TCPSimpleFSM {
	return &TCPSimpleFSM{
		state:   TCPStateClosed,
		options: options,
	}
}

func (t *TCPSimpleFSM) flowState(dir TCPFlowDirection) *tcpFSMState {
	if dir == TCPDirClientToServer {
		return &t.flows[0]
	}
	return &t.flows[1]
}

func (t *TCPSimpleFSM) allowsSeq(s *tcpFSMState, seq Sequence) bool {
	if !s.seqSet {
		return true
	}
	return withinWindow(s.nextSeq.Difference(seq), s.window)
}

func (t *TCPSimpleFSM) allowsAck(s *tcpFSMState, ack Sequence) bool {
	if !s.seqSet {
		return true
	}
	diff := s.nextSeq.Difference(ack)
	// The peer's ACK names the next byte we expect from it.  Only the
	// one-byte difference caused by a missing SYN is tolerated.
	return diff == 0 || (diff == 1 && !s.synSeen)
}

func (t *TCPSimpleFSM) validatePacket(s *tcpFSMState, rev *tcpFSMState, tcp *layers.TCP) bool {
	if !t.allowsSeq(s, Sequence(tcp.Seq)) {
		return false
	}
	if tcp.ACK && !t.allowsAck(rev, Sequence(tcp.Ack)) {
		return false
	}
	return true
}

func (t *TCPSimpleFSM) String() string {
	switch t.state {
	case TCPStateClosed:
		return "Closed"
	case TCPStateSynSent:
		return "SynSent"
	case TCPStateEstablished:
		return "Established"
	case TCPStateCloseWait:
		return "CloseWait"
	case TCPStateLastAck:
		return "LastAck"
	case TCPStateReset:
		return "Reset"
	}
	return "?"
}

// CheckState returns false if tcp is invalid wrt current state or update the state machine's state.
//
// The state machine is updated only if the packet is accepted.  Packets whose
// direction, sequence number, or acknowledgement do not belong to the current
// flow cannot advance the connection.
func (t *TCPSimpleFSM) CheckState(tcp *layers.TCP, dir TCPFlowDirection) bool {
	candidate := *t
	if !candidate.checkState(tcp, dir) {
		return false
	}
	*t = candidate
	return true
}

func (t *TCPSimpleFSM) checkState(tcp *layers.TCP, dir TCPFlowDirection) bool {
	state := t.flowState(dir)
	revState := t.flowState(dir.Reverse())

	if t.state == TCPStateClosed && t.options.SupportMissingEstablishment && !(tcp.SYN && !tcp.ACK) {
		/* try to figure out state */
		switch true {
		case tcp.SYN && tcp.ACK:
			t.state = TCPStateSynSent
			t.dir = dir.Reverse()
		case tcp.FIN && !tcp.ACK:
			t.state = TCPStateEstablished
			t.dir = dir
		case tcp.FIN && tcp.ACK:
			t.state = TCPStateCloseWait
			t.dir = dir.Reverse()
		default:
			t.state = TCPStateEstablished
			t.dir = dir
		}
		// If this packet acknowledges data, remember where the opposite
		// direction starts even though its SYN was not observed.
		if tcp.ACK && !revState.seqSet {
			revState.nextSeq = Sequence(tcp.Ack)
			revState.seqSet = true
		}
	}

	switch t.state {
	/* openning connection */
	case TCPStateClosed:
		if tcp.SYN && !tcp.ACK {
			state.synSeen = true
			state.synSeq = Sequence(tcp.Seq)
			state.nextSeq = Sequence(tcp.Seq).Add(1)
			state.seqSet = true
			state.window = uint(tcp.Window)
			t.dir = dir
			t.state = TCPStateSynSent
			return true
		}
	case TCPStateSynSent:
		if tcp.RST {
			if state.seqSet && !t.allowsSeq(state, Sequence(tcp.Seq)) {
				return false
			}
			t.state = TCPStateReset
			return true
		}

		if tcp.SYN && tcp.ACK && dir == t.dir.Reverse() {
			if state.synSeen && state.synSeq != Sequence(tcp.Seq) {
				return false
			}
			// A handshake acknowledgement is exact: unlike data ACKs it
			// cannot acknowledge anything beyond the initial SYN.
			if revState.seqSet && Sequence(tcp.Ack) != revState.nextSeq {
				return false
			}
			if !revState.seqSet {
				// The SYN was missed; the ACK still gives the next
				// expected sequence number for the initiator.
				revState.nextSeq = Sequence(tcp.Ack)
				revState.seqSet = true
			}
			if !state.synSeen {
				state.synSeen = true
				state.synSeq = Sequence(tcp.Seq)
				state.nextSeq = Sequence(tcp.Seq).Add(1)
				state.seqSet = true
			}
			state.window = uint(tcp.Window)
			t.state = TCPStateEstablished
			return true
		}
		if tcp.SYN && !tcp.ACK && dir == t.dir {
			// re-transmission of the same SYN
			if state.synSeen && state.synSeq != Sequence(tcp.Seq) {
				return false
			}
			return true
		}
	/* established */
	case TCPStateEstablished:
		if tcp.RST {
			if !t.validatePacket(state, revState, tcp) {
				return false
			}
			t.state = TCPStateReset
			return true
		}

		if tcp.SYN {
			// Only a retransmission of this flow's handshake packet is
			// valid here.  A new SYN must not replace the established
			// sequence/option state.
			if !state.synSeen || state.synSeq != Sequence(tcp.Seq) {
				return false
			}
			if tcp.ACK && revState.seqSet && Sequence(tcp.Ack) != revState.nextSeq {
				return false
			}
			return true
		}

		if !t.validatePacket(state, revState, tcp) {
			return false
		}

		if tcp.FIN {
			t.state = TCPStateCloseWait
			t.dir = dir
		}
		state.advance(tcp)
		// accept any packet that belongs to this flow
		return true
	/* closing connection */
	case TCPStateCloseWait:
		if tcp.RST {
			if !t.validatePacket(state, revState, tcp) {
				return false
			}
			t.state = TCPStateReset
			return true
		}

		if tcp.FIN && tcp.ACK && dir == t.dir.Reverse() {
			if !t.validatePacket(state, revState, tcp) {
				return false
			}
			state.advance(tcp)
			t.state = TCPStateLastAck
			return true
		}
		if tcp.ACK {
			if !t.validatePacket(state, revState, tcp) {
				return false
			}
			state.advance(tcp)
			return true
		}
	case TCPStateLastAck:
		if tcp.RST {
			if !t.validatePacket(state, revState, tcp) {
				return false
			}
			t.state = TCPStateReset
			return true
		}

		if tcp.ACK && t.dir == dir {
			if !t.validatePacket(state, revState, tcp) {
				return false
			}
			state.advance(tcp)
			t.state = TCPStateClosed
			return true
		}
	}
	return false
}

func (s *tcpFSMState) advance(tcp *layers.TCP) {
	n := len(tcp.Payload)
	if tcp.SYN {
		n++
	}
	if tcp.FIN {
		n++
	}
	end := Sequence(tcp.Seq).Add(n)
	if !s.seqSet {
		s.nextSeq = end
		s.seqSet = true
	} else if s.nextSeq.Difference(Sequence(tcp.Seq)) >= 0 &&
		s.nextSeq.Difference(end) > 0 {
		s.nextSeq = end
	}
	s.window = uint(tcp.Window)
}
