// Copyright 2024 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package reassembly

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestFSMRejectsMismatchedAckWithoutAdvancing(t *testing.T) {
	fsm := NewTCPSimpleFSM(TCPSimpleFSMOptions{})
	syn := &layers.TCP{SYN: true, Seq: 100}
	synAck := &layers.TCP{SYN: true, ACK: true, Seq: 200, Ack: 101}
	ack := &layers.TCP{ACK: true, Seq: 101, Ack: 201}
	if !fsm.CheckState(syn, TCPDirClientToServer) {
		t.Fatal("SYN did not start the FSM")
	}
	if !fsm.CheckState(synAck, TCPDirServerToClient) {
		t.Fatal("SYN+ACK did not complete server side")
	}
	if !fsm.CheckState(ack, TCPDirClientToServer) {
		t.Fatal("handshake ACK was rejected")
	}

	bad := &layers.TCP{ACK: true, Seq: 9999, Ack: 9999}
	if fsm.CheckState(bad, TCPDirClientToServer) {
		t.Fatal("established FSM accepted an out-of-window packet")
	}
	if got := fsm.String(); got != "Established" {
		t.Fatalf("rejected packet changed FSM state to %s", got)
	}
	if !fsm.CheckState(ack, TCPDirClientToServer) {
		t.Fatal("valid packet after rejection was not accepted")
	}
}

func TestFSMRejectsHandshakeAckFromWrongSequence(t *testing.T) {
	fsm := NewTCPSimpleFSM(TCPSimpleFSMOptions{})
	if !fsm.CheckState(&layers.TCP{SYN: true, Seq: 100}, TCPDirClientToServer) {
		t.Fatal("SYN did not start the FSM")
	}
	if fsm.CheckState(&layers.TCP{SYN: true, ACK: true, Seq: 200, Ack: 999}, TCPDirServerToClient) {
		t.Fatal("SYN+ACK with a mismatched ACK was accepted")
	}
	if got := fsm.String(); got != "SynSent" {
		t.Fatalf("rejected SYN+ACK changed FSM state to %s", got)
	}
	if !fsm.CheckState(&layers.TCP{SYN: true, ACK: true, Seq: 200, Ack: 101}, TCPDirServerToClient) {
		t.Fatal("valid SYN+ACK after rejection was not accepted")
	}
}

func TestOptionCheckRejectsMismatchedAckWithoutAdvancing(t *testing.T) {
	opt := NewTCPOptionCheck()
	ci := gopacket.CaptureInfo{}
	start := false
	if err := opt.Accept(&layers.TCP{SYN: true, Seq: 100}, ci, TCPDirClientToServer, invalidSequence, &start); err != nil {
		t.Fatalf("SYN rejected: %v", err)
	}
	if err := opt.Accept(&layers.TCP{SYN: true, ACK: true, Seq: 200, Ack: 101}, ci, TCPDirServerToClient, invalidSequence, &start); err != nil {
		t.Fatalf("SYN+ACK rejected: %v", err)
	}
	if err := opt.Accept(&layers.TCP{ACK: true, Seq: 101, Ack: 201}, ci, TCPDirClientToServer, invalidSequence, &start); err != nil {
		t.Fatalf("handshake ACK rejected: %v", err)
	}
	if err := opt.Accept(&layers.TCP{ACK: true, Seq: 9999, Ack: 9999}, ci, TCPDirClientToServer, invalidSequence, &start); err == nil {
		t.Fatal("out-of-window ACK was accepted")
	}
	if err := opt.Accept(&layers.TCP{ACK: true, Seq: 101, Ack: 201}, ci, TCPDirClientToServer, invalidSequence, &start); err != nil {
		t.Fatalf("valid packet after rejection was rejected: %v", err)
	}
}

func TestOptionCheckRejectsWindowScaleChange(t *testing.T) {
	opt := NewTCPOptionCheck()
	ci := gopacket.CaptureInfo{}
	start := false
	scale2 := []layers.TCPOption{{OptionType: 3, OptionLength: 3, OptionData: []byte{2}}}
	scale5 := []layers.TCPOption{{OptionType: 3, OptionLength: 3, OptionData: []byte{5}}}

	if err := opt.Accept(&layers.TCP{SYN: true, Seq: 100, Options: scale2}, ci, TCPDirClientToServer, invalidSequence, &start); err != nil {
		t.Fatalf("SYN rejected: %v", err)
	}
	if err := opt.Accept(&layers.TCP{SYN: true, ACK: true, Seq: 200, Ack: 101, Options: scale2}, ci, TCPDirServerToClient, invalidSequence, &start); err != nil {
		t.Fatalf("SYN+ACK rejected: %v", err)
	}
	if err := opt.Accept(&layers.TCP{SYN: true, Seq: 100, Options: scale5}, ci, TCPDirClientToServer, invalidSequence, &start); err == nil {
		t.Fatal("window scale change on retransmitted SYN was accepted")
	}
	if err := opt.Accept(&layers.TCP{SYN: true, ACK: true, Seq: 200, Ack: 101, Options: scale5}, ci, TCPDirServerToClient, invalidSequence, &start); err == nil {
		t.Fatal("window scale change on retransmitted SYN+ACK was accepted")
	}
	if err := opt.Accept(&layers.TCP{ACK: true, Seq: 101, Ack: 201}, ci, TCPDirClientToServer, invalidSequence, &start); err != nil {
		t.Fatalf("valid packet after rejected scale changes was rejected: %v", err)
	}
}

func TestOptionCheckFailureDoesNotPolluteNewConnection(t *testing.T) {
	opt := NewTCPOptionCheck()
	ci := gopacket.CaptureInfo{}
	start := false
	badMSS := []layers.TCPOption{{OptionType: 2, OptionLength: 2, OptionData: []byte{1}}}
	if err := opt.Accept(&layers.TCP{SYN: true, Seq: 100, Options: badMSS}, ci, TCPDirClientToServer, invalidSequence, &start); err == nil {
		t.Fatal("malformed MSS option was accepted")
	}
	if err := opt.Accept(&layers.TCP{SYN: true, Seq: 500}, ci, TCPDirClientToServer, invalidSequence, &start); err != nil {
		t.Fatalf("valid SYN after failed option parse was rejected: %v", err)
	}
	if err := opt.Accept(&layers.TCP{SYN: true, ACK: true, Seq: 900, Ack: 501}, ci, TCPDirServerToClient, invalidSequence, &start); err != nil {
		t.Fatalf("valid SYN+ACK after retry was rejected: %v", err)
	}
}
