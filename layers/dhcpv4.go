// Copyright 2016 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
)

// DHCPOp rerprents a bootp operation
type DHCPOp byte

// bootp operations
const (
	DHCPOpRequest DHCPOp = 1
	DHCPOpReply   DHCPOp = 2
)

// String returns a string version of a DHCPOp.
func (o DHCPOp) String() string {
	switch o {
	case DHCPOpRequest:
		return "Request"
	case DHCPOpReply:
		return "Reply"
	default:
		return "Unknown"
	}
}

// DHCPMsgType represents a DHCP operation
type DHCPMsgType byte

// Constants that represent DHCP operations
const (
	DHCPMsgTypeUnspecified DHCPMsgType = iota
	DHCPMsgTypeDiscover
	DHCPMsgTypeOffer
	DHCPMsgTypeRequest
	DHCPMsgTypeDecline
	DHCPMsgTypeAck
	DHCPMsgTypeNak
	DHCPMsgTypeRelease
	DHCPMsgTypeInform
)

// String returns a string version of a DHCPMsgType.
func (o DHCPMsgType) String() string {
	switch o {
	case DHCPMsgTypeUnspecified:
		return "Unspecified"
	case DHCPMsgTypeDiscover:
		return "Discover"
	case DHCPMsgTypeOffer:
		return "Offer"
	case DHCPMsgTypeRequest:
		return "Request"
	case DHCPMsgTypeDecline:
		return "Decline"
	case DHCPMsgTypeAck:
		return "Ack"
	case DHCPMsgTypeNak:
		return "Nak"
	case DHCPMsgTypeRelease:
		return "Release"
	case DHCPMsgTypeInform:
		return "Inform"
	default:
		return "Unknown"
	}
}

// DHCPMagic is the RFC 2131 "magic cooke" for DHCP.
var DHCPMagic uint32 = 0x63825363

// DHCPv4 contains data for a single DHCP packet.
type DHCPv4 struct {
	BaseLayer
	Operation    DHCPOp
	HardwareType LinkType
	HardwareLen  uint8
	HardwareOpts uint8
	Xid          uint32
	Secs         uint16
	Flags        uint16
	ClientIP     net.IP
	YourClientIP net.IP
	NextServerIP net.IP
	RelayAgentIP net.IP
	ClientHWAddr net.HardwareAddr
	ServerName   []byte
	File         []byte
	Options      DHCPOptions
}

// DHCPOptions is used to get nicely printed option lists which would normally
// be cut off after 5 options.
type DHCPOptions []DHCPOption

// String returns a string version of the options list.
func (o DHCPOptions) String() string {
	buf := &bytes.Buffer{}
	buf.WriteByte('[')
	for i, opt := range o {
		buf.WriteString(opt.String())
		if i+1 != len(o) {
			buf.WriteString(", ")
		}
	}
	buf.WriteByte(']')
	return buf.String()
}

// LayerType returns gopacket.LayerTypeDHCPv4
func (d *DHCPv4) LayerType() gopacket.LayerType { return LayerTypeDHCPv4 }

// DecodeFromBytes decodes the given bytes into this layer.
func (d *DHCPv4) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 240 {
		df.SetTruncated()
		return fmt.Errorf("DHCPv4 length %d too short", len(data))
	}

	// Decode into a candidate layer and only publish it once the complete
	// option chain has been validated.  A failed decode must not leave a
	// partially populated layer behind (or mutate a layer that is still
	// referenced by a previously built Packet).
	candidate := DHCPv4{
		Operation:    DHCPOp(data[0]),
		HardwareType: LinkType(data[1]),
		HardwareLen:  data[2],
		HardwareOpts: data[3],
		Xid:          binary.BigEndian.Uint32(data[4:8]),
		Secs:         binary.BigEndian.Uint16(data[8:10]),
		Flags:        binary.BigEndian.Uint16(data[10:12]),
		ClientIP:     net.IP(data[12:16]),
		YourClientIP: net.IP(data[16:20]),
		NextServerIP: net.IP(data[20:24]),
		RelayAgentIP: net.IP(data[24:28]),
		ServerName:   data[44:108],
		File:         data[108:236],
	}

	hardwareLen := int(candidate.HardwareLen)
	if hardwareLen > 16 {
		return fmt.Errorf("DHCPv4 hardware address length %d is invalid", hardwareLen)
	}
	if 28+hardwareLen > len(data) {
		df.SetTruncated()
		return fmt.Errorf("DHCPv4 length %d too short for hardware address length %d", len(data), hardwareLen)
	}
	candidate.ClientHWAddr = net.HardwareAddr(data[28 : 28+hardwareLen])

	if binary.BigEndian.Uint32(data[236:240]) != DHCPMagic {
		return InvalidMagicCookie
	}

	if len(data) <= 240 {
		// DHCP Packet could have no option (??)
		candidate.Contents = data
		*d = candidate
		return nil
	}

	options := data[240:]
	candidate.Options = make(DHCPOptions, 0, dhcpMinInt(len(options)/2, maxDHCPv4Options))
	seenSingleton := make(map[DHCPOpt]struct{})

	stop := len(options)
	start := 0
	for start < stop {
		o := DHCPOption{}
		if err := o.decode(options[start:]); err != nil {
			df.SetTruncated()
			return err
		}
		if o.Type == DHCPOptEnd {
			break
		}
		// Check if the option is a single byte pad
		if o.Type == DHCPOptPad {
			if len(candidate.Options) >= maxDHCPv4Options {
				return DecOptionBudgetExceeded
			}
			candidate.Options = append(candidate.Options, o)
			start++
		} else {
			if o.Length == 0 && !dhcpv4OptionAllowsEmptyValue(o.Type) {
				return DecOptionZeroLength
			}
			if dhcpv4OptionIsSingleton(o.Type) {
				if _, ok := seenSingleton[o.Type]; ok {
					return DecOptionDuplicate
				}
				seenSingleton[o.Type] = struct{}{}
			}
			if len(candidate.Options) >= maxDHCPv4Options {
				return DecOptionBudgetExceeded
			}
			candidate.Options = append(candidate.Options, o)
			start += int(o.Length) + 2
		}
	}

	candidate.Contents = data
	*d = candidate

	return nil
}

// Len returns the length of a DHCPv4 packet.
func (d *DHCPv4) Len() uint16 {
	n := uint16(240)
	for _, o := range d.Options {
		if o.Type == DHCPOptPad {
			n++
		} else {
			n += uint16(o.Length) + 2
		}
	}
	n++ // for opt end
	return n
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (d *DHCPv4) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	plen := int(d.Len())

	data, err := b.PrependBytes(plen)
	if err != nil {
		return err
	}

	data[0] = byte(d.Operation)
	data[1] = byte(d.HardwareType)
	if opts.FixLengths {
		d.HardwareLen = uint8(len(d.ClientHWAddr))
	}
	data[2] = d.HardwareLen
	data[3] = d.HardwareOpts
	binary.BigEndian.PutUint32(data[4:8], d.Xid)
	binary.BigEndian.PutUint16(data[8:10], d.Secs)
	binary.BigEndian.PutUint16(data[10:12], d.Flags)
	copy(data[12:16], d.ClientIP.To4())
	copy(data[16:20], d.YourClientIP.To4())
	copy(data[20:24], d.NextServerIP.To4())
	copy(data[24:28], d.RelayAgentIP.To4())
	copy(data[28:44], d.ClientHWAddr)
	copy(data[44:108], d.ServerName)
	copy(data[108:236], d.File)
	binary.BigEndian.PutUint32(data[236:240], DHCPMagic)

	if len(d.Options) > 0 {
		offset := 240
		for _, o := range d.Options {
			if err := o.encode(data[offset:]); err != nil {
				return err
			}
			// A pad option is only a single byte
			if o.Type == DHCPOptPad {
				offset++
			} else {
				offset += 2 + len(o.Data)
			}
		}
		optend := NewDHCPOption(DHCPOptEnd, nil)
		if err := optend.encode(data[offset:]); err != nil {
			return err
		}
	}
	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (d *DHCPv4) CanDecode() gopacket.LayerClass {
	return LayerTypeDHCPv4
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (d *DHCPv4) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeDHCPv4(data []byte, p gopacket.PacketBuilder) error {
	dhcp := &DHCPv4{}
	err := dhcp.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(dhcp)
	return p.NextDecoder(gopacket.LayerTypePayload)
}

// DHCPOpt represents a DHCP option or parameter from RFC-2132
type DHCPOpt byte

// Constants for the DHCPOpt options.
const (
	DHCPOptPad                   DHCPOpt = 0
	DHCPOptSubnetMask            DHCPOpt = 1   // 4, net.IP
	DHCPOptTimeOffset            DHCPOpt = 2   // 4, int32 (signed seconds from UTC)
	DHCPOptRouter                DHCPOpt = 3   // n*4, [n]net.IP
	DHCPOptTimeServer            DHCPOpt = 4   // n*4, [n]net.IP
	DHCPOptNameServer            DHCPOpt = 5   // n*4, [n]net.IP
	DHCPOptDNS                   DHCPOpt = 6   // n*4, [n]net.IP
	DHCPOptLogServer             DHCPOpt = 7   // n*4, [n]net.IP
	DHCPOptCookieServer          DHCPOpt = 8   // n*4, [n]net.IP
	DHCPOptLPRServer             DHCPOpt = 9   // n*4, [n]net.IP
	DHCPOptImpressServer         DHCPOpt = 10  // n*4, [n]net.IP
	DHCPOptResLocServer          DHCPOpt = 11  // n*4, [n]net.IP
	DHCPOptHostname              DHCPOpt = 12  // n, string
	DHCPOptBootfileSize          DHCPOpt = 13  // 2, uint16
	DHCPOptMeritDumpFile         DHCPOpt = 14  // >1, string
	DHCPOptDomainName            DHCPOpt = 15  // n, string
	DHCPOptSwapServer            DHCPOpt = 16  // n*4, [n]net.IP
	DHCPOptRootPath              DHCPOpt = 17  // n, string
	DHCPOptExtensionsPath        DHCPOpt = 18  // n, string
	DHCPOptIPForwarding          DHCPOpt = 19  // 1, bool
	DHCPOptSourceRouting         DHCPOpt = 20  // 1, bool
	DHCPOptPolicyFilter          DHCPOpt = 21  // 8*n, [n]{net.IP/net.IP}
	DHCPOptDatagramMTU           DHCPOpt = 22  // 2, uint16
	DHCPOptDefaultTTL            DHCPOpt = 23  // 1, byte
	DHCPOptPathMTUAgingTimeout   DHCPOpt = 24  // 4, uint32
	DHCPOptPathPlateuTableOption DHCPOpt = 25  // 2*n, []uint16
	DHCPOptInterfaceMTU          DHCPOpt = 26  // 2, uint16
	DHCPOptAllSubsLocal          DHCPOpt = 27  // 1, bool
	DHCPOptBroadcastAddr         DHCPOpt = 28  // 4, net.IP
	DHCPOptMaskDiscovery         DHCPOpt = 29  // 1, bool
	DHCPOptMaskSupplier          DHCPOpt = 30  // 1, bool
	DHCPOptRouterDiscovery       DHCPOpt = 31  // 1, bool
	DHCPOptSolicitAddr           DHCPOpt = 32  // 4, net.IP
	DHCPOptStaticRoute           DHCPOpt = 33  // n*8, [n]{net.IP/net.IP} -- note the 2nd is router not mask
	DHCPOptARPTrailers           DHCPOpt = 34  // 1, bool
	DHCPOptARPTimeout            DHCPOpt = 35  // 4, uint32
	DHCPOptEthernetEncap         DHCPOpt = 36  // 1, bool
	DHCPOptTCPTTL                DHCPOpt = 37  // 1, byte
	DHCPOptTCPKeepAliveInt       DHCPOpt = 38  // 4, uint32
	DHCPOptTCPKeepAliveGarbage   DHCPOpt = 39  // 1, bool
	DHCPOptNISDomain             DHCPOpt = 40  // n, string
	DHCPOptNISServers            DHCPOpt = 41  // 4*n,  [n]net.IP
	DHCPOptNTPServers            DHCPOpt = 42  // 4*n, [n]net.IP
	DHCPOptVendorOption          DHCPOpt = 43  // n, [n]byte // may be encapsulated.
	DHCPOptNetBIOSTCPNS          DHCPOpt = 44  // 4*n, [n]net.IP
	DHCPOptNetBIOSTCPDDS         DHCPOpt = 45  // 4*n, [n]net.IP
	DHCPOptNETBIOSTCPNodeType    DHCPOpt = 46  // 1, magic byte
	DHCPOptNetBIOSTCPScope       DHCPOpt = 47  // n, string
	DHCPOptXFontServer           DHCPOpt = 48  // n, string
	DHCPOptXDisplayManager       DHCPOpt = 49  // n, string
	DHCPOptRequestIP             DHCPOpt = 50  // 4, net.IP
	DHCPOptLeaseTime             DHCPOpt = 51  // 4, uint32
	DHCPOptExtOptions            DHCPOpt = 52  // 1, 1/2/3
	DHCPOptMessageType           DHCPOpt = 53  // 1, 1-7
	DHCPOptServerID              DHCPOpt = 54  // 4, net.IP
	DHCPOptParamsRequest         DHCPOpt = 55  // n, []byte
	DHCPOptMessage               DHCPOpt = 56  // n, 3
	DHCPOptMaxMessageSize        DHCPOpt = 57  // 2, uint16
	DHCPOptT1                    DHCPOpt = 58  // 4, uint32
	DHCPOptT2                    DHCPOpt = 59  // 4, uint32
	DHCPOptClassID               DHCPOpt = 60  // n, []byte
	DHCPOptClientID              DHCPOpt = 61  // n >=  2, []byte
	DHCPOptRapidCommit           DHCPOpt = 80  // 0
	DHCPOptDomainSearch          DHCPOpt = 119 // n, string
	DHCPOptSIPServers            DHCPOpt = 120 // n, url
	DHCPOptClasslessStaticRoute  DHCPOpt = 121 //
	DHCPOptMUDURLV4              DHCPOpt = 161 // n, string
	DHCPOptEnd                   DHCPOpt = 255
)

// String returns a string version of a DHCPOpt.
func (o DHCPOpt) String() string {
	switch o {
	case DHCPOptPad:
		return "(padding)"
	case DHCPOptSubnetMask:
		return "SubnetMask"
	case DHCPOptTimeOffset:
		return "TimeOffset"
	case DHCPOptRouter:
		return "Router"
	case DHCPOptTimeServer:
		return "rfc868" // old time server protocol stringified to dissuade confusion w. NTP
	case DHCPOptNameServer:
		return "ien116" // obscure nameserver protocol stringified to dissuade confusion w. DNS
	case DHCPOptDNS:
		return "DNS"
	case DHCPOptLogServer:
		return "mitLCS" // MIT LCS server protocol yada yada w. Syslog
	case DHCPOptCookieServer:
		return "CookieServer"
	case DHCPOptLPRServer:
		return "LPRServer"
	case DHCPOptImpressServer:
		return "ImpressServer"
	case DHCPOptResLocServer:
		return "ResourceLocationServer"
	case DHCPOptHostname:
		return "Hostname"
	case DHCPOptBootfileSize:
		return "BootfileSize"
	case DHCPOptMeritDumpFile:
		return "MeritDumpFile"
	case DHCPOptDomainName:
		return "DomainName"
	case DHCPOptSwapServer:
		return "SwapServer"
	case DHCPOptRootPath:
		return "RootPath"
	case DHCPOptExtensionsPath:
		return "ExtensionsPath"
	case DHCPOptIPForwarding:
		return "IPForwarding"
	case DHCPOptSourceRouting:
		return "SourceRouting"
	case DHCPOptPolicyFilter:
		return "PolicyFilter"
	case DHCPOptDatagramMTU:
		return "DatagramMTU"
	case DHCPOptDefaultTTL:
		return "DefaultTTL"
	case DHCPOptPathMTUAgingTimeout:
		return "PathMTUAgingTimeout"
	case DHCPOptPathPlateuTableOption:
		return "PathPlateuTableOption"
	case DHCPOptInterfaceMTU:
		return "InterfaceMTU"
	case DHCPOptAllSubsLocal:
		return "AllSubsLocal"
	case DHCPOptBroadcastAddr:
		return "BroadcastAddress"
	case DHCPOptMaskDiscovery:
		return "MaskDiscovery"
	case DHCPOptMaskSupplier:
		return "MaskSupplier"
	case DHCPOptRouterDiscovery:
		return "RouterDiscovery"
	case DHCPOptSolicitAddr:
		return "SolicitAddr"
	case DHCPOptStaticRoute:
		return "StaticRoute"
	case DHCPOptARPTrailers:
		return "ARPTrailers"
	case DHCPOptARPTimeout:
		return "ARPTimeout"
	case DHCPOptEthernetEncap:
		return "EthernetEncap"
	case DHCPOptTCPTTL:
		return "TCPTTL"
	case DHCPOptTCPKeepAliveInt:
		return "TCPKeepAliveInt"
	case DHCPOptTCPKeepAliveGarbage:
		return "TCPKeepAliveGarbage"
	case DHCPOptNISDomain:
		return "NISDomain"
	case DHCPOptNISServers:
		return "NISServers"
	case DHCPOptNTPServers:
		return "NTPServers"
	case DHCPOptVendorOption:
		return "VendorOption"
	case DHCPOptNetBIOSTCPNS:
		return "NetBIOSOverTCPNS"
	case DHCPOptNetBIOSTCPDDS:
		return "NetBiosOverTCPDDS"
	case DHCPOptNETBIOSTCPNodeType:
		return "NetBIOSOverTCPNodeType"
	case DHCPOptNetBIOSTCPScope:
		return "NetBIOSOverTCPScope"
	case DHCPOptXFontServer:
		return "XFontServer"
	case DHCPOptXDisplayManager:
		return "XDisplayManager"
	case DHCPOptEnd:
		return "(end)"
	case DHCPOptSIPServers:
		return "SipServers"
	case DHCPOptRequestIP:
		return "RequestIP"
	case DHCPOptLeaseTime:
		return "LeaseTime"
	case DHCPOptExtOptions:
		return "ExtOpts"
	case DHCPOptMessageType:
		return "MessageType"
	case DHCPOptServerID:
		return "ServerID"
	case DHCPOptParamsRequest:
		return "ParamsRequest"
	case DHCPOptMessage:
		return "Message"
	case DHCPOptMaxMessageSize:
		return "MaxDHCPSize"
	case DHCPOptT1:
		return "Timer1"
	case DHCPOptT2:
		return "Timer2"
	case DHCPOptClassID:
		return "ClassID"
	case DHCPOptClientID:
		return "ClientID"
	case DHCPOptRapidCommit:
		return "RapidCommit"
	case DHCPOptDomainSearch:
		return "DomainSearch"
	case DHCPOptClasslessStaticRoute:
		return "ClasslessStaticRoute"
	case DHCPOptMUDURLV4:
		return "ManufacturerUsageDescriptionURL"
	default:
		return "Unknown"
	}
}

// DHCPOption rerpresents a DHCP option.
type DHCPOption struct {
	Type   DHCPOpt
	Length uint8
	Data   []byte
}

// String returns a string version of a DHCP Option.
func (o DHCPOption) String() string {
	switch o.Type {

	case DHCPOptHostname, DHCPOptMeritDumpFile, DHCPOptDomainName, DHCPOptRootPath,
		DHCPOptExtensionsPath, DHCPOptNISDomain, DHCPOptNetBIOSTCPScope, DHCPOptXFontServer,
		DHCPOptXDisplayManager, DHCPOptMessage, DHCPOptDomainSearch: // string
		return fmt.Sprintf("Option(%s:%s)", o.Type, string(o.Data))

	case DHCPOptMessageType:
		if len(o.Data) != 1 {
			return fmt.Sprintf("Option(%s:INVALID)", o.Type)
		}
		return fmt.Sprintf("Option(%s:%s)", o.Type, DHCPMsgType(o.Data[0]))

	case DHCPOptSubnetMask, DHCPOptServerID, DHCPOptBroadcastAddr,
		DHCPOptSolicitAddr, DHCPOptRequestIP: // net.IP
		if len(o.Data) < 4 {
			return fmt.Sprintf("Option(%s:INVALID)", o.Type)
		}
		return fmt.Sprintf("Option(%s:%s)", o.Type, net.IP(o.Data))

	case DHCPOptT1, DHCPOptT2, DHCPOptLeaseTime, DHCPOptPathMTUAgingTimeout,
		DHCPOptARPTimeout, DHCPOptTCPKeepAliveInt: // uint32
		if len(o.Data) != 4 {
			return fmt.Sprintf("Option(%s:INVALID)", o.Type)
		}
		return fmt.Sprintf("Option(%s:%d)", o.Type,
			uint32(o.Data[0])<<24|uint32(o.Data[1])<<16|uint32(o.Data[2])<<8|uint32(o.Data[3]))

	case DHCPOptParamsRequest:
		buf := &bytes.Buffer{}
		buf.WriteString(fmt.Sprintf("Option(%s:", o.Type))
		for i, v := range o.Data {
			buf.WriteString(DHCPOpt(v).String())
			if i+1 != len(o.Data) {
				buf.WriteByte(',')
			}
		}
		buf.WriteString(")")
		return buf.String()

	default:
		return fmt.Sprintf("Option(%s:%v)", o.Type, o.Data)
	}
}

// NewDHCPOption constructs a new DHCPOption with a given type and data.
func NewDHCPOption(t DHCPOpt, data []byte) DHCPOption {
	if len(data) == 0 {
		// A zero-length value is only complete for options that are defined
		// as carrying no data.  Do not manufacture a seemingly valid
		// zero-length option for anything else.
		if dhcpv4OptionAllowsEmptyValue(t) {
			return DHCPOption{Type: t}
		}
		return DHCPOption{}
	}
	return DHCPOption{Type: t, Length: uint8(len(data)), Data: data}
}

func (o *DHCPOption) encode(b []byte) error {
	switch o.Type {
	case DHCPOptPad, DHCPOptEnd:
		b[0] = byte(o.Type)
	default:
		b[0] = byte(o.Type)
		b[1] = o.Length
		copy(b[2:], o.Data)
	}
	return nil
}

func (o *DHCPOption) decode(data []byte) error {
	if len(data) < 1 {
		// Pad/End have a length of 1
		return DecOptionNotEnoughData
	}
	o.Type = DHCPOpt(data[0])
	switch o.Type {
	case DHCPOptPad, DHCPOptEnd:
		o.Data = nil
	default:
		if len(data) < 2 {
			return DecOptionNotEnoughData
		}
		o.Length = data[1]
		if int(o.Length) > len(data[2:]) {
			return DecOptionMalformed
		}
		o.Data = data[2 : 2+int(o.Length)]
	}
	return nil
}

// DHCPv4Error is used for constant errors for DHCPv4. It is needed for test asserts.
type DHCPv4Error string

// DHCPv4Error implements error interface.
func (d DHCPv4Error) Error() string {
	return string(d)
}

const (
	// DecOptionNotEnoughData is returned when there is not enough data during option's decode process
	DecOptionNotEnoughData = DHCPv4Error("Not enough data to decode")
	// DecOptionMalformed is returned when the option is malformed
	DecOptionMalformed = DHCPv4Error("Option is malformed")
	// InvalidMagicCookie is returned when Magic cookie is missing into BOOTP header
	InvalidMagicCookie = DHCPv4Error("Bad DHCP header")
	// DecOptionZeroLength is returned when a data-carrying option has no data.
	DecOptionZeroLength = DHCPv4Error("DHCP option has zero length")
	// DecOptionDuplicate is returned when a singleton option appears more than once.
	DecOptionDuplicate = DHCPv4Error("duplicate singleton DHCP option")
	// DecOptionBudgetExceeded is returned when an option chain exceeds its budget.
	DecOptionBudgetExceeded = DHCPv4Error("DHCP option budget exceeded")
)

// maxDHCPv4Options bounds the number of options materialized for a single
// DHCPv4 layer.  Common Discover/Offer/Request exchanges use only a handful
// of options; this limit leaves ample room for legitimate extensions while
// preventing a short-option flood from producing an unbounded layer.
const maxDHCPv4Options = 64

func dhcpMinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// dhcpv4OptionAllowsEmptyValue reports whether an option is defined to carry
// no value.  Pad and End are encoded as a single byte, while Rapid Commit is
// a zero-length TLV.
func dhcpv4OptionAllowsEmptyValue(t DHCPOpt) bool {
	switch t {
	case DHCPOptPad, DHCPOptEnd, DHCPOptRapidCommit:
		return true
	default:
		return false
	}
}

// dhcpv4OptionIsSingleton reports whether multiple instances of an option
// have no unambiguous meaning for consumers.
func dhcpv4OptionIsSingleton(t DHCPOpt) bool {
	switch t {
	case DHCPOptSubnetMask, DHCPOptRouter, DHCPOptDNS, DHCPOptHostname,
		DHCPOptDomainName, DHCPOptBroadcastAddr, DHCPOptRequestIP,
		DHCPOptLeaseTime, DHCPOptExtOptions, DHCPOptMessageType,
		DHCPOptServerID, DHCPOptParamsRequest, DHCPOptMaxMessageSize,
		DHCPOptT1, DHCPOptT2, DHCPOptClientID, DHCPOptRapidCommit,
		DHCPOptDomainSearch, DHCPOptClasslessStaticRoute:
		return true
	default:
		return false
	}
}
