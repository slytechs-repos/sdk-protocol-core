/*
 * Sly Technologies Free License
 * 
 * Copyright 2025 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.jnet.protocol.api;

import static com.slytechs.jnet.protocol.api.pack.ProtocolPack.*;

/**
 * Unified protocol ID constants for dissection and descriptor encoding.
 * 
 * <p>
 * Protocol IDs are 16-bit values with the high byte indicating the protocol
 * pack and the low byte indicating the protocol within that pack. These
 * constants align with {@code Tcpip.Constants}.
 * </p>
 * 
 * <h2>ID Format</h2>
 * <pre>
 * Bits 15-8: Pack ID (0x02 = TCPIP pack)
 * Bits 7-0:  Protocol index within pack
 * </pre>
 * 
 * <h2>ID Allocation</h2>
 * <pre>
 * 0x01-0x0D: Layer 2 (Ethernet, LLC, VLAN, MPLS, IPsec headers)
 * 0x0E-0x13: Layer 2.5 (ARP, etc.)
 * 0x14-0x1D: Layer 3 (IP, ICMP)
 * 0x1E-0x2F: Layer 4 (TCP, UDP, SCTP)
 * 0x30-0x4F: Tunneling protocols
 * </pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see com.slytechs.jnet.protocol.tcpip.Tcpip.Constants
 */
public final class ProtocolIds {

	private ProtocolIds() {}

	// ═══════════════════════════════════════════════════════════════════════
	// Layer 2 - Data Link (0x01-0x0D)
	// ═══════════════════════════════════════════════════════════════════════

	/** Ethernet II / IEEE 802.3 */
	public static final int PROTO_ID_ETHERNET = TCPIP_ID | 0x01;

	/** IEEE 802.2 LLC */
	public static final int PROTO_ID_LLC = TCPIP_ID | 0x02;

	/** IEEE 802.2 SNAP */
	public static final int PROTO_ID_SNAP = TCPIP_ID | 0x03;

	/** Novell Raw 802.3 */
	public static final int PROTO_ID_NOVELL_RAW = TCPIP_ID | 0x04;

	/** Cisco ISL */
	public static final int PROTO_ID_ISL = TCPIP_ID | 0x05;

	/** PPP */
	public static final int PROTO_ID_PPP = TCPIP_ID | 0x06;

	/** FDDI */
	public static final int PROTO_ID_FDDI = TCPIP_ID | 0x07;

	/** ATM */
	public static final int PROTO_ID_ATM = TCPIP_ID | 0x08;

	/** IEEE 802.1Q VLAN */
	public static final int PROTO_ID_VLAN = TCPIP_ID | 0x09;

	/** MPLS */
	public static final int PROTO_ID_MPLS = TCPIP_ID | 0x0A;

	/** IPsec Authentication Header (IP protocol 51) */
	public static final int PROTO_ID_IPSEC_AH = TCPIP_ID | 0x0B;

	/** IPsec Encapsulating Security Payload (IP protocol 50) */
	public static final int PROTO_ID_IPSEC_ESP = TCPIP_ID | 0x0C;

	/** IPsec ESP Trailer (decrypted) */
	public static final int PROTO_ID_IPSEC_ESP_TRAILER = TCPIP_ID | 0x0D;

	// Aliases for Net2PacketDescriptor compatibility
	/** Alias for PROTO_ID_IPSEC_AH */
	public static final int PROTO_ID_AH = PROTO_ID_IPSEC_AH;

	/** Alias for PROTO_ID_IPSEC_ESP */
	public static final int PROTO_ID_ESP = PROTO_ID_IPSEC_ESP;

	/** IEEE 802.3 (raw, with length field) */
	public static final int PROTO_ID_IEEE8023 = TCPIP_ID | 0x10;

	// ═══════════════════════════════════════════════════════════════════════
	// Layer 2.5 - Address Resolution (0x0E-0x13)
	// ═══════════════════════════════════════════════════════════════════════

	/** ARP - Address Resolution Protocol */
	public static final int PROTO_ID_ARP = TCPIP_ID | 0x0E;

	/** RARP - Reverse ARP */
	public static final int PROTO_ID_RARP = TCPIP_ID | 0x0F;

	// ═══════════════════════════════════════════════════════════════════════
	// Layer 3 - Network (0x14-0x1D)
	// ═══════════════════════════════════════════════════════════════════════

	/** IP (generic, for Ip interface) */
	public static final int PROTO_ID_IP = TCPIP_ID | 0x14;

	/** IPv4 */
	public static final int PROTO_ID_IPV4 = TCPIP_ID | 0x15;

	/** IPv6 */
	public static final int PROTO_ID_IPV6 = TCPIP_ID | 0x16;

	/** ICMP (v4) */
	public static final int PROTO_ID_ICMP = TCPIP_ID | 0x17;

	/** ICMPv6 */
	public static final int PROTO_ID_ICMPV6 = TCPIP_ID | 0x18;

	/** IGMP - Internet Group Management Protocol */
	public static final int PROTO_ID_IGMP = TCPIP_ID | 0x19;

	// ═══════════════════════════════════════════════════════════════════════
	// Layer 4 - Transport (0x1E-0x2F)
	// ═══════════════════════════════════════════════════════════════════════

	/** TCP */
	public static final int PROTO_ID_TCP = TCPIP_ID | 0x1E;

	/** UDP */
	public static final int PROTO_ID_UDP = TCPIP_ID | 0x1F;

	/** SCTP */
	public static final int PROTO_ID_SCTP = TCPIP_ID | 0x20;

	/** DCCP */
	public static final int PROTO_ID_DCCP = TCPIP_ID | 0x21;

	// ═══════════════════════════════════════════════════════════════════════
	// Tunneling Protocols (0x30-0x4F)
	// ═══════════════════════════════════════════════════════════════════════

	/** GRE - Generic Routing Encapsulation */
	public static final int PROTO_ID_GRE = TCPIP_ID | 0x30;

	/** VXLAN - Virtual Extensible LAN */
	public static final int PROTO_ID_VXLAN = TCPIP_ID | 0x31;

	/** IP-in-IP encapsulation */
	public static final int PROTO_ID_IP_IN_IP = TCPIP_ID | 0x32;

	/** L2TP - Layer 2 Tunneling Protocol */
	public static final int PROTO_ID_L2TP = TCPIP_ID | 0x33;

	/** NVGRE - Network Virtualization using GRE */
	public static final int PROTO_ID_NVGRE = TCPIP_ID | 0x34;

	/** GENEVE - Generic Network Virtualization Encapsulation */
	public static final int PROTO_ID_GENEVE = TCPIP_ID | 0x35;

	/** GTP - GPRS Tunneling Protocol */
	public static final int PROTO_ID_GTP = TCPIP_ID | 0x36;

	/** ERSPAN - Encapsulated Remote SPAN */
	public static final int PROTO_ID_ERSPAN = TCPIP_ID | 0x37;

	/** LISP - Locator/ID Separation Protocol */
	public static final int PROTO_ID_LISP = TCPIP_ID | 0x38;

	/** STT - Stateless Transport Tunneling */
	public static final int PROTO_ID_STT = TCPIP_ID | 0x39;

	// ═══════════════════════════════════════════════════════════════════════
	// IP Protocol Numbers (for transport detection in dissector)
	// ═══════════════════════════════════════════════════════════════════════

	/** IP Protocol: ICMP */
	public static final int IP_PROTO_ICMP = 1;

	/** IP Protocol: IGMP */
	public static final int IP_PROTO_IGMP = 2;

	/** IP Protocol: IP-in-IP */
	public static final int IP_PROTO_IPIP = 4;

	/** IP Protocol: TCP */
	public static final int IP_PROTO_TCP = 6;

	/** IP Protocol: UDP */
	public static final int IP_PROTO_UDP = 17;

	/** IP Protocol: IPv6 (encapsulated) */
	public static final int IP_PROTO_IPV6 = 41;

	/** IP Protocol: GRE */
	public static final int IP_PROTO_GRE = 47;

	/** IP Protocol: ESP */
	public static final int IP_PROTO_ESP = 50;

	/** IP Protocol: AH */
	public static final int IP_PROTO_AH = 51;

	/** IP Protocol: ICMPv6 */
	public static final int IP_PROTO_ICMPV6 = 58;

	/** IP Protocol: SCTP */
	public static final int IP_PROTO_SCTP = 132;

	/** IP Protocol: L2TP */
	public static final int IP_PROTO_L2TP = 115;

	// ═══════════════════════════════════════════════════════════════════════
	// EtherTypes (for L2 dissection)
	// ═══════════════════════════════════════════════════════════════════════

	/** EtherType: IPv4 */
	public static final int ETHER_TYPE_IPV4 = 0x0800;

	/** EtherType: ARP */
	public static final int ETHER_TYPE_ARP = 0x0806;

	/** EtherType: RARP */
	public static final int ETHER_TYPE_RARP = 0x8035;

	/** EtherType: VLAN (802.1Q) */
	public static final int ETHER_TYPE_VLAN = 0x8100;

	/** EtherType: IPv6 */
	public static final int ETHER_TYPE_IPV6 = 0x86DD;

	/** EtherType: QinQ (802.1ad) */
	public static final int ETHER_TYPE_QINQ = 0x88A8;

	/** EtherType: MPLS Unicast */
	public static final int ETHER_TYPE_MPLS = 0x8847;

	/** EtherType: MPLS Multicast */
	public static final int ETHER_TYPE_MPLS_MC = 0x8848;

	/** EtherType: Legacy QinQ */
	public static final int ETHER_TYPE_QINQ_LEGACY = 0x9100;

	/** Maximum length value for IEEE 802.3 (vs EtherType) */
	public static final int IEEE_802_3_MAX_LENGTH = 1500;

	// ═══════════════════════════════════════════════════════════════════════
	// UDP Port Numbers (for tunnel detection)
	// ═══════════════════════════════════════════════════════════════════════

	/** UDP Port: VXLAN */
	public static final int UDP_PORT_VXLAN = 4789;

	/** UDP Port: GENEVE */
	public static final int UDP_PORT_GENEVE = 6081;

	/** UDP Port: L2TP */
	public static final int UDP_PORT_L2TP = 1701;

	/** UDP Port: GTP-C */
	public static final int UDP_PORT_GTP_C = 2123;

	/** UDP Port: GTP-U */
	public static final int UDP_PORT_GTP_U = 2152;

	/** UDP Port: LISP */
	public static final int UDP_PORT_LISP = 4341;

	/** UDP Port: STT */
	public static final int UDP_PORT_STT = 7471;
}