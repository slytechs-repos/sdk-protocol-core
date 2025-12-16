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

import static com.slytechs.jnet.protocol.api.pack.PackId.Constants.*;

/**
 * Protocol identifiers for the jnetworks-sdk.
 * 
 * <p>
 * This enum defines all protocol, option, and extension identifiers used throughout
 * the jnetworks-sdk. Protocol IDs are organized hierarchically into packs (protocol
 * families) and support both in-header options and external extensions.
 * </p>
 * 
 * <h2>ID Structure (24-bit)</h2>
 * The protocol ID structure uses 24 bits with the following layout:
 * <pre>
 * [flags-2bits][option-extension-id-6bits][pack-id-8bits][protocol-id-8bits]
 * 
 * Bit positions:
 *   23-22: Flags (option/extension indicators)
 *   21-16: Option/Extension ordinal (0-63)
 *   15-8:  Pack ID (protocol family)
 *   7-0:   Protocol ordinal within pack
 * </pre>
 * 
 * <h3>ID Types:</h3>
 * <ul>
 *   <li><b>Standard Protocol:</b> [00][000000][pack-8][proto-8]<br>
 *       Regular protocol headers (e.g., Ethernet, IPv4, TCP)</li>
 *   <li><b>Option:</b> [10][ordinal-6][pack-8][parent-proto-8]<br>
 *       In-header options with OPTION_FLAG (bit 23) set<br>
 *       Examples: TCP MSS, IPv4 timestamp options</li>
 *   <li><b>Extension:</b> [01][ordinal-6][pack-8][parent-proto-8]<br>
 *       External extensions with EXTENSION_FLAG (bit 22) set<br>
 *       Examples: VLAN tags, IPv6 extension headers</li>
 * </ul>
 * 
 * <h2>Protocol Packs</h2>
 * Protocols are organized into the following packs:
 * <ul>
 *   <li><b>BUILTIN (0x00xx):</b> Core system protocols (payload, unknown, padding)</li>
 *   <li><b>TCPIP (0x02xx):</b> TCP/IP protocol suite (Ethernet, IP, TCP, UDP, etc.)</li>
 *   <li><b>WEB (0x03xx):</b> Application layer web protocols</li>
 * </ul>
 * 
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Check if a protocol is an option
 * if (ProtoId.isOption(protocolId)) {
 *     int optionOrdinal = ProtoId.optionId(protocolId);
 *     // Process option...
 * }
 * 
 * // Get protocol enum from numeric ID
 * ProtoId proto = ProtoId.valueOf(0x0230);  // Returns PROTO_ID_TCP
 * 
 * // Extract pack and protocol components
 * int packId = proto.packId();     // Returns 0x0200 (TCPIP pack)
 * int protoOrdinal = proto.protoId();  // Returns 0x30
 * }</pre>
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public enum ProtoId {

	// ============ BUILTIN PACK ============
	PROTO_ID_PAYLOAD(Constants.PROTO_ID_PAYLOAD),
	PROTO_ID_UNKNOWN(Constants.PROTO_ID_UNKNOWN),
	PROTO_ID_PAD(Constants.PROTO_ID_PAD),

	// ============ TCP/IP PACK - Layer 2 ============
	PROTO_ID_ETHERNET(Constants.PROTO_ID_ETHERNET),
	PROTO_ID_PPP(Constants.PROTO_ID_PPP),
	PROTO_ID_ARP(Constants.PROTO_ID_ARP),
	PROTO_ID_RARP(Constants.PROTO_ID_RARP),
	PROTO_ID_PPPoE(Constants.PROTO_ID_PPPoE),
	PROTO_ID_LLDP(Constants.PROTO_ID_LLDP),
	PROTO_ID_LOOPBACK(Constants.PROTO_ID_LOOPBACK),

	// ============ TCP/IP PACK - Layer 3 ============
	PROTO_ID_IPV4(Constants.PROTO_ID_IPV4),
	PROTO_ID_IPV6(Constants.PROTO_ID_IPV6),
	PROTO_ID_ICMP(Constants.PROTO_ID_ICMP),
	PROTO_ID_ICMPv6(Constants.PROTO_ID_ICMPv6),
	PROTO_ID_IGMP(Constants.PROTO_ID_IGMP),
	PROTO_ID_OSPF(Constants.PROTO_ID_OSPF),
	PROTO_ID_EIGRP(Constants.PROTO_ID_EIGRP),
	PROTO_ID_RIP(Constants.PROTO_ID_RIP),
	PROTO_ID_PIM(Constants.PROTO_ID_PIM),
	PROTO_ID_VRRP(Constants.PROTO_ID_VRRP),

	// ============ TCP/IP PACK - Layer 4 ============
	PROTO_ID_TCP(Constants.PROTO_ID_TCP),
	PROTO_ID_UDP(Constants.PROTO_ID_UDP),
	PROTO_ID_SCTP(Constants.PROTO_ID_SCTP),
	PROTO_ID_DCCP(Constants.PROTO_ID_DCCP),
	PROTO_ID_UDP_LITE(Constants.PROTO_ID_UDP_LITE),

	// ============ TCP/IP PACK - Tunneling ============
	PROTO_ID_GRE(Constants.PROTO_ID_GRE),
	PROTO_ID_IP_IN_IP(Constants.PROTO_ID_IP_IN_IP),
	PROTO_ID_IPV6_IN_IP(Constants.PROTO_ID_IPV6_IN_IP),
	PROTO_ID_L2TP(Constants.PROTO_ID_L2TP),
	PROTO_ID_VXLAN(Constants.PROTO_ID_VXLAN),
	PROTO_ID_NVGRE(Constants.PROTO_ID_NVGRE),
	PROTO_ID_GENEVE(Constants.PROTO_ID_GENEVE),
	PROTO_ID_GTP(Constants.PROTO_ID_GTP),
	PROTO_ID_TEREDO(Constants.PROTO_ID_TEREDO),

	// ============ TCP/IP PACK - Security ============
	PROTO_ID_ESP(Constants.PROTO_ID_ESP),
	PROTO_ID_AH(Constants.PROTO_ID_AH),
	PROTO_ID_IPSEC(Constants.PROTO_ID_IPSEC),

	// ============ ETHERNET EXTENSIONS (External to header) ============
	PROTO_ID_VLAN(Constants.PROTO_ID_VLAN),
	PROTO_ID_QINQ(Constants.PROTO_ID_QINQ),
	PROTO_ID_MPLS(Constants.PROTO_ID_MPLS),
	PROTO_ID_LLC(Constants.PROTO_ID_LLC),
	PROTO_ID_SNAP(Constants.PROTO_ID_SNAP),
	PROTO_ID_STP(Constants.PROTO_ID_STP),

	// ============ IPv4 OPTIONS (In-header) ============
	PROTO_ID_IPV4_OPT_NOP(Constants.PROTO_ID_IPV4_OPT_NOP),
	PROTO_ID_IPV4_OPT_SECURITY(Constants.PROTO_ID_IPV4_OPT_SECURITY),
	PROTO_ID_IPV4_OPT_LSRR(Constants.PROTO_ID_IPV4_OPT_LSRR),
	PROTO_ID_IPV4_OPT_TIMESTAMP(Constants.PROTO_ID_IPV4_OPT_TIMESTAMP),
	PROTO_ID_IPV4_OPT_RR(Constants.PROTO_ID_IPV4_OPT_RR),
	PROTO_ID_IPV4_OPT_SSRR(Constants.PROTO_ID_IPV4_OPT_SSRR),

	// ============ IPv6 EXTENSIONS (External headers) ============
	PROTO_ID_IPV6_HOPOPT(Constants.PROTO_ID_IPV6_HOPOPT),
	PROTO_ID_IPV6_ROUTING(Constants.PROTO_ID_IPV6_ROUTING),
	PROTO_ID_IPV6_FRAG(Constants.PROTO_ID_IPV6_FRAG),
	PROTO_ID_IPV6_DSTOPT(Constants.PROTO_ID_IPV6_DSTOPT),
	PROTO_ID_IPV6_AUTH(Constants.PROTO_ID_IPV6_AUTH),
	PROTO_ID_IPV6_ESP(Constants.PROTO_ID_IPV6_ESP),
	PROTO_ID_IPV6_MOBILITY(Constants.PROTO_ID_IPV6_MOBILITY),

	// ============ TCP OPTIONS (In-header) ============
	PROTO_ID_TCP_OPT_MSS(Constants.PROTO_ID_TCP_OPT_MSS),
	PROTO_ID_TCP_OPT_WSCALE(Constants.PROTO_ID_TCP_OPT_WSCALE),
	PROTO_ID_TCP_OPT_SACK_PERM(Constants.PROTO_ID_TCP_OPT_SACK_PERM),
	PROTO_ID_TCP_OPT_SACK(Constants.PROTO_ID_TCP_OPT_SACK),
	PROTO_ID_TCP_OPT_TIMESTAMP(Constants.PROTO_ID_TCP_OPT_TIMESTAMP),
	PROTO_ID_TCP_OPT_NOP(Constants.PROTO_ID_TCP_OPT_NOP),
	PROTO_ID_TCP_OPT_EOL(Constants.PROTO_ID_TCP_OPT_EOL),

	;

	public interface Constants {

		// ============ PACK_ID_BUILTIN (0x00xx) ============
		int PROTO_ID_PAYLOAD = 0x0000 | PACK_ID_BUILTIN; // Generic payload/data
		int PROTO_ID_UNKNOWN = 0x0001 | PACK_ID_BUILTIN; // Unknown protocol
		int PROTO_ID_PAD = 0x0002 | PACK_ID_BUILTIN; // Padding

		// ============ PACK_ID_TCPIP (0x02xx) - Main protocols ============

		// Layer 2 - Data Link (0x0200 - 0x020F)
		int PROTO_ID_ETHERNET = 0x0200; // Ethernet II (DIX)
		int PROTO_ID_PPP = 0x0202; // Point-to-Point Protocol
		int PROTO_ID_ARP = 0x0203; // Address Resolution Protocol
		int PROTO_ID_RARP = 0x0204; // Reverse ARP
		int PROTO_ID_PPPoE = 0x0205; // PPP over Ethernet
		int PROTO_ID_LLDP = 0x0206; // Link Layer Discovery Protocol
		int PROTO_ID_LOOPBACK = 0x0207; // Loopback interface
		
		

		// Layer 3 - Network (0x0210 - 0x022F)
		int PROTO_ID_IPV4 = 0x0210; // Internet Protocol v4
		int PROTO_ID_IPV6 = 0x0211; // Internet Protocol v6
		int PROTO_ID_ICMP = 0x0212; // ICMP (for IPv4)
		int PROTO_ID_ICMPv6 = 0x0213; // ICMPv6 (for IPv6)
		int PROTO_ID_IGMP = 0x0214; // Internet Group Management Protocol
		int PROTO_ID_OSPF = 0x0215; // Open Shortest Path First
		int PROTO_ID_EIGRP = 0x0216; // Enhanced Interior Gateway Routing
		int PROTO_ID_RIP = 0x0218; // Routing Information Protocol
		int PROTO_ID_PIM = 0x0219; // Protocol Independent Multicast
		int PROTO_ID_VRRP = 0x021A; // Virtual Router Redundancy Protocol

		// Layer 4 - Transport (0x0230 - 0x023F)
		int PROTO_ID_TCP = 0x0230; // Transmission Control Protocol
		int PROTO_ID_UDP = 0x0231; // User Datagram Protocol
		int PROTO_ID_SCTP = 0x0232; // Stream Control Transmission Protocol
		int PROTO_ID_DCCP = 0x0233; // Datagram Congestion Control Protocol
		int PROTO_ID_UDP_LITE = 0x0234; // Lightweight UDP

		// Tunneling Protocols (0x0240 - 0x024F)
		int PROTO_ID_GRE = 0x0240; // Generic Routing Encapsulation
		int PROTO_ID_IP_IN_IP = 0x0241; // IP in IP (Protocol 4)
		int PROTO_ID_IPV6_IN_IP = 0x0242; // IPv6 in IPv4 (Protocol 41)
		int PROTO_ID_L2TP = 0x0243; // Layer 2 Tunneling Protocol
		int PROTO_ID_VXLAN = 0x0244; // Virtual Extensible LAN
		int PROTO_ID_NVGRE = 0x0245; // Network Virtualization using GRE
		int PROTO_ID_GENEVE = 0x0246; // Generic Network Virtualization Encapsulation
		int PROTO_ID_GTP = 0x0247; // GPRS Tunneling Protocol
		int PROTO_ID_TEREDO = 0x0248; // Teredo tunneling

		// Security Protocols (0x0250 - 0x025F)
		int PROTO_ID_ESP = 0x0250; // Encapsulating Security Payload
		int PROTO_ID_AH = 0x0251; // Authentication Header
		int PROTO_ID_IPSEC = 0x0252; // IPsec (generic)
		
		// Add to ProtoId.Constants:

		// Special L2 capture formats
		int PROTO_ID_SLL           = 0x0208;  // Linux cooked capture
		int PROTO_ID_SLL2          = 0x0209;  // Linux cooked capture v2
		int PROTO_ID_RADIOTAP      = 0x020A;  // Radiotap wireless header
		int PROTO_ID_AVS           = 0x020B;  // AVS wireless header
		int PROTO_ID_IEEE80211     = 0x020C;  // 802.11 wireless
		int PROTO_ID_CHDLC         = 0x020D;  // Cisco HDLC
		int PROTO_ID_FRELAY        = 0x020E;  // Frame Relay
		int PROTO_ID_IPOIB         = 0x020F;  // IP over InfiniBand

		// Virtual/Special interfaces
		int PROTO_ID_NETLINK       = 0x0260;  // Linux Netlink
		int PROTO_ID_USB           = 0x0261;  // USB capture
		int PROTO_ID_NFLOG         = 0x0262;  // Netfilter log
		int PROTO_ID_VSOCK         = 0x0263;  // VM sockets
		int PROTO_ID_DPDK          = 0x0264;  // DPDK
		int PROTO_ID_CAN           = 0x0265;  // CAN bus
		int PROTO_ID_BLUETOOTH     = 0x0266;  // Bluetooth HCI
		int PROTO_ID_BLUETOOTH_LE  = 0x0267;  // Bluetooth LE
		int PROTO_ID_DOCSIS        = 0x0268;  // DOCSIS

		// ============ ETHERNET EXTENSIONS (external to header) ============
		// Structure: EXTENSION_FLAG | (ordinal << 16) | PARENT_ID
		int PROTO_ID_VLAN = PACK_FLAG_PROTO_EXTENSION | (0x00 << PACK_BITSHIFT_EXTENSION_ID) | PROTO_ID_ETHERNET; // 802.1Q
																													// VLAN
		int PROTO_ID_QINQ = PACK_FLAG_PROTO_EXTENSION | (0x01 << PACK_BITSHIFT_EXTENSION_ID) | PROTO_ID_ETHERNET; // 802.1Q-in-Q
		int PROTO_ID_MPLS = PACK_FLAG_PROTO_EXTENSION | (0x02 << PACK_BITSHIFT_EXTENSION_ID) | PROTO_ID_ETHERNET; // MPLS
		int PROTO_ID_LLC = PACK_FLAG_PROTO_EXTENSION | (0x03 << PACK_BITSHIFT_EXTENSION_ID) | PROTO_ID_ETHERNET; // 802.2
																													// LLC
		int PROTO_ID_SNAP = PACK_FLAG_PROTO_EXTENSION | (0x04 << PACK_BITSHIFT_EXTENSION_ID) | PROTO_ID_ETHERNET; // 802.2
																													// SNAP
		int PROTO_ID_STP = PACK_FLAG_PROTO_EXTENSION | (0x05 << PACK_BITSHIFT_EXTENSION_ID) | PROTO_ID_ETHERNET; // Spanning
																													// Tree

		// ============ IPv4 OPTIONS (in-header) ============
		// Structure: OPTION_FLAG | (ordinal << 16) | PARENT_ID
		int PROTO_ID_IPV4_OPT_NOP = PACK_FLAG_PROTO_OPTION | (0x00 << PACK_BITSHIFT_OPTION_ID) | PROTO_ID_IPV4; // No
																												// Operation
		int PROTO_ID_IPV4_OPT_SECURITY = PACK_FLAG_PROTO_OPTION | (0x01 << PACK_BITSHIFT_OPTION_ID) | PROTO_ID_IPV4; // Security
		int PROTO_ID_IPV4_OPT_LSRR = PACK_FLAG_PROTO_OPTION | (0x02 << PACK_BITSHIFT_OPTION_ID) | PROTO_ID_IPV4; // Loose
																													// Source
																													// Route
		int PROTO_ID_IPV4_OPT_TIMESTAMP = PACK_FLAG_PROTO_OPTION | (0x03 << PACK_BITSHIFT_OPTION_ID) | PROTO_ID_IPV4; // Timestamp
		int PROTO_ID_IPV4_OPT_RR = PACK_FLAG_PROTO_OPTION | (0x04 << PACK_BITSHIFT_OPTION_ID) | PROTO_ID_IPV4; // Record
																												// Route
		int PROTO_ID_IPV4_OPT_SSRR = PACK_FLAG_PROTO_OPTION | (0x05 << PACK_BITSHIFT_OPTION_ID) | PROTO_ID_IPV4; // Strict
																													// Source
																													// Route

		// ============ IPv6 EXTENSIONS (external headers) ============
		// Structure: EXTENSION_FLAG | (ordinal << 16) | PARENT_ID
		int PROTO_ID_IPV6_HOPOPT = PACK_FLAG_PROTO_EXTENSION | (0x00 << PACK_BITSHIFT_EXTENSION_ID) | PROTO_ID_IPV6; // Hop-by-Hop
		int PROTO_ID_IPV6_ROUTING = PACK_FLAG_PROTO_EXTENSION | (0x01 << PACK_BITSHIFT_EXTENSION_ID) | PROTO_ID_IPV6; // Routing
		int PROTO_ID_IPV6_FRAG = PACK_FLAG_PROTO_EXTENSION | (0x02 << PACK_BITSHIFT_EXTENSION_ID) | PROTO_ID_IPV6; // Fragment
		int PROTO_ID_IPV6_DSTOPT = PACK_FLAG_PROTO_EXTENSION | (0x03 << PACK_BITSHIFT_EXTENSION_ID) | PROTO_ID_IPV6; // Destination
																														// Options
		int PROTO_ID_IPV6_AUTH = PACK_FLAG_PROTO_EXTENSION | (0x04 << PACK_BITSHIFT_EXTENSION_ID) | PROTO_ID_IPV6; // Authentication
		int PROTO_ID_IPV6_ESP = PACK_FLAG_PROTO_EXTENSION | (0x05 << PACK_BITSHIFT_EXTENSION_ID) | PROTO_ID_IPV6; // ESP
		int PROTO_ID_IPV6_MOBILITY = PACK_FLAG_PROTO_EXTENSION | (0x06 << PACK_BITSHIFT_EXTENSION_ID) | PROTO_ID_IPV6; // Mobility

		// ============ TCP OPTIONS (in-header) ============
		// Structure: OPTION_FLAG | (ordinal << 16) | PARENT_ID
		int PROTO_ID_TCP_OPT_EOL = PACK_FLAG_PROTO_OPTION | (0x00 << PACK_BITSHIFT_OPTION_ID) | PROTO_ID_TCP; // End of
																												// Options
		int PROTO_ID_TCP_OPT_NOP = PACK_FLAG_PROTO_OPTION | (0x01 << PACK_BITSHIFT_OPTION_ID) | PROTO_ID_TCP; // No
																												// Operation
		int PROTO_ID_TCP_OPT_MSS = PACK_FLAG_PROTO_OPTION | (0x02 << PACK_BITSHIFT_OPTION_ID) | PROTO_ID_TCP; // Maximum
																												// Segment
																												// Size
		int PROTO_ID_TCP_OPT_WSCALE = PACK_FLAG_PROTO_OPTION | (0x03 << PACK_BITSHIFT_OPTION_ID) | PROTO_ID_TCP; // Window
																													// Scale
		int PROTO_ID_TCP_OPT_SACK_PERM = PACK_FLAG_PROTO_OPTION | (0x04 << PACK_BITSHIFT_OPTION_ID) | PROTO_ID_TCP; // SACK
																													// Permitted
		int PROTO_ID_TCP_OPT_SACK = PACK_FLAG_PROTO_OPTION | (0x05 << PACK_BITSHIFT_OPTION_ID) | PROTO_ID_TCP; // SACK
		int PROTO_ID_TCP_OPT_TIMESTAMP = PACK_FLAG_PROTO_OPTION | (0x08 << PACK_BITSHIFT_OPTION_ID) | PROTO_ID_TCP; // Timestamps
	}

	/**
	 * Extracts the extension ordinal from the specified protocol ID.
	 * 
	 * The extension ordinal identifies the specific extension type within the
	 * parent protocol's extension space. This value occupies bits 21-16 and is only
	 * meaningful for IDs where {@link #isExtension(int)} returns true.
	 * 
	 * @param id the protocol ID from which to extract the extension ordinal
	 * @return the extension ordinal (0-63) if this is an extension, or 0 if not an
	 *         extension
	 */
	public static int extensionId(int id) {
		return (id & PACK_MASK_EXTENSION_ID) >> PACK_BITSHIFT_EXTENSION_ID;
	}

	/**
	 * Checks if the specified protocol ID represents an external extension.
	 * 
	 * Extensions are additional headers or protocol layers that follow their parent
	 * protocol (e.g., VLAN tags after Ethernet, IPv6 extension headers after IPv6
	 * base header).
	 * 
	 * @param id the protocol ID to check
	 * @return true if the ID represents an external extension, false otherwise
	 */
	public static boolean isExtension(int id) {
		return (id & PACK_FLAG_PROTO_EXTENSION) != 0;
	}

	/**
	 * Checks if the specified protocol ID represents an in-header option.
	 * 
	 * Options are protocol-specific fields that appear within the header of their
	 * parent protocol (e.g., TCP options within the TCP header, IPv4 options within
	 * the IPv4 header).
	 * 
	 * @param id the protocol ID to check
	 * @return true if the ID represents an in-header option, false otherwise
	 */
	public static boolean isOption(int id) {
		return (id & PACK_FLAG_PROTO_OPTION) != 0;
	}

	/**
	 * Extracts the option ordinal from the specified protocol ID.
	 * 
	 * The option ordinal identifies the specific option type within the parent
	 * protocol's option space. This value occupies bits 21-16 and is only
	 * meaningful for IDs where {@link #isOption(int)} returns true.
	 * 
	 * @param id the protocol ID from which to extract the option ordinal
	 * @return the option ordinal (0-63) if this is an option, or 0 if not an option
	 */
	public static int optionId(int id) {
		return (id & PACK_MASK_OPTION_ID) >> PACK_BITSHIFT_OPTION_ID;
	}

	/**
	 * Extracts the pack ID from the specified protocol ID.
	 * 
	 * The pack ID identifies the protocol family or group (e.g., BUILTIN, TCPIP,
	 * WEB). Pack IDs occupy bits 15-8 of the protocol ID.
	 * 
	 * @param id the protocol ID from which to extract the pack ID
	 * @return the pack ID (bits 15-8) of the specified protocol
	 */
	public static int packId(int id) {
		return id & PACK_MASK_PACK_ID;
	}

	/**
	 * Extracts the protocol ordinal from the specified protocol ID.
	 * 
	 * The protocol ordinal is the base protocol identifier within its pack,
	 * occupying bits 7-0. For options and extensions, this returns the parent
	 * protocol's ordinal.
	 * 
	 * @param id the protocol ID from which to extract the protocol ordinal
	 * @return the protocol ordinal (bits 7-0) of the specified protocol
	 */
	public static int protoId(int id) {
		return id & PACK_MASK_PROTO_ID;
	}

	/**
	 * Returns the ProtoId enum constant for the specified protocol ID value.
	 * 
	 * This method performs a linear search through all defined protocol IDs to find
	 * a match. If no matching protocol is found, returns {@link #PROTO_ID_UNKNOWN}.
	 * 
	 * @param id the numeric protocol ID to look up
	 * @return the corresponding ProtoId enum constant, or PROTO_ID_UNKNOWN if not
	 *         found
	 */
	public static ProtoId valueOf(int id) {
		for (ProtoId proto : values()) {
			if (proto.id == id) {
				return proto;
			}
		}
		return PROTO_ID_UNKNOWN;
	}

	private final int id;

	ProtoId(int id) {
		this.id = id;
	}

	/**
	 * Extracts the extension ordinal from this protocol ID.
	 * 
	 * The extension ordinal identifies the specific extension type within the
	 * parent protocol's extension space. This value occupies bits 21-16 and is only
	 * meaningful for IDs where {@link #isExtension()} returns true.
	 * 
	 * @return the extension ordinal (0-63) if this is an extension, or 0 if not an
	 *         extension
	 */
	public int extensionId() {
		return (id & PACK_MASK_EXTENSION_ID) >> PACK_BITSHIFT_EXTENSION_ID;
	}

	public int id() {
		return id;
	}

	/**
	 * Checks if this protocol ID represents an external extension.
	 * 
	 * Extensions are additional headers or protocol layers that follow their parent
	 * protocol (e.g., VLAN tags after Ethernet, IPv6 extension headers after IPv6
	 * base header).
	 * 
	 * @return true if this ID represents an external extension, false otherwise
	 */
	public boolean isExtension() {
		return (id & PACK_FLAG_PROTO_EXTENSION) != 0;
	}

	/**
	 * Checks if this protocol ID represents an in-header option.
	 * 
	 * Options are protocol-specific fields that appear within the header of their
	 * parent protocol (e.g., TCP options within the TCP header, IPv4 options within
	 * the IPv4 header).
	 * 
	 * @return true if this ID represents an in-header option, false otherwise
	 */
	public boolean isOption() {
		return (id & PACK_FLAG_PROTO_OPTION) != 0;
	}

	/**
	 * Extracts the option ordinal from this protocol ID.
	 * 
	 * The option ordinal identifies the specific option type within the parent
	 * protocol's option space. This value occupies bits 21-16 and is only
	 * meaningful for IDs where {@link #isOption()} returns true.
	 * 
	 * @return the option ordinal (0-63) if this is an option, or 0 if not an option
	 */
	public int optionId() {
		return (id & PACK_MASK_OPTION_ID) >> PACK_BITSHIFT_OPTION_ID;
	}

	/**
	 * Extracts the pack ID from this protocol ID.
	 * 
	 * The pack ID identifies the protocol family or group (e.g., BUILTIN, TCPIP,
	 * WEB). Pack IDs occupy bits 15-8 of the protocol ID.
	 * 
	 * @return the pack ID (bits 15-8) of this protocol
	 */
	public int packId() {
		return id & PACK_MASK_PACK_ID;
	}

	/**
	 * Extracts the protocol ordinal from this protocol ID.
	 * 
	 * The protocol ordinal is the base protocol identifier within its pack,
	 * occupying bits 7-0. For options and extensions, this returns the parent
	 * protocol's ordinal.
	 * 
	 * @return the protocol ordinal (bits 7-0) of this protocol
	 */
	public int protoId() {
		return id & PACK_MASK_PROTO_ID;
	}
}