/*
 * Copyright 2005-2026 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.protocol.core.id;

/**
 * Ethernet Type field constants (wire format).
 *
 * <p>
 * Contains the actual 16-bit values found in the EtherType field of Ethernet II
 * frames. Values greater than 1500 (0x05DC) are EtherTypes; values less than or
 * equal to 1500 indicate IEEE 802.3 frame lengths.
 * </p>
 *
 * <p>
 * This is a sealed constants-only interface. For type-safe usage, see the
 * {@link EtherType} enum which provides dynamic lookup and instance methods.
 * For internal protocol identification, see {@link ProtocolIds}.
 * </p>
 *
 * <h2>Usage</h2>
 *
 * {@snippet :
 * import static com.slytechs.sdk.protocol.core.EtherTypes.*;
 *
 * int etherType = buffer.getShortBE() & 0xFFFF;
 * if (etherType == IPv4) {
 *     // Parse IPv4
 * } else if (etherType == VLAN) {
 *     // Parse VLAN tag
 * }
 * }
 *
 * <p>
 * The EtherType constants are defined in the protocol-core module as these L2
 * constants are referenced throughout all of the protocol modules. Additional
 * definitions can be found in the protocol-tcpip module, including tables in
 * resource files obtained from public information published by IANA.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see EtherType
 * @see <a href=
 *      "https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml">
 *      IANA IEEE 802 Numbers</a>
 */
public sealed interface EtherTypes permits EtherType {

	// @formatter:off
   // ════════════════════════════════════════════════════════════════════════
    // IEEE 802.3 Length Boundary
    // ════════════════════════════════════════════════════════════════════════

    /** Maximum value for IEEE 802.3 length field (values > 1500 are EtherTypes) */
    int MAX_802_3_LENGTH = 1500;

    // ════════════════════════════════════════════════════════════════════════
    // Common EtherTypes
    // ════════════════════════════════════════════════════════════════════════

    int UNKNOWN   = 0x0000;  // UNKNOWN ETHER TYPE
    int IPv4      = 0x0800;  // Internet Protocol version 4
    int ARP       = 0x0806;  // Address Resolution Protocol
    int WOL       = 0x0842;  // Wake-on-LAN
    int RARP      = 0x8035;  // Reverse ARP
    int VLAN      = 0x8100;  // IEEE 802.1Q VLAN tag
    int IPX       = 0x8137;  // Internetwork Packet Exchange
    int IPv6      = 0x86DD;  // Internet Protocol version 6
    int FLOW_CTRL = 0x8808;  // Ethernet flow control
    int SLOW      = 0x8809;  // Slow protocols (LACP, etc.)
    int MPLS      = 0x8847;  // MPLS unicast
    int MPLS_MC   = 0x8848;  // MPLS multicast
    int PPPoE_D   = 0x8863;  // PPPoE Discovery
    int PPPoE_S   = 0x8864;  // PPPoE SystemSession
    int JUMBO     = 0x8870;  // Jumbo frames
    int QINQ      = 0x88A8;  // IEEE 802.1ad Q-in-Q
    int LLDP      = 0x88CC;  // Link Layer Discovery Protocol
    int MACSEC    = 0x88E5;  // IEEE 802.1AE MAC Security
    int PTP       = 0x88F7;  // Precision Time Protocol
    int CFM       = 0x8902;  // IEEE 802.1ag Connectivity Fault Management
    int FCoE      = 0x8906;  // Fibre Channel over Ethernet
    int FIP       = 0x8914;  // FCoE Initialization Protocol
    int LOOPBACK  = 0x9000;  // Loopback
    int HSR       = 0x892F;  // High-availability Seamless Redundancy

    // ════════════════════════════════════════════════════════════════════════
    // VLAN Variants
    // ════════════════════════════════════════════════════════════════════════

    int VLAN_9100 = 0x9100;  // QinQ (legacy)
    int VLAN_9200 = 0x9200;  // QinQ (legacy)
    int VLAN_9300 = 0x9300;  // QinQ (legacy)

    // ════════════════════════════════════════════════════════════════════════
    // Experimental / Private
    // ════════════════════════════════════════════════════════════════════════

    int EXPERIMENTAL_1 = 0x88B5;  // IEEE 802 experimental
    int EXPERIMENTAL_2 = 0x88B6;  // IEEE 802 experimental
    int PRIVATE_1      = 0x88B7;  // Private experiments
	// @formatter:on

	// ════════════════════════════════════════════════════════════════════════
	// Helper Methods
	// ════════════════════════════════════════════════════════════════════════

	/**
	 * Checks if the value is a valid EtherTypes (vs 802.3 length).
	 * 
	 * @param value the 16-bit value from the EtherTypes/Length field
	 * @return true if this is an EtherTypes, false if it's an 802.3 length
	 */
	static boolean isEtherType(int value) {
		return (value & 0xFFFF) > MAX_802_3_LENGTH;
	}

	/**
	 * Checks if the value is an 802.3 length field.
	 * 
	 * @param value the 16-bit value from the EtherTypes/Length field
	 * @return true if this is an 802.3 length, false if it's an EtherTypes
	 */
	static boolean is802_3Length(int value) {
		return (value & 0xFFFF) <= MAX_802_3_LENGTH;
	}

	/**
	 * Checks if the EtherTypes represents a VLAN tag (any variant).
	 * 
	 * @param etherType the EtherTypes value
	 * @return true if this is a VLAN tag
	 */
	static boolean isVlan(int etherType) {
		return switch (etherType & 0xFFFF) {
		case VLAN, QINQ, VLAN_9100, VLAN_9200, VLAN_9300 -> true;
		default -> false;
		};
	}

	/**
	 * Gets the name of an EtherTypes for debugging.
	 * 
	 * @param etherType the EtherTypes value
	 * @return human-readable name
	 */
	static String nameOf(int etherType) {
		EtherType type = EtherType.valueOf(etherType);

		return switch (type) {
		case UNKNOWN -> String.format("0x%04X", etherType & 0xFFFF);

		default -> type.name();
		};
	}
}