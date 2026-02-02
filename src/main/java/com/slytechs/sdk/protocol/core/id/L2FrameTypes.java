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
package com.slytechs.sdk.protocol.core.id;

/**
 * L2 frame type constants for descriptor encoding.
 * 
 * <p>
 * These values identify the link-layer frame type and are stored in the
 * descriptor's rx_flags field. They determine which root protocol processor
 * handles dissection and provide quick frame-type identification without
 * parsing.
 * </p>
 * 
 * <h2>Usage</h2>
 * 
 * <pre>{@code
 * int l2Type = descriptor.l2FrameType();
 * if (l2Type == L2FrameTypes.ETHER) {
 * 	// Ethernet frame
 * }
 * 
 * // Get metadata
 * L2FrameType info = L2FrameType.of(l2Type);
 * int baseLen = info.baseLength();
 * }</pre>
 * 
 * <h2>Value Ranges</h2>
 * <ul>
 * <li>0x00-0x0F: Common (Ethernet, PPP, SLL, Loopback)</li>
 * <li>0x10-0x1F: Wireless (802.11, Radiotap)</li>
 * <li>0x20-0x2F: Linux-specific (Netlink, CAN, USB)</li>
 * <li>0x30-0x3F: Legacy (FDDI, ATM, Token Ring)</li>
 * <li>0x40-0x4F: Specialty (Bluetooth, InfiniBand)</li>
 * <li>0x50-0x5F: BSD-specific (pflog, pfsync)</li>
 * <li>0x60-0x6F: IoT/Embedded (ZigBee, DECT)</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see L2FrameType
 */
public sealed interface L2FrameTypes permits L2FrameType {

	// @formatter:off

    // ════════════════════════════════════════════════════════════════════════════
    // Common Frame Types (0x00-0x0F)
    // ════════════════════════════════════════════════════════════════════════════

    /** Unknown or unspecified frame type. */
    int UNKNOWN      = 0x00;

    /** Ethernet II (DIX) or IEEE 802.3. */
    int ETHER        = 0x01;

    /** Point-to-Point Protocol. */
    int PPP          = 0x02;

    /** Linux cooked capture v1 (SLL). */
    int SLL          = 0x03;

    /** Linux cooked capture v2 (SLL2). */
    int SLL2         = 0x04;

    /** BSD loopback/null encapsulation. */
    int LOOPBACK     = 0x05;

    /** Raw IPv4 (no L2 header). */
    int RAW_IP4      = 0x06;

    /** Raw IPv6 (no L2 header). */
    int RAW_IP6      = 0x07;

    /** PPP with HDLC framing. */
    int PPP_HDLC     = 0x08;

    /** Cisco HDLC. */
    int CHDLC        = 0x09;

    /** PPP over Ethernet. */
    int PPPOE        = 0x0A;

    // Reserved: 0x0B-0x0F

    // ════════════════════════════════════════════════════════════════════════════
    // Wireless Frame Types (0x10-0x1F)
    // ════════════════════════════════════════════════════════════════════════════

    /** IEEE 802.11 wireless (native). */
    int IEEE80211           = 0x10;

    /** IEEE 802.11 with Radiotap header. */
    int IEEE80211_RADIOTAP  = 0x11;

    /** IEEE 802.11 with AVS header. */
    int IEEE80211_AVS       = 0x12;

    /** IEEE 802.11 with Prism header. */
    int IEEE80211_PRISM     = 0x13;

    /** IEEE 802.11 with PPI header. */
    int IEEE80211_PPI       = 0x14;

    // Reserved: 0x15-0x1F

    // ════════════════════════════════════════════════════════════════════════════
    // Linux-Specific Frame Types (0x20-0x2F)
    // ════════════════════════════════════════════════════════════════════════════

    /** Linux Netlink messages. */
    int NETLINK      = 0x20;

    /** Linux Netfilter log (NFLOG). */
    int NFLOG        = 0x21;

    /** Linux Netfilter queue. */
    int NFQUEUE      = 0x22;

    /** Linux SocketCAN. */
    int LINUX_CAN    = 0x23;

    /** Linux USB capture. */
    int LINUX_USB    = 0x24;

    /** Linux USB capture (64-bit/mmapped). */
    int LINUX_USB_MM = 0x25;

    /** Linux VM Sockets. */
    int VSOCK        = 0x26;

    /** Linux LAPD (ISDN D-channel). */
    int LAPD         = 0x27;

    // Reserved: 0x28-0x2F

    // ════════════════════════════════════════════════════════════════════════════
    // Legacy Frame Types (0x30-0x3F)
    // ════════════════════════════════════════════════════════════════════════════

    /** FDDI. */
    int FDDI         = 0x30;

    /** Token Ring. */
    int TOKEN_RING   = 0x31;

    /** ARCNET. */
    int ARCNET       = 0x32;

    /** ATM. */
    int ATM          = 0x33;

    /** Frame Relay. */
    int FRELAY       = 0x34;

    /** SLIP. */
    int SLIP         = 0x35;

    /** Chaosnet. */
    int CHAOS        = 0x36;

    // Reserved: 0x37-0x3F

    // ════════════════════════════════════════════════════════════════════════════
    // Specialty Frame Types (0x40-0x4F)
    // ════════════════════════════════════════════════════════════════════════════

    /** Bluetooth HCI H4. */
    int BLUETOOTH_HCI    = 0x40;

    /** Bluetooth Low Energy Link Layer. */
    int BLUETOOTH_LE     = 0x41;

    /** BlueZ monitor. */
    int BLUETOOTH_MON    = 0x42;

    /** IP over InfiniBand. */
    int IPOIB            = 0x43;

    /** DOCSIS. */
    int DOCSIS           = 0x44;

    /** DPDK capture. */
    int DPDK             = 0x45;

    // Reserved: 0x46-0x4F

    // ════════════════════════════════════════════════════════════════════════════
    // BSD-Specific Frame Types (0x50-0x5F)
    // ════════════════════════════════════════════════════════════════════════════

    /** OpenBSD pflog. */
    int PFLOG        = 0x50;

    /** OpenBSD pfsync. */
    int PFSYNC       = 0x51;

    /** OpenBSD enc. */
    int ENC          = 0x52;

    // Reserved: 0x53-0x5F

    // ════════════════════════════════════════════════════════════════════════════
    // IoT/Embedded Frame Types (0x60-0x6F)
    // ════════════════════════════════════════════════════════════════════════════

    /** IEEE 802.15.4 (ZigBee PHY). */
    int IEEE802_15_4     = 0x60;

    /** IEEE 802.15.4 with TAP header. */
    int IEEE802_15_4_TAP = 0x61;

    /** Amateur radio AX.25. */
    int AX25             = 0x62;

    /** DECT. */
    int DECT             = 0x63;

    // Reserved: 0x64-0x6F

    // @formatter:on

	// ════════════════════════════════════════════════════════════════════════════
	// Helper Methods
	// ════════════════════════════════════════════════════════════════════════════

	/**
	 * Checks if the frame type is Ethernet-based.
	 *
	 * @param type the L2 frame type value
	 * @return true if Ethernet II or 802.3
	 */
	static boolean isEthernet(int type) {
		return type == ETHER;
	}

	/**
	 * Checks if the frame type has no L2 header (raw IP).
	 *
	 * @param type the L2 frame type value
	 * @return true if raw IP
	 */
	static boolean isRawIp(int type) {
		return type == RAW_IP4 || type == RAW_IP6;
	}

	/**
	 * Checks if the frame type is wireless (802.11).
	 *
	 * @param type the L2 frame type value
	 * @return true if any 802.11 variant
	 */
	static boolean isWireless(int type) {
		return type >= IEEE80211 && type <= IEEE80211_PPI;
	}

	/**
	 * Returns the name for an L2 frame type constant.
	 *
	 * @param l2Type the L2 frame type value
	 * @return human-readable name
	 */
	static String nameOf(int l2Type) {
		return switch (l2Type) {
		case UNKNOWN -> "UNKNOWN";
		case ETHER -> "ETHER";
		case PPP -> "PPP";
		case SLL -> "SLL";
		case SLL2 -> "SLL2";
		case LOOPBACK -> "LOOPBACK";
		case RAW_IP4 -> "RAW_IP4";
		case RAW_IP6 -> "RAW_IP6";
		case PPP_HDLC -> "PPP_HDLC";
		case CHDLC -> "CHDLC";
		case PPPOE -> "PPPOE";
		case IEEE80211 -> "IEEE80211";
		case IEEE80211_RADIOTAP -> "IEEE80211_RADIOTAP";
		case IEEE80211_AVS -> "IEEE80211_AVS";
		case IEEE80211_PRISM -> "IEEE80211_PRISM";
		case IEEE80211_PPI -> "IEEE80211_PPI";
		case NETLINK -> "NETLINK";
		case NFLOG -> "NFLOG";
		case NFQUEUE -> "NFQUEUE";
		case LINUX_CAN -> "LINUX_CAN";
		case LINUX_USB -> "LINUX_USB";
		case LINUX_USB_MM -> "LINUX_USB_MM";
		case VSOCK -> "VSOCK";
		case LAPD -> "LAPD";
		case FDDI -> "FDDI";
		case TOKEN_RING -> "TOKEN_RING";
		case ARCNET -> "ARCNET";
		case ATM -> "ATM";
		case FRELAY -> "FRELAY";
		case SLIP -> "SLIP";
		case CHAOS -> "CHAOS";
		case BLUETOOTH_HCI -> "BLUETOOTH_HCI";
		case BLUETOOTH_LE -> "BLUETOOTH_LE";
		case BLUETOOTH_MON -> "BLUETOOTH_MON";
		case IPOIB -> "IPOIB";
		case DOCSIS -> "DOCSIS";
		case DPDK -> "DPDK";
		case PFLOG -> "PFLOG";
		case PFSYNC -> "PFSYNC";
		case ENC -> "ENC";
		case IEEE802_15_4 -> "IEEE802_15_4";
		case IEEE802_15_4_TAP -> "IEEE802_15_4_TAP";
		case AX25 -> "AX25";
		case DECT -> "DECT";
		default -> "UNKNOWN(0x" + Integer.toHexString(l2Type) + ")";
		};
	}

}