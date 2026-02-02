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

import com.slytechs.sdk.common.util.IntId;

/**
 * L2 frame type metadata: base header lengths and protocol ID mappings.
 * 
 * <p>
 * This enum provides the metadata needed to process frames of each L2 type,
 * including the base header length and the corresponding {@link ProtocolIds} for
 * the root protocol.
 * </p>
 * 
 * <h2>Usage</h2>
 * 
 * <pre>{@code
 * int l2Type = descriptor.l2FrameType();
 * L2FrameType info = L2FrameType.of(l2Type);
 * 
 * int headerLen = info.baseLength();
 * int protoId = info.protocolId();
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see L2FrameTypes
 * @see ProtocolIds
 */
public enum L2FrameType implements L2FrameTypes, IntId {

	// @formatter:off

    // ════════════════════════════════════════════════════════════════════════════
    // Common Frame Types
    // ════════════════════════════════════════════════════════════════════════════

    /** Unknown/unspecified - no L2 processing. */
    UNKNOWN         (L2FrameTypes.UNKNOWN,           0, ProtocolIds.PAYLOAD),

    /** Ethernet II (DIX) or IEEE 802.3. */
    ETHER           (L2FrameTypes.ETHER,            14, ProtocolIds.ETHERNET),

    /** Point-to-Point Protocol. */
    PPP             (L2FrameTypes.PPP,               4, ProtocolIds.PPP),

    /** Linux cooked capture v1 (now in CAPTURE pack). */
    SLL             (L2FrameTypes.SLL,              16, ProtocolIds.SLL),

    /** Linux cooked capture v2 (now in CAPTURE pack). */
    SLL2            (L2FrameTypes.SLL2,             20, ProtocolIds.SLL2),

    /** BSD loopback/null encapsulation (now in CAPTURE pack). */
    LOOPBACK        (L2FrameTypes.LOOPBACK,          4, ProtocolIds.LOOPBACK),

    /** Raw IPv4 (no L2 header). */
    RAW_IP4         (L2FrameTypes.RAW_IP4,           0, ProtocolIds.IPv4),

    /** Raw IPv6 (no L2 header). */
    RAW_IP6         (L2FrameTypes.RAW_IP6,           0, ProtocolIds.IPv6),

    /** PPP with HDLC framing. */
    PPP_HDLC        (L2FrameTypes.PPP_HDLC,          4, ProtocolIds.PPP),

    /** Cisco HDLC. */
    CHDLC           (L2FrameTypes.CHDLC,             4, ProtocolIds.CHDLC),

    /** PPP over Ethernet. */
    PPPOE           (L2FrameTypes.PPPOE,             8, ProtocolIds.PPPoE),

    // ════════════════════════════════════════════════════════════════════════════
    // Wireless Frame Types
    // ════════════════════════════════════════════════════════════════════════════

    /** IEEE 802.11 wireless (native). Variable header 24-30 bytes. */
    IEEE80211           (L2FrameTypes.IEEE80211,          24, ProtocolIds.IEEE80211),

    /** IEEE 802.11 with Radiotap header. Variable length. */
    IEEE80211_RADIOTAP  (L2FrameTypes.IEEE80211_RADIOTAP,  8, ProtocolIds.RADIOTAP),

    /** IEEE 802.11 with AVS header. */
    IEEE80211_AVS       (L2FrameTypes.IEEE80211_AVS,      64, ProtocolIds.AVS),

    /** IEEE 802.11 with Prism header. */
    IEEE80211_PRISM     (L2FrameTypes.IEEE80211_PRISM,   144, ProtocolIds.PRISM),

    /** IEEE 802.11 with PPI header. Variable length. */
    IEEE80211_PPI       (L2FrameTypes.IEEE80211_PPI,       8, ProtocolIds.PPI),

    // ════════════════════════════════════════════════════════════════════════════
    // Linux-Specific Frame Types
    // ════════════════════════════════════════════════════════════════════════════

    /** Linux Netlink messages. */
    NETLINK         (L2FrameTypes.NETLINK,          16, ProtocolIds.NETLINK),

    /** Linux Netfilter log. */
    NFLOG           (L2FrameTypes.NFLOG,             4, ProtocolIds.NFLOG),

    /** Linux Netfilter queue. */
    NFQUEUE         (L2FrameTypes.NFQUEUE,           4, ProtocolIds.NFQUEUE),

    /** Linux SocketCAN. */
    LINUX_CAN       (L2FrameTypes.LINUX_CAN,        16, ProtocolIds.LINUX_CAN),

    /** Linux USB capture. */
    LINUX_USB       (L2FrameTypes.LINUX_USB,        48, ProtocolIds.LINUX_USB),

    /** Linux USB capture (64-bit/mmapped). */
    LINUX_USB_MM    (L2FrameTypes.LINUX_USB_MM,     64, ProtocolIds.LINUX_USB),

    /** Linux VM Sockets. */
    VSOCK           (L2FrameTypes.VSOCK,            16, ProtocolIds.VSOCK),

    /** Linux LAPD. */
    LAPD            (L2FrameTypes.LAPD,              4, ProtocolIds.LAPD),

    // ════════════════════════════════════════════════════════════════════════════
    // Legacy Frame Types
    // ════════════════════════════════════════════════════════════════════════════

    /** FDDI. */
    FDDI            (L2FrameTypes.FDDI,             21, ProtocolIds.FDDI),

    /** Token Ring. */
    TOKEN_RING      (L2FrameTypes.TOKEN_RING,       22, ProtocolIds.TOKEN_RING),

    /** ARCNET. */
    ARCNET          (L2FrameTypes.ARCNET,            3, ProtocolIds.ARCNET),

    /** ATM. */
    ATM             (L2FrameTypes.ATM,              56, ProtocolIds.ATM),

    /** Frame Relay. */
    FRELAY          (L2FrameTypes.FRELAY,            4, ProtocolIds.FRELAY),

    /** SLIP. */
    SLIP            (L2FrameTypes.SLIP,              0, ProtocolIds.SLIP),

    /** Chaosnet. */
    CHAOS           (L2FrameTypes.CHAOS,             4, ProtocolIds.CHAOS),

    // ════════════════════════════════════════════════════════════════════════════
    // Specialty Frame Types
    // ════════════════════════════════════════════════════════════════════════════

    /** Bluetooth HCI H4. */
    BLUETOOTH_HCI   (L2FrameTypes.BLUETOOTH_HCI,     1, ProtocolIds.BLUETOOTH_HCI),

    /** Bluetooth Low Energy Link Layer. */
    BLUETOOTH_LE    (L2FrameTypes.BLUETOOTH_LE,     10, ProtocolIds.BLUETOOTH_LE),

    /** BlueZ monitor. */
    BLUETOOTH_MON   (L2FrameTypes.BLUETOOTH_MON,     6, ProtocolIds.BLUETOOTH_MON),

    /** IP over InfiniBand. */
    IPOIB           (L2FrameTypes.IPOIB,             4, ProtocolIds.IPOIB),

    /** DOCSIS. */
    DOCSIS          (L2FrameTypes.DOCSIS,            6, ProtocolIds.DOCSIS),

    /** DPDK capture. */
    DPDK            (L2FrameTypes.DPDK,             24, ProtocolIds.PAYLOAD),

    // ════════════════════════════════════════════════════════════════════════════
    // BSD-Specific Frame Types (all in CAPTURE pack)
    // ════════════════════════════════════════════════════════════════════════════

    /** OpenBSD pflog (CAPTURE pack). */
    PFLOG           (L2FrameTypes.PFLOG,            48, ProtocolIds.PFLOG),

    /** OpenBSD pfsync (CAPTURE pack). */
    PFSYNC          (L2FrameTypes.PFSYNC,            4, ProtocolIds.PFSYNC),

    /** OpenBSD enc (CAPTURE pack). */
    ENC             (L2FrameTypes.ENC,              12, ProtocolIds.ENC),

    // ════════════════════════════════════════════════════════════════════════════
    // IoT/Embedded Frame Types
    // ════════════════════════════════════════════════════════════════════════════

    /** IEEE 802.15.4 (ZigBee PHY). */
    IEEE802_15_4        (L2FrameTypes.IEEE802_15_4,      0, ProtocolIds.IEEE802_15_4),

    /** IEEE 802.15.4 with TAP header. */
    IEEE802_15_4_TAP    (L2FrameTypes.IEEE802_15_4_TAP,  4, ProtocolIds.IEEE802_15_4_TAP),

    /** Amateur radio AX.25. Variable header. */
    AX25                (L2FrameTypes.AX25,              0, ProtocolIds.AX25),

    /** DECT. */
    DECT                (L2FrameTypes.DECT,             12, ProtocolIds.DECT),

    // @formatter:on
	;

	// ════════════════════════════════════════════════════════════════════════════
	// Instance Fields
	// ════════════════════════════════════════════════════════════════════════════

	private final int l2FrameId;
	private final int minLength;
	private final int maxLength;
	private final int protocolId;

	/**
	 * Creates a new L2 frame type info entry.
	 *
	 * @param l2FrameId  the L2FrameTypes constant value
	 * @param minLength  the base header length in bytes (may be variable)
	 * @param protocolId the ProtocolIds for the root protocol
	 */
	L2FrameType(int l2FrameId, int minLength, int protocolId) {
		this.l2FrameId = l2FrameId;
		this.minLength = minLength;
		this.maxLength = minLength;
		this.protocolId = protocolId;
	}

	/**
	 * Returns the L2 frame type constant.
	 *
	 * @return the L2FrameTypes value
	 */
	public int id() {
		return l2FrameId;
	}

	/**
	 * Returns the base header length in bytes.
	 * 
	 * <p>
	 * Note: Some frame types have variable-length headers (e.g., Radiotap, 802.11).
	 * This value represents the minimum or typical length. Actual length must be
	 * determined by parsing the header.
	 * </p>
	 *
	 * @return base header length in bytes
	 */
	public int minLength() {
		return minLength;
	}

	public int maxLength() {
		return maxLength;
	}

	/**
	 * Returns the protocol ID for the root protocol.
	 *
	 * @return ProtocolIds constant for dissection
	 */
	public int protocolId() {
		return protocolId;
	}

	/**
	 * Returns the protocol ID formatted for descriptors (lower 16 bits).
	 *
	 * @return descriptor-compatible protocol ID
	 */
	public int descriptorProtocolId() {
		return protocolId & ProtocolIds.MASK_DESCRIPTOR;
	}

	// ════════════════════════════════════════════════════════════════════════════
	// Static Lookup
	// ════════════════════════════════════════════════════════════════════════════

	/** Lookup table indexed by L2FrameTypes constant. */
	private static final L2FrameType[] BY_TYPE = new L2FrameType[128];

	static {
		for (L2FrameType info : values()) {
			if (info.l2FrameId >= 0 && info.l2FrameId < BY_TYPE.length) {
				BY_TYPE[info.l2FrameId] = info;
			}
		}
	}

	/**
	 * Returns the L2FrameType for the given L2 frame type constant.
	 *
	 * @param l2Type the L2FrameTypes constant
	 * @return the corresponding info, or {@link #UNKNOWN} if not found
	 */
	public static L2FrameType valueOf(int l2Type) {
		if (l2Type >= 0 && l2Type < BY_TYPE.length && BY_TYPE[l2Type] != null) {
			return BY_TYPE[l2Type];
		}
		return UNKNOWN;
	}

	/**
	 * Checks if the given L2 frame type is known.
	 *
	 * @param l2Type the L2FrameTypes constant
	 * @return true if a mapping exists
	 */
	public static boolean isKnown(int l2Type) {
		return l2Type >= 0 && l2Type < BY_TYPE.length && BY_TYPE[l2Type] != null;
	}

	/**
	 * Maps L2FrameTypes to ProtocolIds numerical values.
	 * 
	 * @param l2FrameType frame type value to convert to protocol ID
	 * @return equivalent protocol ID
	 */
	public static int mapToProtocolId(int l2FrameType) {
		return valueOf(l2FrameType).protocolId;
	}
}