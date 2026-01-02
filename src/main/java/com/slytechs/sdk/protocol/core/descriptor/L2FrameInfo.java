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
package com.slytechs.sdk.protocol.core.descriptor;

import com.slytechs.sdk.protocol.core.ProtocolId;

/**
 * L2 frame type metadata: base header lengths and protocol ID mappings.
 * 
 * <p>
 * This enum provides the metadata needed to process frames of each L2 type,
 * including the base header length and the corresponding {@link ProtocolId} for
 * the root protocol.
 * </p>
 * 
 * <h2>Usage</h2>
 * 
 * <pre>{@code
 * int l2Type = descriptor.l2FrameType();
 * L2FrameInfo info = L2FrameInfo.of(l2Type);
 * 
 * int headerLen = info.baseLength();
 * int protoId = info.protocolId();
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see L2FrameType
 * @see ProtocolId
 */
public enum L2FrameInfo implements L2FrameType {

	// @formatter:off

    // ════════════════════════════════════════════════════════════════════════════
    // Common Frame Types
    // ════════════════════════════════════════════════════════════════════════════

    /** Unknown/unspecified - no L2 processing. */
    UNKNOWN         (L2FrameType.UNKNOWN,           0, ProtocolId.PAYLOAD),

    /** Ethernet II (DIX) or IEEE 802.3. */
    ETHER           (L2FrameType.ETHER,            14, ProtocolId.ETHERNET),

    /** Point-to-Point Protocol. */
    PPP             (L2FrameType.PPP,               4, ProtocolId.PPP),

    /** Linux cooked capture v1 (now in CAPTURE pack). */
    SLL             (L2FrameType.SLL,              16, ProtocolId.SLL),

    /** Linux cooked capture v2 (now in CAPTURE pack). */
    SLL2            (L2FrameType.SLL2,             20, ProtocolId.SLL2),

    /** BSD loopback/null encapsulation (now in CAPTURE pack). */
    LOOPBACK        (L2FrameType.LOOPBACK,          4, ProtocolId.LOOPBACK),

    /** Raw IPv4 (no L2 header). */
    RAW_IP4         (L2FrameType.RAW_IP4,           0, ProtocolId.IPv4),

    /** Raw IPv6 (no L2 header). */
    RAW_IP6         (L2FrameType.RAW_IP6,           0, ProtocolId.IPv6),

    /** PPP with HDLC framing. */
    PPP_HDLC        (L2FrameType.PPP_HDLC,          4, ProtocolId.PPP),

    /** Cisco HDLC. */
    CHDLC           (L2FrameType.CHDLC,             4, ProtocolId.CHDLC),

    /** PPP over Ethernet. */
    PPPOE           (L2FrameType.PPPOE,             8, ProtocolId.PPPoE),

    // ════════════════════════════════════════════════════════════════════════════
    // Wireless Frame Types
    // ════════════════════════════════════════════════════════════════════════════

    /** IEEE 802.11 wireless (native). Variable header 24-30 bytes. */
    IEEE80211           (L2FrameType.IEEE80211,          24, ProtocolId.IEEE80211),

    /** IEEE 802.11 with Radiotap header. Variable length. */
    IEEE80211_RADIOTAP  (L2FrameType.IEEE80211_RADIOTAP,  8, ProtocolId.RADIOTAP),

    /** IEEE 802.11 with AVS header. */
    IEEE80211_AVS       (L2FrameType.IEEE80211_AVS,      64, ProtocolId.AVS),

    /** IEEE 802.11 with Prism header. */
    IEEE80211_PRISM     (L2FrameType.IEEE80211_PRISM,   144, ProtocolId.PRISM),

    /** IEEE 802.11 with PPI header. Variable length. */
    IEEE80211_PPI       (L2FrameType.IEEE80211_PPI,       8, ProtocolId.PPI),

    // ════════════════════════════════════════════════════════════════════════════
    // Linux-Specific Frame Types
    // ════════════════════════════════════════════════════════════════════════════

    /** Linux Netlink messages. */
    NETLINK         (L2FrameType.NETLINK,          16, ProtocolId.NETLINK),

    /** Linux Netfilter log. */
    NFLOG           (L2FrameType.NFLOG,             4, ProtocolId.NFLOG),

    /** Linux Netfilter queue. */
    NFQUEUE         (L2FrameType.NFQUEUE,           4, ProtocolId.NFQUEUE),

    /** Linux SocketCAN. */
    LINUX_CAN       (L2FrameType.LINUX_CAN,        16, ProtocolId.LINUX_CAN),

    /** Linux USB capture. */
    LINUX_USB       (L2FrameType.LINUX_USB,        48, ProtocolId.LINUX_USB),

    /** Linux USB capture (64-bit/mmapped). */
    LINUX_USB_MM    (L2FrameType.LINUX_USB_MM,     64, ProtocolId.LINUX_USB),

    /** Linux VM Sockets. */
    VSOCK           (L2FrameType.VSOCK,            16, ProtocolId.VSOCK),

    /** Linux LAPD. */
    LAPD            (L2FrameType.LAPD,              4, ProtocolId.LAPD),

    // ════════════════════════════════════════════════════════════════════════════
    // Legacy Frame Types
    // ════════════════════════════════════════════════════════════════════════════

    /** FDDI. */
    FDDI            (L2FrameType.FDDI,             21, ProtocolId.FDDI),

    /** Token Ring. */
    TOKEN_RING      (L2FrameType.TOKEN_RING,       22, ProtocolId.TOKEN_RING),

    /** ARCNET. */
    ARCNET          (L2FrameType.ARCNET,            3, ProtocolId.ARCNET),

    /** ATM. */
    ATM             (L2FrameType.ATM,              56, ProtocolId.ATM),

    /** Frame Relay. */
    FRELAY          (L2FrameType.FRELAY,            4, ProtocolId.FRELAY),

    /** SLIP. */
    SLIP            (L2FrameType.SLIP,              0, ProtocolId.SLIP),

    /** Chaosnet. */
    CHAOS           (L2FrameType.CHAOS,             4, ProtocolId.CHAOS),

    // ════════════════════════════════════════════════════════════════════════════
    // Specialty Frame Types
    // ════════════════════════════════════════════════════════════════════════════

    /** Bluetooth HCI H4. */
    BLUETOOTH_HCI   (L2FrameType.BLUETOOTH_HCI,     1, ProtocolId.BLUETOOTH_HCI),

    /** Bluetooth Low Energy Link Layer. */
    BLUETOOTH_LE    (L2FrameType.BLUETOOTH_LE,     10, ProtocolId.BLUETOOTH_LE),

    /** BlueZ monitor. */
    BLUETOOTH_MON   (L2FrameType.BLUETOOTH_MON,     6, ProtocolId.BLUETOOTH_MON),

    /** IP over InfiniBand. */
    IPOIB           (L2FrameType.IPOIB,             4, ProtocolId.IPOIB),

    /** DOCSIS. */
    DOCSIS          (L2FrameType.DOCSIS,            6, ProtocolId.DOCSIS),

    /** DPDK capture. */
    DPDK            (L2FrameType.DPDK,             24, ProtocolId.PAYLOAD),

    // ════════════════════════════════════════════════════════════════════════════
    // BSD-Specific Frame Types (all in CAPTURE pack)
    // ════════════════════════════════════════════════════════════════════════════

    /** OpenBSD pflog (CAPTURE pack). */
    PFLOG           (L2FrameType.PFLOG,            48, ProtocolId.PFLOG),

    /** OpenBSD pfsync (CAPTURE pack). */
    PFSYNC          (L2FrameType.PFSYNC,            4, ProtocolId.PFSYNC),

    /** OpenBSD enc (CAPTURE pack). */
    ENC             (L2FrameType.ENC,              12, ProtocolId.ENC),

    // ════════════════════════════════════════════════════════════════════════════
    // IoT/Embedded Frame Types
    // ════════════════════════════════════════════════════════════════════════════

    /** IEEE 802.15.4 (ZigBee PHY). */
    IEEE802_15_4        (L2FrameType.IEEE802_15_4,      0, ProtocolId.IEEE802_15_4),

    /** IEEE 802.15.4 with TAP header. */
    IEEE802_15_4_TAP    (L2FrameType.IEEE802_15_4_TAP,  4, ProtocolId.IEEE802_15_4_TAP),

    /** Amateur radio AX.25. Variable header. */
    AX25                (L2FrameType.AX25,              0, ProtocolId.AX25),

    /** DECT. */
    DECT                (L2FrameType.DECT,             12, ProtocolId.DECT),

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
	 * @param l2FrameId  the L2FrameType constant value
	 * @param minLength  the base header length in bytes (may be variable)
	 * @param protocolId the ProtocolId for the root protocol
	 */
	L2FrameInfo(int l2FrameId, int minLength, int protocolId) {
		this.l2FrameId = l2FrameId;
		this.minLength = minLength;
		this.maxLength = minLength;
		this.protocolId = protocolId;
	}

	/**
	 * Returns the L2 frame type constant.
	 *
	 * @return the L2FrameType value
	 */
	@Override
	public int l2FrameId() {
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
	@Override
	public int minLength() {
		return minLength;
	}

	@Override
	public int maxLength() {
		return maxLength;
	}

	/**
	 * Returns the protocol ID for the root protocol.
	 *
	 * @return ProtocolId constant for dissection
	 */
	@Override
	public int protocolId() {
		return protocolId;
	}

	/**
	 * Returns the protocol ID formatted for descriptors (lower 16 bits).
	 *
	 * @return descriptor-compatible protocol ID
	 */
	public int descriptorProtocolId() {
		return protocolId & ProtocolId.MASK_DESCRIPTOR;
	}

	// ════════════════════════════════════════════════════════════════════════════
	// Static Lookup
	// ════════════════════════════════════════════════════════════════════════════

	/** Lookup table indexed by L2FrameType constant. */
	private static final L2FrameInfo[] BY_TYPE = new L2FrameInfo[128];

	static {
		for (L2FrameInfo info : values()) {
			if (info.l2FrameId >= 0 && info.l2FrameId < BY_TYPE.length) {
				BY_TYPE[info.l2FrameId] = info;
			}
		}
	}

	/**
	 * Returns the L2FrameInfo for the given L2 frame type constant.
	 *
	 * @param l2Type the L2FrameType constant
	 * @return the corresponding info, or {@link #UNKNOWN} if not found
	 */
	public static L2FrameInfo of(int l2Type) {
		if (l2Type >= 0 && l2Type < BY_TYPE.length && BY_TYPE[l2Type] != null) {
			return BY_TYPE[l2Type];
		}
		return UNKNOWN;
	}

	/**
	 * Checks if the given L2 frame type is known.
	 *
	 * @param l2Type the L2FrameType constant
	 * @return true if a mapping exists
	 */
	public static boolean isKnown(int l2Type) {
		return l2Type >= 0 && l2Type < BY_TYPE.length && BY_TYPE[l2Type] != null;
	}
}