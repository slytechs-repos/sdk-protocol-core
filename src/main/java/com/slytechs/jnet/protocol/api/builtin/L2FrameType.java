/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
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
package com.slytechs.jnet.protocol.api.builtin;

import java.util.Optional;

import com.slytechs.jnet.protocol.api.Header;
import com.slytechs.jnet.protocol.api.HeaderFactory;
import com.slytechs.jnet.protocol.api.ProtoId;
import com.slytechs.jnet.protocol.api.Protocol;
import com.slytechs.jnet.protocol.api.pack.ProtocolPackManager;

/**
 * The Enum L2FrameType.
 *
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
public enum L2FrameType {

	/** Unknown/unspecified frame type */
	L2_FRAME_TYPE_UNKNOWN(0, Constants.L2_FRAME_TYPE_UNKNOWN, ProtoId.Constants.PROTO_ID_PAYLOAD),

	/** Standard Ethernet II (DIX) */
	L2_FRAME_TYPE_ETHER(14, Constants.L2_FRAME_TYPE_ETHER, ProtoId.Constants.PROTO_ID_ETHERNET),

	/** Point-to-Point Protocol */
	L2_FRAME_TYPE_PPP(4, Constants.L2_FRAME_TYPE_PPP, ProtoId.Constants.PROTO_ID_PPP),

	/** Linux "any" pseudo-header (SLL) */
	L2_FRAME_TYPE_SLL(16, Constants.L2_FRAME_TYPE_SLL, ProtoId.Constants.PROTO_ID_SLL),

	/** Linux "any" pseudo-header v2 (SLL2) - newer version */
	L2_FRAME_TYPE_SLL2(20, Constants.L2_FRAME_TYPE_SLL2, ProtoId.Constants.PROTO_ID_SLL2),

	/** BSD loopback encapsulation (NULL) */
	L2_FRAME_TYPE_NULL(4, Constants.L2_FRAME_TYPE_NULL, ProtoId.Constants.PROTO_ID_LOOPBACK),

	/** Raw IP (no L2 header) */
	L2_FRAME_TYPE_RAW_IP(0, Constants.L2_FRAME_TYPE_RAW_IP, ProtoId.Constants.PROTO_ID_IPV4),

	/** IEEE 802.11 wireless */
	L2_FRAME_TYPE_IEEE80211(24, Constants.L2_FRAME_TYPE_IEEE80211, ProtoId.Constants.PROTO_ID_IEEE80211),

	/** IEEE 802.11 + Radiotap header */
	L2_FRAME_TYPE_IEEE80211_RADIOTAP(8, Constants.L2_FRAME_TYPE_IEEE80211_RADIOTAP,
			ProtoId.Constants.PROTO_ID_RADIOTAP),

	/** IEEE 802.11 + AVS header */
	L2_FRAME_TYPE_IEEE80211_AVS(64, Constants.L2_FRAME_TYPE_IEEE80211_AVS, ProtoId.Constants.PROTO_ID_AVS),

	/** Linux cooked capture v1 (older) */
	L2_FRAME_TYPE_LINUX_SLL(16, Constants.L2_FRAME_TYPE_LINUX_SLL, ProtoId.Constants.PROTO_ID_SLL),

	/** Linux cooked capture v2 (current) */
	L2_FRAME_TYPE_LINUX_SLL2(20, Constants.L2_FRAME_TYPE_LINUX_SLL2, ProtoId.Constants.PROTO_ID_SLL2),

	/** Cisco HDLC */
	L2_FRAME_TYPE_CHDLC(4, Constants.L2_FRAME_TYPE_CHDLC, ProtoId.Constants.PROTO_ID_CHDLC),

	/** Frame Relay */
	L2_FRAME_TYPE_FRELAY(4, Constants.L2_FRAME_TYPE_FRELAY, ProtoId.Constants.PROTO_ID_FRELAY),

	/** PPP with HDLC framing */
	L2_FRAME_TYPE_PPP_HDLC(4, Constants.L2_FRAME_TYPE_PPP_HDLC, ProtoId.Constants.PROTO_ID_PPP),

	/** PPP over Ethernet Discovery/Session */
	L2_FRAME_TYPE_PPPOE(8, Constants.L2_FRAME_TYPE_PPPOE, ProtoId.Constants.PROTO_ID_PPPoE),

	/** IP over InfiniBand */
	L2_FRAME_TYPE_IPOIB(4, Constants.L2_FRAME_TYPE_IPOIB, ProtoId.Constants.PROTO_ID_IPOIB),

	/** DOCSIS (Data Over Cable Service Interface Specification) */
	L2_FRAME_TYPE_DOCSIS(6, Constants.L2_FRAME_TYPE_DOCSIS, ProtoId.Constants.PROTO_ID_DOCSIS),

	/** Linux Netlink messages */
	L2_FRAME_TYPE_NETLINK(16, Constants.L2_FRAME_TYPE_NETLINK, ProtoId.Constants.PROTO_ID_NETLINK),

	/** USB packets with Linux header */
	L2_FRAME_TYPE_USB_LINUX(48, Constants.L2_FRAME_TYPE_USB_LINUX, ProtoId.Constants.PROTO_ID_USB),

	/** USB packets with Linux header (64-bit) */
	L2_FRAME_TYPE_USB_LINUX_MMAPPED(64, Constants.L2_FRAME_TYPE_USB_LINUX_MMAPPED, ProtoId.Constants.PROTO_ID_USB),

	/** NFLOG (Linux netfilter log) */
	L2_FRAME_TYPE_NFLOG(4, Constants.L2_FRAME_TYPE_NFLOG, ProtoId.Constants.PROTO_ID_NFLOG),

	/** VSock (VM sockets) */
	L2_FRAME_TYPE_VSOCK(16, Constants.L2_FRAME_TYPE_VSOCK, ProtoId.Constants.PROTO_ID_VSOCK),

	/** DPDK (Data Plane Development Kit) */
	L2_FRAME_TYPE_DPDK(24, Constants.L2_FRAME_TYPE_DPDK, ProtoId.Constants.PROTO_ID_DPDK),

	/** SocketCAN (Linux CAN bus) */
	L2_FRAME_TYPE_LINUX_CAN(16, Constants.L2_FRAME_TYPE_LINUX_CAN, ProtoId.Constants.PROTO_ID_CAN),

	/** Bluetooth HCI H4 */
	L2_FRAME_TYPE_BLUETOOTH_HCI_H4(1, Constants.L2_FRAME_TYPE_BLUETOOTH_HCI_H4, ProtoId.Constants.PROTO_ID_BLUETOOTH),

	/** Bluetooth Low Energy Link Layer */
	L2_FRAME_TYPE_BLUETOOTH_LE_LL(10, Constants.L2_FRAME_TYPE_BLUETOOTH_LE_LL, ProtoId.Constants.PROTO_ID_BLUETOOTH_LE),

	/** Legacy - kept for compatibility */
	L2_FRAME_TYPE_ATM(56, Constants.L2_FRAME_TYPE_ATM, ProtoId.Constants.PROTO_ID_PAYLOAD),
	L2_FRAME_TYPE_FDDI(21, Constants.L2_FRAME_TYPE_FDDI, ProtoId.Constants.PROTO_ID_PAYLOAD),
	L2_FRAME_TYPE_TOKEN_RING(22, Constants.L2_FRAME_TYPE_TOKEN_RING, ProtoId.Constants.PROTO_ID_PAYLOAD),
	L2_FRAME_TYPE_ARCNET(3, Constants.L2_FRAME_TYPE_ARCNET, ProtoId.Constants.PROTO_ID_PAYLOAD),
	;

	;

	public static final L2FrameType DEFAULT_L2_FRAME_TYPE = L2_FRAME_TYPE_ETHER;

	/** The id. */
	private final int protocolId;
	private final int l2Type;
	private final int offset = 0;
	private final int baseLength;

	/** The supplier. */
	private final Optional<Protocol> protocol;
	private final HeaderFactory.ProxyCreated<?> factory;

	/**
	 * Instantiates a new layer 2 frame type.
	 *
	 * @param id       the id
	 * @param supplier the supplier
	 */
	L2FrameType(int baseLength, int id, int protocolId) {
		this.baseLength = baseLength;
		this.protocolId = protocolId;
		this.l2Type = id;
		this.protocol = ProtocolPackManager.findProtocol(protocolId);

		if (protocol.isEmpty())
			this.factory = () -> {
				throw new UnsupportedOperationException("L2 frame type protocol not found "
						+ "0x" + Integer.toHexString(protocolId).toUpperCase());
			};
		else
			this.factory = protocol.get()
					.headerFactory()
					.proxy();
	}

	public interface Constants {
		/** The Constant L2_FRAME_TYPE_UNKNOWN. */
		int L2_FRAME_TYPE_UNKNOWN = -1;

		/** The Constant L2_FRAME_TYPE_OTHER. */
		int L2_FRAME_TYPE_OTHER = 0;

		/** The Constant L2_FRAME_TYPE_ETHER. */
		int L2_FRAME_TYPE_ETHER = 1;

		/** The Constant L2_FRAME_TYPE_LLC. */
		int L2_FRAME_TYPE_LLC = 2;

		/** The Constant L2_FRAME_TYPE_SNAP. */
		int L2_FRAME_TYPE_SNAP = 3;

		/** The Constant L2_FRAME_TYPE_NOVELL_RAW. */
		int L2_FRAME_TYPE_NOVELL_RAW = 4;

		/** The Constant L2_FRAME_TYPE_ISL. */
		int L2_FRAME_TYPE_ISL = 5;

		/** The Constant L2_FRAME_TYPE_PPP. */
		int L2_FRAME_TYPE_PPP = 6;

		/** The Constant L2_FRAME_TYPE_FDDI. */
		int L2_FRAME_TYPE_FDDI = 7;

		/** The Constant L2_FRAME_TYPE_ATM. */
		int L2_FRAME_TYPE_ATM = 8;

		/** The Constant L2_FRAME_TYPE_IEEE80211. */
		int L2_FRAME_TYPE_IEEE80211 = 9;

		/** The Constant L2_FRAME_TYPE_SLL. */
		int L2_FRAME_TYPE_SLL = 10;

		/** The Constant L2_FRAME_TYPE_SLL2. */
		int L2_FRAME_TYPE_SLL2 = 11;

		/** The Constant L2_FRAME_TYPE_NULL. */
		int L2_FRAME_TYPE_NULL = 12;

		/** The Constant L2_FRAME_TYPE_MPLS. */
		int L2_FRAME_TYPE_MPLS = 13;

		/** The Constant L2_FRAME_TYPE_VXLAN. */
		int L2_FRAME_TYPE_VXLAN = 14;

		/** The Constant L2_FRAME_TYPE_GRE. */
		int L2_FRAME_TYPE_GRE = 15;

		/** The Constant L2_FRAME_TYPE_RAW_IP. */
		int L2_FRAME_TYPE_RAW_IP = 16;

		/** The Constant L2_FRAME_TYPE_IEEE80211_RADIOTAP. */
		int L2_FRAME_TYPE_IEEE80211_RADIOTAP = 17;

		/** The Constant L2_FRAME_TYPE_IEEE80211_AVS. */
		int L2_FRAME_TYPE_IEEE80211_AVS = 18;

		/** The Constant L2_FRAME_TYPE_LINUX_SLL. */
		int L2_FRAME_TYPE_LINUX_SLL = 19;

		/** The Constant L2_FRAME_TYPE_LINUX_SLL2. */
		int L2_FRAME_TYPE_LINUX_SLL2 = 20;

		/** The Constant L2_FRAME_TYPE_CHDLC. */
		int L2_FRAME_TYPE_CHDLC = 21;

		/** The Constant L2_FRAME_TYPE_FRELAY. */
		int L2_FRAME_TYPE_FRELAY = 22;

		/** The Constant L2_FRAME_TYPE_PPP_HDLC. */
		int L2_FRAME_TYPE_PPP_HDLC = 23;

		/** The Constant L2_FRAME_TYPE_PPPOE. */
		int L2_FRAME_TYPE_PPPOE = 24;

		/** The Constant L2_FRAME_TYPE_IPOIB. */
		int L2_FRAME_TYPE_IPOIB = 25;

		/** The Constant L2_FRAME_TYPE_DOCSIS. */
		int L2_FRAME_TYPE_DOCSIS = 26;

		/** The Constant L2_FRAME_TYPE_NETLINK. */
		int L2_FRAME_TYPE_NETLINK = 27;

		/** The Constant L2_FRAME_TYPE_USB_LINUX. */
		int L2_FRAME_TYPE_USB_LINUX = 28;

		/** The Constant L2_FRAME_TYPE_USB_LINUX_MMAPPED. */
		int L2_FRAME_TYPE_USB_LINUX_MMAPPED = 29;

		/** The Constant L2_FRAME_TYPE_NFLOG. */
		int L2_FRAME_TYPE_NFLOG = 30;

		/** The Constant L2_FRAME_TYPE_VSOCK. */
		int L2_FRAME_TYPE_VSOCK = 31;

		/** The Constant L2_FRAME_TYPE_DPDK. */
		int L2_FRAME_TYPE_DPDK = 32;

		/** The Constant L2_FRAME_TYPE_LINUX_CAN. */
		int L2_FRAME_TYPE_LINUX_CAN = 33;

		/** The Constant L2_FRAME_TYPE_BLUETOOTH_HCI_H4. */
		int L2_FRAME_TYPE_BLUETOOTH_HCI_H4 = 34;

		/** The Constant L2_FRAME_TYPE_BLUETOOTH_LE_LL. */
		int L2_FRAME_TYPE_BLUETOOTH_LE_LL = 35;

		/** The Constant L2_FRAME_TYPE_TOKEN_RING. */
		int L2_FRAME_TYPE_TOKEN_RING = 36;

		/** The Constant L2_FRAME_TYPE_ARCNET. */
		int L2_FRAME_TYPE_ARCNET = 37;

		/** The Constant L2_FRAME_TYPE_SLIP. */
		int L2_FRAME_TYPE_SLIP = 38;

		/** The Constant L2_FRAME_TYPE_LOOP. */
		int L2_FRAME_TYPE_LOOP = 39;

		/** The Constant L2_FRAME_TYPE_ENC. */
		int L2_FRAME_TYPE_ENC = 40;

		/** The Constant L2_FRAME_TYPE_PFLOG. */
		int L2_FRAME_TYPE_PFLOG = 41;

		/** The Constant L2_FRAME_TYPE_PFSYNC. */
		int L2_FRAME_TYPE_PFSYNC = 42;

		/** The Constant L2_FRAME_TYPE_CSLIP. */
		int L2_FRAME_TYPE_CSLIP = 43;

		/** The Constant L2_FRAME_TYPE_IPV4. */
		int L2_FRAME_TYPE_IPV4 = 44;

		/** The Constant L2_FRAME_TYPE_IPV6. */
		int L2_FRAME_TYPE_IPV6 = 45;

		/** The Constant L2_FRAME_TYPE_AX25. */
		int L2_FRAME_TYPE_AX25 = 46;

		/** The Constant L2_FRAME_TYPE_CHAOS. */
		int L2_FRAME_TYPE_CHAOS = 47;

		/** The Constant L2_FRAME_TYPE_IEEE802_15_4. */
		int L2_FRAME_TYPE_IEEE802_15_4 = 48;

		/** The Constant L2_FRAME_TYPE_LINUX_LAPD. */
		int L2_FRAME_TYPE_LINUX_LAPD = 49;
	}

	/**
	 * Value of integer l2 type to enum constant.
	 *
	 * @param l2FrameType the layer2 frame type
	 * @return the enum constant
	 */
	public static L2FrameType valueOf(int l2FrameType) {
		return values()[l2FrameType];
	}

	/**
	 * Gets the l 2 frame type as int.
	 *
	 * @return the l 2 frame type as int
	 */
	public int l2TypeId() {
		return l2Type;
	}

	public int l2Offset() {
		return offset;
	}

	public int baseLength() {
		return baseLength;
	}

	/**
	 * Gets the header id.
	 *
	 * @return the header id
	 * @see com.slytechs.jnet.protocol.api.common.HeaderInfo#descriptorId()
	 */
	public int protocolId() {
		return protocolId;
	}

	public Protocol protocol() {
		return protocol.orElse(null);
	}

	/**
	 * New header instance.
	 *
	 * @return the header
	 * @see com.slytechs.jnet.protocol.api.common.HeaderSupplier#newHeaderInstance()
	 */
	public Header newHeaderInstance() {
		return factory.newHeader();
	}

}