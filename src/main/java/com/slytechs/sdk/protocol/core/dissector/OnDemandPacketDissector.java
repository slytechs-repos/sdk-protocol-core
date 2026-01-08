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
package com.slytechs.sdk.protocol.core.dissector;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

import com.slytechs.sdk.common.memory.BindableView;
import com.slytechs.sdk.protocol.core.Header;
import com.slytechs.sdk.protocol.core.ProtocolId;
import com.slytechs.sdk.protocol.core.descriptor.L2FrameType;
import com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor;

/**
 * High-performance stateless packet dissector for on-demand protocol mapping.
 * 
 * <p>
 * This dissector provides zero-allocation, stateless protocol lookup designed
 * for scenarios where only minimal descriptor information is available (such as
 * PcapDescriptor with L2 frame type, capture length, and wire length). It
 * dissects packet data on-demand up to the requested protocol and returns the
 * encoded offset/length.
 * </p>
 * 
 * <h2>Design Goals</h2>
 * <ul>
 * <li><strong>Stateless:</strong> No instance state, all methods are static for
 * maximum performance when switching between descriptors at 100Mpps</li>
 * <li><strong>Zero allocation:</strong> No object creation during
 * dissection</li>
 * <li><strong>Early termination:</strong> Stops dissection as soon as target
 * protocol is found</li>
 * <li><strong>Minimal branching:</strong> Optimized switch statements and
 * inline constants</li>
 * </ul>
 * 
 * <h2>Supported Protocol Stack</h2>
 * 
 * <pre>
 * L2: Ethernet II, 802.3/LLC/SNAP, VLAN (802.1Q, QinQ)
 * L3: IPv4, IPv6 (with extension headers), ARP
 * L4: TCP, UDP, SCTP, ICMPv4, ICMPv6
 * Tunnels: GRE, VXLAN, IP-in-IP
 * </pre>
 * 
 * <h2>Usage Example</h2>
 * 
 * <pre>{@code
 * // In PcapDescriptor.mapProtocol() implementation:
 * public long mapProtocol(int protocolId, int depth) {
 *     MemorySegment seg = packet.segment();
 *     long base = packet.start();
 *     long limit = captureLength();
 *     
 *     return OnDemandPacketDissector.mapProtocol(
 *         l2FrameType(),
 *         protocolId,
 *         depth,
 *         seg,
 *         base,
 *         limit
 *     );
 * }
 * 
 * // Direct usage with raw segment:
 * long encoded = OnDemandPacketDissector.mapProtocol(
 *     L2FrameType.ETHER,
 *     ProtocolId.TCP,
 *     0,  // outer occurrence
 *     segment,
 *     0,
 *     packetLength
 * );
 * 
 * if (encoded != PacketDescriptor.PROTOCOL_NOT_FOUND) {
 *     int offset = PacketDescriptor.decodeOffset(encoded);
 *     int length = PacketDescriptor.decodeLength(encoded);
 * }
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see PacketDescriptor#mapProtocol(int, int)
 * @see L2FrameType
 * @see ProtocolId
 * @since 1.0
 */
public final class OnDemandPacketDissector {

	// ════════════════════════════════════════════════════════════════════════════
	// VarHandle for direct memory access (big-endian for network byte order)
	// ════════════════════════════════════════════════════════════════════════════

	private static final VarHandle BYTE_HANDLE = ValueLayout.JAVA_BYTE.varHandle();
	private static final VarHandle SHORT_BE = ValueLayout.JAVA_SHORT_UNALIGNED
			.withOrder(ByteOrder.BIG_ENDIAN).varHandle();
	private static final VarHandle INT_BE = ValueLayout.JAVA_INT_UNALIGNED
			.withOrder(ByteOrder.BIG_ENDIAN).varHandle();
	private static final VarHandle INT_LE = ValueLayout.JAVA_INT_UNALIGNED
			.withOrder(ByteOrder.LITTLE_ENDIAN).varHandle();

	// ════════════════════════════════════════════════════════════════════════════
	// Protocol Constants (inline for performance)
	// ════════════════════════════════════════════════════════════════════════════

	// EtherTypes
	private static final int ETHERTYPE_IPV4 = 0x0800;
	private static final int ETHERTYPE_IPV6 = 0x86DD;
	private static final int ETHERTYPE_ARP = 0x0806;
	private static final int ETHERTYPE_VLAN = 0x8100;
	private static final int ETHERTYPE_QINQ = 0x88A8;
	private static final int ETHERTYPE_MPLS = 0x8847;
	private static final int ETHERTYPE_MPLS_MC = 0x8848;

	// IP Protocol Numbers
	private static final int IP_PROTO_ICMP = 1;
	private static final int IP_PROTO_TCP = 6;
	private static final int IP_PROTO_UDP = 17;
	private static final int IP_PROTO_IPV6 = 41;
	private static final int IP_PROTO_GRE = 47;
	private static final int IP_PROTO_ICMPV6 = 58;
	private static final int IP_PROTO_SCTP = 132;
	private static final int IP_PROTO_IPIP = 4;

	// IPv6 Extension Header Types
	private static final int IPV6_EXT_HOP_BY_HOP = 0;
	private static final int IPV6_EXT_ROUTING = 43;
	private static final int IPV6_EXT_FRAGMENT = 44;
	private static final int IPV6_EXT_ESP = 50;
	private static final int IPV6_EXT_AH = 51;
	private static final int IPV6_EXT_DEST_OPTIONS = 60;
	private static final int IPV6_EXT_MOBILITY = 135;
	private static final int IPV6_EXT_HIP = 139;
	private static final int IPV6_EXT_SHIM6 = 140;

	// Header Lengths
	private static final int ETHER_HEADER_LEN = 14;
	private static final int VLAN_TAG_LEN = 4;
	private static final int IPV4_MIN_HEADER_LEN = 20;
	private static final int IPV6_HEADER_LEN = 40;
	private static final int TCP_MIN_HEADER_LEN = 20;
	private static final int UDP_HEADER_LEN = 8;
	private static final int ICMP_HEADER_LEN = 8;
	private static final int ARP_HEADER_LEN = 28;
	private static final int GRE_MIN_HEADER_LEN = 4;
	private static final int VXLAN_HEADER_LEN = 8;
	private static final int SCTP_HEADER_LEN = 12;

	// UDP Ports for tunnel detection
	private static final int UDP_PORT_VXLAN = 4789;

	// Descriptor IDs (masked for comparison)
	private static final int DESC_ETHERNET = ProtocolId.ETHERNET & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_VLAN = ProtocolId.VLAN & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_VLAN_8021Q = ProtocolId.VLAN_8021Q & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_VLAN_8021AD = ProtocolId.VLAN_8021AD & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_ARP = ProtocolId.ARP & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_IP = ProtocolId.IP & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_IPV4 = ProtocolId.IPv4 & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_IPV6 = ProtocolId.IPv6 & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_ICMP = ProtocolId.ICMP & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_ICMPV4 = ProtocolId.ICMPv4 & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_ICMPV6 = ProtocolId.ICMPv6 & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_TCP = ProtocolId.TCP & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_UDP = ProtocolId.UDP & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_SCTP = ProtocolId.SCTP & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_GRE = ProtocolId.GRE & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_VXLAN = ProtocolId.VXLAN & ProtocolId.MASK_DESCRIPTOR;
	private static final int DESC_MPLS = ProtocolId.MPLS & ProtocolId.MASK_DESCRIPTOR;

	// ════════════════════════════════════════════════════════════════════════════
	// Private constructor - utility class
	// ════════════════════════════════════════════════════════════════════════════

	private OnDemandPacketDissector() {
		// Utility class - no instantiation
	}

	// ════════════════════════════════════════════════════════════════════════════
	// Main Entry Point
	// ════════════════════════════════════════════════════════════════════════════

	public static boolean bindHeader(BindableView packet, Header header,
			int l2FrameType, int protocolId, int depth) {
		// Slow path
		MemorySegment mseg = packet.boundMemory().segment();
		long start = packet.view().start();
		long limit = packet.view().length();
		long encoded = OnDemandPacketDissector.mapProtocol(l2FrameType, protocolId, depth, mseg, start, limit);
		if (encoded < 0)
			return false;

		long offset = PacketDescriptor.decodeOffset(encoded);
		long length = PacketDescriptor.decodeLength(encoded);

		return header.bindHeader(packet, protocolId, depth, offset, length);

	}

	/**
	 * Maps a protocol ID to its offset and length within the packet.
	 * 
	 * <p>
	 * Performs stateless, on-demand dissection starting from the specified L2 frame
	 * type and traversing the protocol stack until the target protocol is found or
	 * the packet is exhausted.
	 * </p>
	 * 
	 * <h3>Return Value Encoding</h3>
	 * 
	 * <pre>
	 * 64-bit encoded value:
	 * +----------------+----------------+
	 * | Length (32-bit)| Offset (32-bit)|
	 * +----------------+----------------+
	 * </pre>
	 * 
	 * <p>
	 * Use {@link PacketDescriptor#decodeOffset(long)} and
	 * {@link PacketDescriptor#decodeLength(long)} to extract values.
	 * </p>
	 *
	 * @param l2FrameType the L2 frame type constant from {@link L2FrameType}
	 * @param protocolId  the target protocol ID from {@link ProtocolId}
	 * @param depth       occurrence depth (0=outer/first, 1=inner/second for
	 *                    tunnels)
	 * @param seg         the memory segment containing packet data
	 * @param base        the base offset within the segment where packet starts
	 * @param limit       the length of packet data available
	 * @return encoded offset and length, or
	 *         {@link PacketDescriptor#PROTOCOL_NOT_FOUND} if the protocol is not
	 *         present
	 * @see PacketDescriptor#encodeLengthAndOffset(int, int)
	 */
	public static long mapProtocol(int l2FrameType, int protocolId, int depth,
			MemorySegment seg, long base, long limit) {

		if (seg == null || limit < ETHER_HEADER_LEN) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		// Normalize protocol ID to descriptor format
		int targetId = protocolId & ProtocolId.MASK_DESCRIPTOR;

		return dissectFromL2(l2FrameType, seg, base, limit, targetId, depth);
	}

	// ════════════════════════════════════════════════════════════════════════════
	// L2 Dissection
	// ════════════════════════════════════════════════════════════════════════════

	/**
	 * Dissects from L2 layer based on frame type.
	 */
	private static long dissectFromL2(int l2FrameType, MemorySegment seg, long base,
			long limit, int targetId, int depth) {

		return switch (l2FrameType) {
		case L2FrameType.ETHER -> dissectEthernet(seg, base, limit, targetId, depth);
		case L2FrameType.RAW_IP4 -> dissectIPv4(seg, base, 0, limit, targetId, depth);
		case L2FrameType.RAW_IP6 -> dissectIPv6(seg, base, 0, limit, targetId, depth);
		case L2FrameType.SLL -> dissectSLL(seg, base, limit, targetId, depth);
		case L2FrameType.SLL2 -> dissectSLL2(seg, base, limit, targetId, depth);
		case L2FrameType.LOOPBACK -> dissectLoopback(seg, base, limit, targetId, depth);
		default -> PacketDescriptor.PROTOCOL_NOT_FOUND;
		};
	}

	/**
	 * Dissects Ethernet II frame.
	 */
	private static long dissectEthernet(MemorySegment seg, long base, long limit,
			int targetId, int depth) {

		if (limit < ETHER_HEADER_LEN) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		// Check if Ethernet itself is the target
		if (targetId == DESC_ETHERNET && depth == 0) {
			return PacketDescriptor.encodeLengthAndOffset(ETHER_HEADER_LEN, 0);
		}

		// Read EtherType at offset 12
		int etherType = getShortBE(seg, base + 12) & 0xFFFF;
		int offset = ETHER_HEADER_LEN;

		// Handle VLAN tags
		int vlanCount = 0;
		while ((etherType == ETHERTYPE_VLAN || etherType == ETHERTYPE_QINQ)
				&& offset + VLAN_TAG_LEN <= limit) {

			// Check if VLAN is the target
			if ((targetId == DESC_VLAN || targetId == DESC_VLAN_8021Q || targetId == DESC_VLAN_8021AD)
					&& vlanCount == depth) {
				return PacketDescriptor.encodeLengthAndOffset(VLAN_TAG_LEN, offset);
			}

			// Skip VLAN tag and read next EtherType
			etherType = getShortBE(seg, base + offset + 2) & 0xFFFF;
			offset += VLAN_TAG_LEN;
			vlanCount++;
		}

		// Dispatch based on EtherType
		return dissectByEtherType(seg, base, offset, limit, etherType, targetId, depth);
	}

	/**
	 * Dissects Linux cooked capture v1 (SLL).
	 */
	private static long dissectSLL(MemorySegment seg, long base, long limit,
			int targetId, int depth) {

		final int SLL_HEADER_LEN = 16;
		if (limit < SLL_HEADER_LEN) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		// Protocol type at offset 14
		int protoType = getShortBE(seg, base + 14) & 0xFFFF;
		return dissectByEtherType(seg, base, SLL_HEADER_LEN, limit, protoType, targetId, depth);
	}

	/**
	 * Dissects Linux cooked capture v2 (SLL2).
	 */
	private static long dissectSLL2(MemorySegment seg, long base, long limit,
			int targetId, int depth) {

		final int SLL2_HEADER_LEN = 20;
		if (limit < SLL2_HEADER_LEN) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		// Protocol type at offset 0
		int protoType = getShortBE(seg, base) & 0xFFFF;
		return dissectByEtherType(seg, base, SLL2_HEADER_LEN, limit, protoType, targetId, depth);
	}

	/**
	 * Dissects BSD loopback encapsulation.
	 */
	private static long dissectLoopback(MemorySegment seg, long base, long limit,
			int targetId, int depth) {

		final int LOOP_HEADER_LEN = 4;
		if (limit < LOOP_HEADER_LEN) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		// Address family (host byte order, but commonly little-endian)
		int family = getIntLE(seg, base);

		return switch (family) {
		case 2 -> dissectIPv4(seg, base, LOOP_HEADER_LEN, limit, targetId, depth); // AF_INET
		case 24, 28, 30 -> dissectIPv6(seg, base, LOOP_HEADER_LEN, limit, targetId, depth); // AF_INET6 variants
		default -> PacketDescriptor.PROTOCOL_NOT_FOUND;
		};
	}

	/**
	 * Dispatches dissection based on EtherType.
	 */
	private static long dissectByEtherType(MemorySegment seg, long base, int offset,
			long limit, int etherType, int targetId, int depth) {

		return switch (etherType) {
		case ETHERTYPE_IPV4 -> dissectIPv4(seg, base, offset, limit, targetId, depth);
		case ETHERTYPE_IPV6 -> dissectIPv6(seg, base, offset, limit, targetId, depth);
		case ETHERTYPE_ARP -> dissectARP(seg, base, offset, limit, targetId, depth);
		case ETHERTYPE_MPLS, ETHERTYPE_MPLS_MC -> dissectMPLS(seg, base, offset, limit, targetId, depth);
		default -> PacketDescriptor.PROTOCOL_NOT_FOUND;
		};
	}

	// ════════════════════════════════════════════════════════════════════════════
	// L3 Dissection
	// ════════════════════════════════════════════════════════════════════════════

	/**
	 * Dissects IPv4 header.
	 */
	private static long dissectIPv4(MemorySegment seg, long base, int offset,
			long limit, int targetId, int depth) {

		if (offset + IPV4_MIN_HEADER_LEN > limit) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		// Read version/IHL byte
		int versionIhl = getByte(seg, base + offset) & 0xFF;
		int version = versionIhl >>> 4;
		int ihl = (versionIhl & 0x0F) * 4;

		if (version != 4 || ihl < IPV4_MIN_HEADER_LEN || offset + ihl > limit) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		// Check if IPv4 is the target
		if ((targetId == DESC_IPV4 || targetId == DESC_IP) && depth == 0) {
			return PacketDescriptor.encodeLengthAndOffset(ihl, offset);
		}

		// Read protocol and total length
		int protocol = getByte(seg, base + offset + 9) & 0xFF;
		int totalLength = getShortBE(seg, base + offset + 2) & 0xFFFF;

		// Validate total length
		if (offset + totalLength > limit) {
			totalLength = (int) (limit - offset);
		}

		int l4Offset = offset + ihl;
		int l4Limit = offset + totalLength;

		return dissectIPv4Payload(seg, base, l4Offset, l4Limit, limit, protocol, targetId, depth);
	}

	/**
	 * Dissects IPv4 payload based on protocol number.
	 */
	private static long dissectIPv4Payload(MemorySegment seg, long base, int offset,
			int payloadLimit, long limit, int protocol, int targetId, int depth) {

		return switch (protocol) {
		case IP_PROTO_TCP -> dissectTCP(seg, base, offset, payloadLimit, targetId, depth);
		case IP_PROTO_UDP -> dissectUDP(seg, base, offset, payloadLimit, limit, targetId, depth);
		case IP_PROTO_ICMP -> dissectICMPv4(seg, base, offset, payloadLimit, targetId, depth);
		case IP_PROTO_SCTP -> dissectSCTP(seg, base, offset, payloadLimit, targetId, depth);
		case IP_PROTO_GRE -> dissectGRE(seg, base, offset, payloadLimit, limit, targetId, depth);
		case IP_PROTO_IPIP -> dissectIPv4(seg, base, offset, limit, targetId, decrementDepth(targetId, DESC_IPV4,
				depth));
		case IP_PROTO_IPV6 -> dissectIPv6(seg, base, offset, limit, targetId, decrementDepth(targetId, DESC_IPV6,
				depth));
		default -> PacketDescriptor.PROTOCOL_NOT_FOUND;
		};
	}

	/**
	 * Dissects IPv6 header and extension headers.
	 */
	private static long dissectIPv6(MemorySegment seg, long base, int offset,
			long limit, int targetId, int depth) {

		if (offset + IPV6_HEADER_LEN > limit) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		// Verify version
		int versionTC = getByte(seg, base + offset) & 0xFF;
		if ((versionTC >>> 4) != 6) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		// Check if IPv6 is the target
		if ((targetId == DESC_IPV6 || targetId == DESC_IP) && depth == 0) {
			return PacketDescriptor.encodeLengthAndOffset(IPV6_HEADER_LEN, offset);
		}

		// Read next header and payload length
		int nextHeader = getByte(seg, base + offset + 6) & 0xFF;
		int payloadLength = getShortBE(seg, base + offset + 4) & 0xFFFF;

		int extOffset = offset + IPV6_HEADER_LEN;
		long payloadLimit = Math.min(offset + IPV6_HEADER_LEN + payloadLength, limit);

		// Skip extension headers
		while (isIPv6ExtensionHeader(nextHeader) && extOffset < payloadLimit) {
			int extLen;
			if (nextHeader == IPV6_EXT_FRAGMENT) {
				extLen = 8; // Fragment header is always 8 bytes
			} else if (nextHeader == IPV6_EXT_AH) {
				extLen = (getByte(seg, base + extOffset + 1) & 0xFF) * 4 + 8;
			} else {
				extLen = (getByte(seg, base + extOffset + 1) & 0xFF) * 8 + 8;
			}

			if (extOffset + extLen > payloadLimit) {
				return PacketDescriptor.PROTOCOL_NOT_FOUND;
			}

			nextHeader = getByte(seg, base + extOffset) & 0xFF;
			extOffset += extLen;
		}

		return dissectIPv6Payload(seg, base, extOffset, payloadLimit, limit, nextHeader, targetId, depth);
	}

	/**
	 * Checks if the next header value is an IPv6 extension header.
	 */
	private static boolean isIPv6ExtensionHeader(int nextHeader) {
		return switch (nextHeader) {
		case IPV6_EXT_HOP_BY_HOP, IPV6_EXT_ROUTING, IPV6_EXT_FRAGMENT,
				IPV6_EXT_DEST_OPTIONS, IPV6_EXT_AH, IPV6_EXT_MOBILITY,
				IPV6_EXT_HIP, IPV6_EXT_SHIM6 -> true;
		default -> false;
		};
	}

	/**
	 * Dissects IPv6 payload based on next header value.
	 */
	private static long dissectIPv6Payload(MemorySegment seg, long base, int offset,
			long payloadLimit, long limit, int nextHeader, int targetId, int depth) {

		return switch (nextHeader) {
		case IP_PROTO_TCP -> dissectTCP(seg, base, offset, (int) payloadLimit, targetId, depth);
		case IP_PROTO_UDP -> dissectUDP(seg, base, offset, (int) payloadLimit, limit, targetId, depth);
		case IP_PROTO_ICMPV6 -> dissectICMPv6(seg, base, offset, (int) payloadLimit, targetId, depth);
		case IP_PROTO_SCTP -> dissectSCTP(seg, base, offset, (int) payloadLimit, targetId, depth);
		case IP_PROTO_GRE -> dissectGRE(seg, base, offset, (int) payloadLimit, limit, targetId, depth);
		case IP_PROTO_IPIP -> dissectIPv4(seg, base, offset, limit, targetId, decrementDepth(targetId, DESC_IPV4,
				depth));
		case IP_PROTO_IPV6 -> dissectIPv6(seg, base, offset, limit, targetId, decrementDepth(targetId, DESC_IPV6,
				depth));
		default -> PacketDescriptor.PROTOCOL_NOT_FOUND;
		};
	}

	/**
	 * Dissects ARP header.
	 */
	private static long dissectARP(MemorySegment seg, long base, int offset,
			long limit, int targetId, int depth) {

		if (targetId == DESC_ARP && depth == 0) {
			if (offset + ARP_HEADER_LEN <= limit) {
				return PacketDescriptor.encodeLengthAndOffset(ARP_HEADER_LEN, offset);
			}
		}
		return PacketDescriptor.PROTOCOL_NOT_FOUND;
	}

	/**
	 * Dissects MPLS header stack.
	 */
	private static long dissectMPLS(MemorySegment seg, long base, int offset,
			long limit, int targetId, int depth) {

		if (targetId == DESC_MPLS && depth == 0) {
			// Count MPLS labels to determine total length
			int mplsOffset = offset;
			int labelCount = 0;
			boolean bottomOfStack = false;

			while (!bottomOfStack && mplsOffset + 4 <= limit) {
				int label = getIntBE(seg, base + mplsOffset);
				bottomOfStack = (label & 0x100) != 0; // S bit
				mplsOffset += 4;
				labelCount++;
				if (labelCount > 16)
					break; // Safety limit
			}

			if (labelCount > 0) {
				return PacketDescriptor.encodeLengthAndOffset(labelCount * 4, offset);
			}
		}

		// Skip MPLS labels to find encapsulated protocol
		int mplsOffset = offset;
		boolean bottomOfStack = false;

		while (!bottomOfStack && mplsOffset + 4 <= limit) {
			int label = getIntBE(seg, base + mplsOffset);
			bottomOfStack = (label & 0x100) != 0;
			mplsOffset += 4;
		}

		if (!bottomOfStack || mplsOffset >= limit) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		// Detect encapsulated protocol by version nibble
		int version = (getByte(seg, base + mplsOffset) & 0xF0) >>> 4;
		return switch (version) {
		case 4 -> dissectIPv4(seg, base, mplsOffset, limit, targetId, depth);
		case 6 -> dissectIPv6(seg, base, mplsOffset, limit, targetId, depth);
		default -> PacketDescriptor.PROTOCOL_NOT_FOUND;
		};
	}

	// ════════════════════════════════════════════════════════════════════════════
	// L4 Dissection
	// ════════════════════════════════════════════════════════════════════════════

	/**
	 * Dissects TCP header.
	 */
	private static long dissectTCP(MemorySegment seg, long base, int offset,
			int payloadLimit, int targetId, int depth) {

		if (offset + TCP_MIN_HEADER_LEN > payloadLimit) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		if (targetId == DESC_TCP && depth == 0) {
			// Read data offset from byte 12 (upper nibble)
			int dataOffset = ((getByte(seg, base + offset + 12) & 0xF0) >>> 4) * 4;
			if (dataOffset < TCP_MIN_HEADER_LEN) {
				dataOffset = TCP_MIN_HEADER_LEN;
			}
			return PacketDescriptor.encodeLengthAndOffset(dataOffset, offset);
		}

		return PacketDescriptor.PROTOCOL_NOT_FOUND;
	}

	/**
	 * Dissects UDP header and potential tunnel protocols.
	 */
	private static long dissectUDP(MemorySegment seg, long base, int offset,
			int payloadLimit, long limit, int targetId, int depth) {

		if (offset + UDP_HEADER_LEN > payloadLimit) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		if (targetId == DESC_UDP && depth == 0) {
			return PacketDescriptor.encodeLengthAndOffset(UDP_HEADER_LEN, offset);
		}

		// Check for tunnel protocols
		int dstPort = getShortBE(seg, base + offset + 2) & 0xFFFF;

		if (dstPort == UDP_PORT_VXLAN) {
			return dissectVXLAN(seg, base, offset + UDP_HEADER_LEN, limit, targetId, depth);
		}

		return PacketDescriptor.PROTOCOL_NOT_FOUND;
	}

	/**
	 * Dissects ICMPv4 header.
	 */
	private static long dissectICMPv4(MemorySegment seg, long base, int offset,
			int payloadLimit, int targetId, int depth) {

		if ((targetId == DESC_ICMPV4 || targetId == DESC_ICMP) && depth == 0) {
			if (offset + ICMP_HEADER_LEN <= payloadLimit) {
				return PacketDescriptor.encodeLengthAndOffset(ICMP_HEADER_LEN, offset);
			}
		}
		return PacketDescriptor.PROTOCOL_NOT_FOUND;
	}

	/**
	 * Dissects ICMPv6 header.
	 */
	private static long dissectICMPv6(MemorySegment seg, long base, int offset,
			int payloadLimit, int targetId, int depth) {

		if ((targetId == DESC_ICMPV6 || targetId == DESC_ICMP) && depth == 0) {
			if (offset + ICMP_HEADER_LEN <= payloadLimit) {
				return PacketDescriptor.encodeLengthAndOffset(ICMP_HEADER_LEN, offset);
			}
		}
		return PacketDescriptor.PROTOCOL_NOT_FOUND;
	}

	/**
	 * Dissects SCTP header.
	 */
	private static long dissectSCTP(MemorySegment seg, long base, int offset,
			int payloadLimit, int targetId, int depth) {

		if (targetId == DESC_SCTP && depth == 0) {
			if (offset + SCTP_HEADER_LEN <= payloadLimit) {
				return PacketDescriptor.encodeLengthAndOffset(SCTP_HEADER_LEN, offset);
			}
		}
		return PacketDescriptor.PROTOCOL_NOT_FOUND;
	}

	// ════════════════════════════════════════════════════════════════════════════
	// Tunnel Dissection
	// ════════════════════════════════════════════════════════════════════════════

	/**
	 * Dissects GRE header and encapsulated protocol.
	 */
	private static long dissectGRE(MemorySegment seg, long base, int offset,
			int payloadLimit, long limit, int targetId, int depth) {

		if (offset + GRE_MIN_HEADER_LEN > payloadLimit) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		int flags = getShortBE(seg, base + offset) & 0xFFFF;
		int protocol = getShortBE(seg, base + offset + 2) & 0xFFFF;

		// Calculate GRE header length based on flags
		int greLen = GRE_MIN_HEADER_LEN;
		if ((flags & 0x8000) != 0)
			greLen += 4; // Checksum present
		if ((flags & 0x2000) != 0)
			greLen += 4; // Key present
		if ((flags & 0x1000) != 0)
			greLen += 4; // Sequence present

		if (targetId == DESC_GRE && depth == 0) {
			return PacketDescriptor.encodeLengthAndOffset(greLen, offset);
		}

		int innerOffset = offset + greLen;
		if (innerOffset >= limit) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		// Dissect encapsulated protocol
		return dissectByEtherType(seg, base, innerOffset, limit, protocol, targetId,
				decrementDepthForTunnel(targetId, depth));
	}

	/**
	 * Dissects VXLAN header and inner Ethernet frame.
	 */
	private static long dissectVXLAN(MemorySegment seg, long base, int offset,
			long limit, int targetId, int depth) {

		if (offset + VXLAN_HEADER_LEN > limit) {
			return PacketDescriptor.PROTOCOL_NOT_FOUND;
		}

		if (targetId == DESC_VXLAN && depth == 0) {
			return PacketDescriptor.encodeLengthAndOffset(VXLAN_HEADER_LEN, offset);
		}

		// VXLAN encapsulates an inner Ethernet frame
		int innerOffset = offset + VXLAN_HEADER_LEN;
		return dissectEthernet(seg, base + innerOffset, limit - innerOffset, targetId,
				decrementDepthForTunnel(targetId, depth));
	}

	// ════════════════════════════════════════════════════════════════════════════
	// Helper Methods
	// ════════════════════════════════════════════════════════════════════════════

	/**
	 * Decrements depth if the target matches the current protocol (for IP-in-IP).
	 */
	private static int decrementDepth(int targetId, int currentProto, int depth) {
		return (targetId == currentProto && depth > 0) ? depth - 1 : depth;
	}

	/**
	 * Decrements depth for tunnel protocols (used when entering inner packet).
	 */
	private static int decrementDepthForTunnel(int targetId, int depth) {
		// Depth is decremented when we enter the inner packet for all protocols
		return (depth > 0) ? depth - 1 : depth;
	}

	/**
	 * Reads a byte at the specified offset.
	 */
	private static byte getByte(MemorySegment seg, long offset) {
		return (byte) BYTE_HANDLE.get(seg, offset);
	}

	/**
	 * Reads a big-endian short at the specified offset.
	 */
	private static short getShortBE(MemorySegment seg, long offset) {
		return (short) SHORT_BE.get(seg, offset);
	}

	/**
	 * Reads a big-endian int at the specified offset.
	 */
	private static int getIntBE(MemorySegment seg, long offset) {
		return (int) INT_BE.get(seg, offset);
	}

	/**
	 * Reads a little-endian int at the specified offset.
	 */
	private static int getIntLE(MemorySegment seg, long offset) {
		return (int) INT_LE.get(seg, offset);
	}
}