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

import java.lang.foreign.MemoryLayout;

import com.slytechs.sdk.common.format.StructFormat;
import com.slytechs.sdk.common.format.StructFormattable;
import com.slytechs.sdk.common.memory.ByteBuf;
import com.slytechs.sdk.common.memory.Memory;
import com.slytechs.sdk.common.time.TimestampUnit;
import com.slytechs.sdk.protocol.core.IpProto;
import com.slytechs.sdk.protocol.core.ProtocolId;
import com.slytechs.sdk.protocol.core.descriptor.L2FrameType;
import com.slytechs.sdk.protocol.core.descriptor.L2FrameTypeInfo;
import com.slytechs.sdk.protocol.core.descriptor.NetPacketDescriptor;

/**
 * Zero-allocation dissector for Net3PacketDescriptor.
 * 
 * <p>
 * High-performance dissector that parses packet headers and stores results in a
 * compact descriptor format. Headers parse their own options/extensions; the
 * dissector only records offset and extended length (total including options).
 * </p>
 * 
 * <h2>Supported Protocols</h2>
 * <ul>
 * <li><b>Layer 2:</b> Ethernet II, IEEE 802.3 (LLC/SNAP), VLAN (802.1Q/QinQ),
 * MPLS</li>
 * <li><b>Layer 3:</b> IPv4, IPv6 (with extensions), ARP, IPsec (AH/ESP)</li>
 * <li><b>Layer 4:</b> TCP, UDP, ICMP, ICMPv6</li>
 * </ul>
 * 
 * <h2>Inline Table (8 slots)</h2>
 * <p>
 * Common protocols get O(1) lookup via inline slots:
 * </p>
 * 
 * <pre>
 * [0] Ethernet  [1] VLAN  [2] IPv4  [3] IPv6
 * [4] TCP       [5] UDP   [6] ICMP  [7] ARP
 * </pre>
 * <p>
 * Additional protocols (MPLS, IPsec, multiple VLANs) go to extended table.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class Net3PacketDissector extends BasePacketDissector implements PacketDissector, StructFormattable {

	public static final MemoryLayout LAYOUT = NetPacketDescriptor.LAYOUT;

	// Maximum protocols to track
	private static final int MAX_PROTOCOLS = 32;

	// Protocol storage - all pre-allocated
	private final int[] protocolIds = new int[MAX_PROTOCOLS];
	private final int[] protocolOffsets = new int[MAX_PROTOCOLS];
	private final int[] protocolExtendedLengths = new int[MAX_PROTOCOLS];
	private final int[] protocolInstances = new int[MAX_PROTOCOLS];
	private final int[] protocolEncounterOrder = new int[MAX_PROTOCOLS];
	private final boolean[] protocolIsFragment = new boolean[MAX_PROTOCOLS];
	private final boolean[] protocolIsTunneled = new boolean[MAX_PROTOCOLS];
	private final boolean[] protocolHasError = new boolean[MAX_PROTOCOLS];

	// Inline table (8 slots)
	private final long[] inlineEntries = new long[8];
	private final boolean[] inlineUsed = new boolean[8];

	// Extended table
	private final long[] extendedEntries = new long[MAX_PROTOCOLS];
	private int extendedIndex = 0;

	// Dissection state
	private int protocolCount = 0;
	private int vlanCount = 0;
	private int mplsCount = 0;
	private int encounterOrder = 0;
	private long protoBitmap = 0;

	// Packet metadata
	private final ByteBuf internalView = new ByteBuf();

	// Last IP header info (for transport dissection)
	private int lastIpProtocol = 0;
	private int lastIpOffset = 0;
	private int lastIpHeaderLen = 0;

	// Protocol entry bit layout (64 bits)
	private static final long PROTOCOL_ID_MASK = 0xFFFFL;
	private static final int HEADER_OFFSET_SHIFT = 16;
	private static final int HEADER_OFFSET_MASK = 0xFFFF;
	private static final int EXTENDED_LENGTH_SHIFT = 32;
	private static final int EXTENDED_LENGTH_MASK = 0xFFFF;
	private static final int ENCOUNTER_ORDER_SHIFT = 48;
	private static final int ENCOUNTER_ORDER_MASK = 0xFF;
	private static final int INSTANCE_NUM_SHIFT = 56;
	private static final int INSTANCE_NUM_MASK = 0x7;
	private static final long IS_FRAGMENT_BIT = 1L << 59;
	private static final long IS_TUNNELED_BIT = 1L << 60;
	private static final long HAS_ERRORS_BIT = 1L << 61;

	// Proto counts packing (16 bits)
	private static final int PROTOCOL_COUNT_MASK = 0xFF;
	private static final int VLAN_COUNT_SHIFT = 8;
	private static final int VLAN_COUNT_MASK = 0xF;
	private static final int MPLS_COUNT_SHIFT = 12;
	private static final int MPLS_COUNT_MASK = 0xF;

	// Inline table slots
	private static final int INLINE_ETHERNET = 0;
	private static final int INLINE_VLAN = 1;
	private static final int INLINE_IPV4 = 2;
	private static final int INLINE_IPV6 = 3;
	private static final int INLINE_TCP = 4;
	private static final int INLINE_UDP = 5;
	private static final int INLINE_ICMP = 6;
	private static final int INLINE_ARP = 7;

	// EtherTypes (Layer 2 next-protocol indicators)
	private static final int ETHER_TYPE_IPV4 = 0x0800;
	private static final int ETHER_TYPE_IPV6 = 0x86DD;
	private static final int ETHER_TYPE_VLAN = 0x8100;
	private static final int ETHER_TYPE_QINQ = 0x88A8;
	private static final int ETHER_TYPE_MPLS = 0x8847;
	private static final int ETHER_TYPE_MPLS_MC = 0x8848;
	private static final int ETHER_TYPE_ARP = 0x0806;

	// IEEE 802.3 length/type boundary (values <= 1500 are lengths, not types)
	private static final int IEEE_802_3_MAX_LENGTH = 1500;

	// ═══════════════════════════════════════════════════════════════════════
	// L2 Frame Type Support
	// ═══════════════════════════════════════════════════════════════════════

	@Override
	public int dissectPacket(ByteBuf buffer, long timestamp, int caplen, int wirelen) {
		recycle();
		
		super.dissectPacket(buffer, timestamp, caplen, wirelen);

		this.timestamp = timestamp;
		this.captureLength = caplen;
		this.wireLength = wirelen;

		buffer.position(0);
		buffer.limit(caplen);

		// Dispatch based on L2 frame type
		int nextProto;
		int offset;

		switch (l2FrameType) {
		case L2FrameType.ETHER -> {
			nextProto = dissectEthernet(buffer, 0);
			offset = protocolExtendedLengths[0]; // Ethernet recorded its own length (14 or 22)
		}

		case L2FrameType.SLL -> {
			nextProto = dissectLinuxSll(buffer, 0);
			offset = 16;
		}

		case L2FrameType.SLL2 -> {
			nextProto = dissectLinuxSll2(buffer, 0);
			offset = 20;
		}

		case L2FrameType.LOOPBACK -> {
			nextProto = dissectNull(buffer, 0);
			offset = 4;
		}

		case L2FrameType.RAW_IP4 -> {
			// No L2 header - peek IP version
			offset = 0;
			if (caplen > 0) {
				buffer.position(0);
				int version = (buffer.get() >> 4) & 0x0F;
				nextProto = (version == 4) ? ETHER_TYPE_IPV4 : (version == 6) ? ETHER_TYPE_IPV6 : 0;
			} else {
				nextProto = 0;
			}
		}

		case L2FrameType.PPP, L2FrameType.PPP_HDLC -> {
			nextProto = dissectPpp(buffer, 0);
			offset = L2FrameTypeInfo.of(l2FrameType).baseLength();
		}

		default -> {
			// Unknown L2 - record as payload, no further dissection
			addProtocol(ProtocolId.PAYLOAD, 0, caplen, 0);
			prepareTableEntries();
			return caplen;
		}
		}

		// Handle VLAN tags (only after Ethernet-like L2)
		if (l2FrameType == L2FrameType.ETHER ||
				l2FrameType == L2FrameType.SLL ||
				l2FrameType == L2FrameType.SLL2) {

			while ((nextProto == ETHER_TYPE_VLAN || nextProto == ETHER_TYPE_QINQ)
					&& offset + 4 <= caplen) {
				offset = dissectVlan(buffer, offset, vlanCount);
				vlanCount++;
				buffer.position(offset - 2);
				nextProto = buffer.getShortBE() & 0xFFFF;
			}
		}

		// Handle MPLS labels
		if (nextProto == ETHER_TYPE_MPLS || nextProto == ETHER_TYPE_MPLS_MC) {
			offset = dissectMpls(buffer, offset);
			if (offset < caplen) {
				buffer.position(offset);
				int version = (buffer.get() >> 4) & 0x0F;
				nextProto = (version == 4) ? ETHER_TYPE_IPV4 : (version == 6) ? ETHER_TYPE_IPV6 : 0;
			}
		}

		// Dissect Layer 3
		switch (nextProto) {
		case ETHER_TYPE_IPV4 -> offset = dissectIPv4(buffer, offset);
		case ETHER_TYPE_IPV6 -> offset = dissectIPv6(buffer, offset);
		case ETHER_TYPE_ARP -> offset = dissectARP(buffer, offset);
		}

		// Dissect Layer 4 / IPsec
		if (lastIpProtocol != 0 && offset < caplen) {
			dissectTransportOrIpsec(buffer, offset);
		}

		prepareTableEntries();
		return caplen;
	}

	// ═══════════════════════════════════════════════════════════════════════
	// New L2 Dissectors
	// ═══════════════════════════════════════════════════════════════════════

	private int dissectLinuxSll(ByteBuf buffer, int offset) {
		if (offset + 16 > captureLength)
			return 0;

		addProtocol(ProtocolId.SLL, offset, 16, 0);

		// Protocol type at offset 14-15
		buffer.position(offset + 14);
		return buffer.getShortBE() & 0xFFFF;
	}

	private int dissectLinuxSll2(ByteBuf buffer, int offset) {
		if (offset + 20 > captureLength)
			return 0;

		addProtocol(ProtocolId.SLL2, offset, 20, 0);

		// Protocol type at offset 0-1 in SLL2
		buffer.position(offset);
		return buffer.getShortBE() & 0xFFFF;
	}

	private int dissectNull(ByteBuf buffer, int offset) {
		if (offset + 4 > captureLength)
			return 0;

		addProtocol(ProtocolId.LOOPBACK, offset, 4, 0);

		// BSD null header: 4-byte AF family (host byte order!)
		buffer.position(offset);
		int af = buffer.getInt(); // Note: LE for BSD loopback

		return switch (af) {
		case 2 -> ETHER_TYPE_IPV4; // AF_INET
		case 24, 28, 30 -> ETHER_TYPE_IPV6; // AF_INET6 (varies by OS)
		default -> 0;
		};
	}

	private int dissectPpp(ByteBuf buffer, int offset) {
		if (offset + 4 > captureLength)
			return 0;

		addProtocol(ProtocolId.PPP, offset, 4, 0);

		// PPP protocol field at offset 2-3
		buffer.position(offset + 2);
		int pppProto = buffer.getShortBE() & 0xFFFF;

		return switch (pppProto) {
		case 0x0021 -> ETHER_TYPE_IPV4; // PPP_IP
		case 0x0057 -> ETHER_TYPE_IPV6; // PPP_IPV6
		default -> 0;
		};
	}

	@Override
	public void recycle() {
		protocolCount = 0;
		vlanCount = 0;
		mplsCount = 0;
		encounterOrder = 0;
		protoBitmap = 0;
		extendedIndex = 0;
		lastIpProtocol = 0;
		lastIpOffset = 0;
		lastIpHeaderLen = 0;

		for (int i = 0; i < 8; i++) {
			inlineEntries[i] = 0;
			inlineUsed[i] = false;
		}
	}

	@Override
	public int writeDescriptor(ByteBuf buffer) {
		buffer.position(0);
		super.writeDescriptor(buffer);

		// Net3 extensions
		buffer.putLong(protoBitmap);

		int protoCounts = (protocolCount & PROTOCOL_COUNT_MASK) |
				((vlanCount & VLAN_COUNT_MASK) << VLAN_COUNT_SHIFT) |
				((mplsCount & MPLS_COUNT_MASK) << MPLS_COUNT_SHIFT);
		buffer.putShort((short) protoCounts);

		buffer.putShort((short) 0); // extended offset (updated below if needed)
		buffer.putShort((short) extendedIndex);
		buffer.putShort((short) 0); // reserved

		// Inline table (64 bytes)
		for (int i = 0; i < 8; i++) {
			buffer.putLong(inlineEntries[i]);
		}

		if (buffer.hasError()) {
			buffer.clearError();
			return -1;
		}

		// Extended table
		if (extendedIndex > 0) {
			buffer.position(96 + captureLength);
			for (int i = 0; i < extendedIndex; i++) {
				buffer.putLong(extendedEntries[i]);
			}
			// Update extended offset
			buffer.position(0x1A);
			buffer.putShort((short) captureLength);

			if (buffer.hasError()) {
				buffer.clearError();
				return -1;
			}
		}

		return 96;
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Protocol Addition
	// ═══════════════════════════════════════════════════════════════════════

	private void addProtocol(int id, int offset, int extendedLength, int instance) {
		if (protocolCount >= MAX_PROTOCOLS)
			return;

		int idx = protocolCount;
		protocolIds[idx] = id;
		protocolOffsets[idx] = offset;
		protocolExtendedLengths[idx] = extendedLength;
		protocolInstances[idx] = instance;
		protocolEncounterOrder[idx] = encounterOrder++;
		protocolIsFragment[idx] = false;
		protocolIsTunneled[idx] = false;
		protocolHasError[idx] = false;

		int bitPos = getProtocolBitPosition(id);
		if (bitPos >= 0) {
			protoBitmap |= (1L << bitPos);
		}

		protocolCount++;
	}

	private void setLastProtocolFragment(boolean isFragment) {
		if (protocolCount > 0) {
			protocolIsFragment[protocolCount - 1] = isFragment;
		}
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Layer 2 Dissection
	// ═══════════════════════════════════════════════════════════════════════

	private int dissectEthernet(ByteBuf buffer, int offset) {
		if (offset + 14 > captureLength)
			return 0;

		buffer.position(offset + 12);
		int etherType = buffer.getShortBE() & 0xFFFF;

		if (etherType <= IEEE_802_3_MAX_LENGTH) {
			// IEEE 802.3 with LLC/SNAP
			if (offset + 17 > captureLength) {
				addProtocol(ProtocolId.ETHERNET, offset, 14, 0);
				return 0;
			}

			buffer.position(offset + 14);
			byte dsap = buffer.get();
			byte ssap = buffer.get();

			if (dsap == (byte) 0xAA && ssap == (byte) 0xAA) {
				// SNAP: LLC (3) + OUI (3) + Type (2) = 8 bytes
				if (offset + 22 > captureLength) {
					addProtocol(ProtocolId.ETHERNET, offset, 17, 0);
					return 0;
				}
				buffer.position(offset + 20);
				etherType = buffer.getShortBE() & 0xFFFF;
				addProtocol(ProtocolId.ETHERNET, offset, 22, 0);
			} else {
				// Just LLC
				addProtocol(ProtocolId.ETHERNET, offset, 17, 0);
				return 0; // No EtherType, can't continue
			}
		} else {
			// Ethernet II
			addProtocol(ProtocolId.ETHERNET, offset, 14, 0);
		}

		return etherType;
	}

	private int dissectVlan(ByteBuf buffer, int offset, int instance) {
		if (offset + 4 > captureLength)
			return offset;

		addProtocol(ProtocolId.VLAN, offset, 4, instance);
		return offset + 4;
	}

	private int dissectMpls(ByteBuf buffer, int offset) {
		// Parse MPLS label stack until bottom-of-stack bit
		while (offset + 4 <= captureLength) {
			buffer.position(offset);
			int labelEntry = buffer.getIntBE();

			addProtocol(ProtocolId.MPLS, offset, 4, mplsCount);
			mplsCount++;
			offset += 4;

			// Check bottom-of-stack bit (bit 8, counting from LSB)
			if ((labelEntry & 0x100) != 0) {
				break;
			}

			// Safety: max 8 labels
			if (mplsCount >= 8)
				break;
		}
		return offset;
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Layer 3 Dissection
	// ═══════════════════════════════════════════════════════════════════════

	private int dissectIPv4(ByteBuf buffer, int offset) {
		if (offset + 20 > captureLength)
			return offset;

		buffer.position(offset);
		byte verIhl = buffer.get();
		int headerLen = (verIhl & 0x0F) * 4;

		if (offset + headerLen > captureLength) {
			addProtocol(ProtocolId.IPv4, offset, 20, 0);
			return offset + 20;
		}

		addProtocol(ProtocolId.IPv4, offset, headerLen, 0);

		// Check fragmentation
		buffer.position(offset + 6);
		int flagsOffset = buffer.getShortBE() & 0xFFFF;
		boolean moreFragments = (flagsOffset & 0x2000) != 0;
		int fragOffset = flagsOffset & 0x1FFF;
		if (moreFragments || fragOffset != 0) {
			setLastProtocolFragment(true);
		}

		// Get protocol for transport layer
		buffer.position(offset + 9);
		lastIpProtocol = buffer.get() & 0xFF;
		lastIpOffset = offset;
		lastIpHeaderLen = headerLen;

		return offset + headerLen;
	}

	private int dissectIPv6(ByteBuf buffer, int offset) {
		if (offset + 40 > captureLength)
			return offset;

		int totalLength = 40;
		buffer.position(offset + 6);
		int nextHeader = buffer.get() & 0xFF;
		int currentOffset = offset + 40;

		// Process extension headers
		while (isIPv6Extension(nextHeader) && currentOffset + 2 <= captureLength) {
			buffer.position(currentOffset);
			int extNextHeader = buffer.get() & 0xFF;
			int extLen = ((buffer.get() & 0xFF) + 1) * 8;

			// Fragment header is fixed 8 bytes
			if (nextHeader == 44) {
				extLen = 8;
				// Check if fragmented
				buffer.position(currentOffset + 2);
				int fragInfo = buffer.getShortBE() & 0xFFFF;
				if ((fragInfo & 0x0001) != 0 || (fragInfo & 0xFFF8) != 0) {
					// More fragments or fragment offset != 0
					setLastProtocolFragment(true);
				}
			}

			totalLength += extLen;
			currentOffset += extLen;
			nextHeader = extNextHeader;
		}

		addProtocol(ProtocolId.IPv6, offset, totalLength, 0);

		lastIpProtocol = nextHeader;
		lastIpOffset = offset;
		lastIpHeaderLen = totalLength;

		return offset + totalLength;
	}

	private boolean isIPv6Extension(int nextHeader) {
		return switch (nextHeader) {
		case 0 -> true; // Hop-by-Hop
		case 43 -> true; // Routing
		case 44 -> true; // Fragment
		case 50 -> false; // ESP - handled separately
		case 51 -> false; // AH - handled separately
		case 60 -> true; // Destination Options
		case 135 -> true; // Mobility
		case 139 -> true; // HIP
		case 140 -> true; // Shim6
		default -> false;
		};
	}

	private int dissectARP(ByteBuf buffer, int offset) {
		if (offset + 28 > captureLength)
			return offset;

		addProtocol(ProtocolId.ARP, offset, 28, 0);
		return offset + 28;
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Layer 4 / IPsec Dissection
	// ═══════════════════════════════════════════════════════════════════════

	private void dissectTransportOrIpsec(ByteBuf buffer, int offset) {
		switch (lastIpProtocol) {
		case IpProto.TCP -> dissectTcp(buffer, offset);
		case IpProto.UDP -> dissectUdp(buffer, offset);
		case IpProto.ICMPV4 -> dissectIcmp(buffer, offset);
		case IpProto.ICMPV6 -> dissectIcmpv6(buffer, offset);
		case IpProto.AH -> dissectIpsecAh(buffer, offset);
		case IpProto.ESP -> dissectIpsecEsp(buffer, offset);
		}
	}

	private void dissectTcp(ByteBuf buffer, int offset) {
		if (offset + 20 > captureLength)
			return;

		buffer.position(offset + 12);
		int dataOffset = (buffer.get() >> 4) & 0x0F;
		int tcpLen = dataOffset * 4;

		if (tcpLen < 20)
			tcpLen = 20;
		if (offset + tcpLen > captureLength)
			tcpLen = captureLength - offset;

		addProtocol(ProtocolId.TCP, offset, tcpLen, 0);
	}

	private void dissectUdp(ByteBuf buffer, int offset) {
		if (offset + 8 > captureLength)
			return;

		addProtocol(ProtocolId.UDP, offset, 8, 0);
	}

	private void dissectIcmp(ByteBuf buffer, int offset) {
		if (offset + 8 > captureLength)
			return;

		// ICMP header is at least 8 bytes, but message can be longer
		// For now, record just the header
		addProtocol(ProtocolId.ICMP, offset, 8, 0);
	}

	private void dissectIcmpv6(ByteBuf buffer, int offset) {
		if (offset + 8 > captureLength)
			return;

		addProtocol(ProtocolId.ICMPv6, offset, 8, 0);
	}

	private void dissectIpsecAh(ByteBuf buffer, int offset) {
		if (offset + 12 > captureLength)
			return;

		buffer.position(offset + 1);
		int payloadLen = buffer.get() & 0xFF;
		int ahLen = (payloadLen + 2) * 4;

		if (offset + ahLen > captureLength) {
			addProtocol(ProtocolId.AH, offset, 12, 0);
			return;
		}

		addProtocol(ProtocolId.AH, offset, ahLen, 0);

		// Get next header and continue dissection
		buffer.position(offset);
		int nextHeader = buffer.get() & 0xFF;
		lastIpProtocol = nextHeader;

		int nextOffset = offset + ahLen;
		if (nextOffset < captureLength) {
			dissectTransportOrIpsec(buffer, nextOffset);
		}
	}

	private void dissectIpsecEsp(ByteBuf buffer, int offset) {
		if (offset + 8 > captureLength)
			return;

		// ESP header is 8 bytes, but payload is encrypted
		// We can only record the header, cannot parse further
		addProtocol(IpProto.ESP, offset, 8, 0);

		// Note: Cannot continue dissection - payload is encrypted
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Table Preparation
	// ═══════════════════════════════════════════════════════════════════════

	private void prepareTableEntries() {
		extendedIndex = 0;

		for (int i = 0; i < protocolCount; i++) {
			long entry = buildProtocolEntry(i);
			int inlineSlot = getInlineSlot(protocolIds[i]);

			if (inlineSlot >= 0 && !inlineUsed[inlineSlot]) {
				inlineEntries[inlineSlot] = entry;
				inlineUsed[inlineSlot] = true;
			} else {
				extendedEntries[extendedIndex++] = entry;
			}
		}
	}

	private long buildProtocolEntry(int idx) {
		long entry = protocolIds[idx] & PROTOCOL_ID_MASK;
		entry |= ((long) (protocolOffsets[idx] & HEADER_OFFSET_MASK)) << HEADER_OFFSET_SHIFT;
		entry |= ((long) (protocolExtendedLengths[idx] & EXTENDED_LENGTH_MASK)) << EXTENDED_LENGTH_SHIFT;
		entry |= ((long) (protocolEncounterOrder[idx] & ENCOUNTER_ORDER_MASK)) << ENCOUNTER_ORDER_SHIFT;
		entry |= ((long) (protocolInstances[idx] & INSTANCE_NUM_MASK)) << INSTANCE_NUM_SHIFT;

		if (protocolIsFragment[idx])
			entry |= IS_FRAGMENT_BIT;
		if (protocolIsTunneled[idx])
			entry |= IS_TUNNELED_BIT;
		if (protocolHasError[idx])
			entry |= HAS_ERRORS_BIT;

		return entry;
	}

	private int getInlineSlot(int protocolId) {
		return switch (protocolId) {
		case ProtocolId.ETHERNET -> INLINE_ETHERNET;
		case ProtocolId.VLAN -> INLINE_VLAN;
		case ProtocolId.IPv4 -> INLINE_IPV4;
		case ProtocolId.IPv6 -> INLINE_IPV6;
		case ProtocolId.TCP -> INLINE_TCP;
		case ProtocolId.UDP -> INLINE_UDP;
		case ProtocolId.ICMP, ProtocolId.ICMPv6 -> INLINE_ICMP;
		case ProtocolId.ARP -> INLINE_ARP;
		default -> -1; // MPLS, IPsec go to extended table
		};
	}

	private int getProtocolBitPosition(int protocolId) {
		return switch (protocolId) {
		case ProtocolId.ETHERNET -> 0;
		case ProtocolId.VLAN -> 1;
		case ProtocolId.IPv4 -> 2;
		case ProtocolId.IPv6 -> 3;
		case ProtocolId.TCP -> 4;
		case ProtocolId.UDP -> 5;
		case ProtocolId.ICMP, ProtocolId.ICMPv6 -> 6;
		case ProtocolId.ARP -> 7;
		// Extended bitmap positions (8+)
		case ProtocolId.MPLS -> 8;
		case ProtocolId.AH -> 9;
		case ProtocolId.ESP -> 10;
		default -> -1;
		};
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Accessors and Utilities
	// ═══════════════════════════════════════════════════════════════════════

	@Override
	public TimestampUnit timestampUnit() {
		return timestampUnit;
	}

	@Override
	public Net3PacketDissector setTimestampUnit(TimestampUnit timestampUnit) {
		this.timestampUnit = timestampUnit;
		return this;
	}

	@Override
	public int dissectPacket(Memory packet, long timestamp, int caplen, int wirelen) {
		internalView.bind(packet);
		return dissectPacket(internalView, timestamp, caplen, wirelen);
	}

	@Override
	public StructFormat format(StructFormat p) {
		p.openln("=== Net3PacketDissector State ===");
		p.println("timestamp", timestamp);
		p.println("captureLength", captureLength);
		p.println("wireLength", wireLength);
		p.println("protocolCount", protocolCount);
		p.println("vlanCount", vlanCount);
		p.println("mplsCount", mplsCount);
		p.println("extendedSize", extendedIndex);
		p.println("protoBitmap", String.format("0x%016X", protoBitmap));

		p.println("=== Inline Table ===");
		String[] slotNames = {
				"Ethernet",
				"VLAN",
				"IPv4",
				"IPv6",
				"TCP",
				"UDP",
				"ICMP",
				"ARP"
		};

		for (int i = 0; i < 8; i++) {
			if (inlineUsed[i] && inlineEntries[i] != 0) {
				long entry = inlineEntries[i];
				int offset = (int) ((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
				int length = (int) ((entry >> EXTENDED_LENGTH_SHIFT) & EXTENDED_LENGTH_MASK);
				int order = (int) ((entry >> ENCOUNTER_ORDER_SHIFT) & ENCOUNTER_ORDER_MASK);

				p.println(String.format("  [%d] %s: offset=%d, length=%d, order=%d",
						i, slotNames[i], offset, length, order));
			}
		}

		if (extendedIndex > 0) {
			p.println("=== Extended Table ===");
			for (int i = 0; i < extendedIndex; i++) {
				long entry = extendedEntries[i];
				int id = (int) (entry & PROTOCOL_ID_MASK);
				int offset = (int) ((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
				int length = (int) ((entry >> EXTENDED_LENGTH_SHIFT) & EXTENDED_LENGTH_MASK);
				int instance = (int) ((entry >> INSTANCE_NUM_SHIFT) & INSTANCE_NUM_MASK);

				p.println(String.format("  [%d] %s: offset=%d, length=%d, instance=%d",
						i, ProtocolId.nameOf(id), offset, length, instance));
			}
		}

		return p;
	}

	@Override
	public String toString() {
		return format(new StructFormat()).toString();
	}
}