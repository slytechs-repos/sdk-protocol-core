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
package com.slytechs.jnet.protocol.api.dissector;

import static com.slytechs.jnet.protocol.api.ProtocolIds.*;

import java.lang.foreign.MemoryLayout;

import com.slytechs.jnet.core.api.format.StructFormat;
import com.slytechs.jnet.core.api.format.StructFormattable;
import com.slytechs.jnet.core.api.memory.ByteBuf;
import com.slytechs.jnet.core.api.memory.Memory;
import com.slytechs.jnet.core.api.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.descriptor.Net3PacketDescriptor;

/**
 * Zero-allocation dissector for Net3PacketDescriptor.
 * 
 * <p>
 * High-performance dissector that parses packet headers and stores results
 * in a compact descriptor format. Headers parse their own options/extensions;
 * the dissector only records offset and extended length (total including
 * options).
 * </p>
 * 
 * <h2>Supported Protocols</h2>
 * <ul>
 * <li><b>Layer 2:</b> Ethernet II, IEEE 802.3 (LLC/SNAP), VLAN (802.1Q/QinQ), MPLS</li>
 * <li><b>Layer 3:</b> IPv4, IPv6 (with extensions), ARP, IPsec (AH/ESP)</li>
 * <li><b>Layer 4:</b> TCP, UDP, ICMP, ICMPv6</li>
 * </ul>
 * 
 * <h2>Inline Table (8 slots)</h2>
 * <p>
 * Common protocols get O(1) lookup via inline slots:
 * </p>
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
public class Net3PacketDissector implements PacketDissector, StructFormattable {

	public static final MemoryLayout LAYOUT = Net3PacketDescriptor.LAYOUT;

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
	private long timestamp;
	private int captureLength;
	private int wireLength;
	private TimestampUnit timestampUnit = TimestampUnit.EPOCH_NANO;
	private final ByteBuf internalView = new ByteBuf();

	// RX/TX flags
	private int rxFlags = 0;
	private int txFlags = 0;

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

	@Override
	public int dissectPacket(ByteBuf buffer, long timestamp, int caplen, int wirelen) {
		recycle();

		this.timestamp = timestamp;
		this.captureLength = caplen;
		this.wireLength = wirelen;

		buffer.position(0);
		buffer.limit(caplen);

		// Dissect Layer 2
		int nextProto = dissectEthernet(buffer, 0);
		int offset = 14;

		// Handle VLAN tags
		while ((nextProto == ETHER_TYPE_VLAN || nextProto == ETHER_TYPE_QINQ) && offset + 4 <= caplen) {
			offset = dissectVlan(buffer, offset, vlanCount);
			vlanCount++;
			buffer.position(offset - 2);
			nextProto = buffer.getShortBE() & 0xFFFF;
		}

		// Handle MPLS labels
		if (nextProto == ETHER_TYPE_MPLS || nextProto == ETHER_TYPE_MPLS_MC) {
			offset = dissectMpls(buffer, offset);
			// After MPLS, peek at first nibble to determine IP version
			if (offset < caplen) {
				buffer.position(offset);
				int version = (buffer.get() >> 4) & 0x0F;
				nextProto = (version == 4) ? ETHER_TYPE_IPV4 : 
				            (version == 6) ? ETHER_TYPE_IPV6 : 0;
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

	@Override
	public void recycle() {
		protocolCount = 0;
		vlanCount = 0;
		mplsCount = 0;
		encounterOrder = 0;
		protoBitmap = 0;
		extendedIndex = 0;
		rxFlags = 0;
		txFlags = 0;
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
		
		// NetPacketDescriptor base (16 bytes)
		buffer.putLong(timestamp);
		buffer.putShort((short) captureLength);
		buffer.putShort((short) rxFlags);
		buffer.putShort((short) wireLength);
		buffer.putShort((short) txFlags);

		// Net3 extensions
		buffer.putLong(protoBitmap);

		int protoCounts = (protocolCount & PROTOCOL_COUNT_MASK) |
				((vlanCount & VLAN_COUNT_MASK) << VLAN_COUNT_SHIFT) |
				((mplsCount & MPLS_COUNT_MASK) << MPLS_COUNT_SHIFT);
		buffer.putShort((short) protoCounts);

		buffer.putShort((short) 0);  // extended offset (updated below if needed)
		buffer.putShort((short) extendedIndex);
		buffer.putShort((short) 0);  // reserved

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
		if (protocolCount >= MAX_PROTOCOLS) return;

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
		if (offset + 14 > captureLength) return 0;

		buffer.position(offset + 12);
		int etherType = buffer.getShortBE() & 0xFFFF;

		if (etherType <= IEEE_802_3_MAX_LENGTH) {
			// IEEE 802.3 with LLC/SNAP
			if (offset + 17 > captureLength) {
				addProtocol(PROTO_ID_ETHERNET, offset, 14, 0);
				return 0;
			}

			buffer.position(offset + 14);
			byte dsap = buffer.get();
			byte ssap = buffer.get();

			if (dsap == (byte) 0xAA && ssap == (byte) 0xAA) {
				// SNAP: LLC (3) + OUI (3) + Type (2) = 8 bytes
				if (offset + 22 > captureLength) {
					addProtocol(PROTO_ID_ETHERNET, offset, 17, 0);
					return 0;
				}
				buffer.position(offset + 20);
				etherType = buffer.getShortBE() & 0xFFFF;
				addProtocol(PROTO_ID_ETHERNET, offset, 22, 0);
			} else {
				// Just LLC
				addProtocol(PROTO_ID_ETHERNET, offset, 17, 0);
				return 0; // No EtherType, can't continue
			}
		} else {
			// Ethernet II
			addProtocol(PROTO_ID_ETHERNET, offset, 14, 0);
		}

		return etherType;
	}

	private int dissectVlan(ByteBuf buffer, int offset, int instance) {
		if (offset + 4 > captureLength) return offset;
		
		addProtocol(PROTO_ID_VLAN, offset, 4, instance);
		return offset + 4;
	}

	private int dissectMpls(ByteBuf buffer, int offset) {
		// Parse MPLS label stack until bottom-of-stack bit
		while (offset + 4 <= captureLength) {
			buffer.position(offset);
			int labelEntry = buffer.getIntBE();
			
			addProtocol(PROTO_ID_MPLS, offset, 4, mplsCount);
			mplsCount++;
			offset += 4;

			// Check bottom-of-stack bit (bit 8, counting from LSB)
			if ((labelEntry & 0x100) != 0) {
				break;
			}

			// Safety: max 8 labels
			if (mplsCount >= 8) break;
		}
		return offset;
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Layer 3 Dissection
	// ═══════════════════════════════════════════════════════════════════════

	private int dissectIPv4(ByteBuf buffer, int offset) {
		if (offset + 20 > captureLength) return offset;

		buffer.position(offset);
		byte verIhl = buffer.get();
		int headerLen = (verIhl & 0x0F) * 4;

		if (offset + headerLen > captureLength) {
			addProtocol(PROTO_ID_IPV4, offset, 20, 0);
			return offset + 20;
		}

		addProtocol(PROTO_ID_IPV4, offset, headerLen, 0);

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
		if (offset + 40 > captureLength) return offset;

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

		addProtocol(PROTO_ID_IPV6, offset, totalLength, 0);

		lastIpProtocol = nextHeader;
		lastIpOffset = offset;
		lastIpHeaderLen = totalLength;

		return offset + totalLength;
	}

	private boolean isIPv6Extension(int nextHeader) {
		return switch (nextHeader) {
			case 0 -> true;   // Hop-by-Hop
			case 43 -> true;  // Routing
			case 44 -> true;  // Fragment
			case 50 -> false; // ESP - handled separately
			case 51 -> false; // AH - handled separately
			case 60 -> true;  // Destination Options
			case 135 -> true; // Mobility
			case 139 -> true; // HIP
			case 140 -> true; // Shim6
			default -> false;
		};
	}

	private int dissectARP(ByteBuf buffer, int offset) {
		if (offset + 28 > captureLength) return offset;
		
		addProtocol(PROTO_ID_ARP, offset, 28, 0);
		return offset + 28;
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Layer 4 / IPsec Dissection
	// ═══════════════════════════════════════════════════════════════════════

	private void dissectTransportOrIpsec(ByteBuf buffer, int offset) {
		switch (lastIpProtocol) {
			case IP_PROTO_TCP -> dissectTcp(buffer, offset);
			case IP_PROTO_UDP -> dissectUdp(buffer, offset);
			case IP_PROTO_ICMP -> dissectIcmp(buffer, offset);
			case IP_PROTO_ICMPV6 -> dissectIcmpv6(buffer, offset);
			case IP_PROTO_AH -> dissectIpsecAh(buffer, offset);
			case IP_PROTO_ESP -> dissectIpsecEsp(buffer, offset);
		}
	}

	private void dissectTcp(ByteBuf buffer, int offset) {
		if (offset + 20 > captureLength) return;

		buffer.position(offset + 12);
		int dataOffset = (buffer.get() >> 4) & 0x0F;
		int tcpLen = dataOffset * 4;

		if (tcpLen < 20) tcpLen = 20;
		if (offset + tcpLen > captureLength) tcpLen = captureLength - offset;

		addProtocol(PROTO_ID_TCP, offset, tcpLen, 0);
	}

	private void dissectUdp(ByteBuf buffer, int offset) {
		if (offset + 8 > captureLength) return;
		
		addProtocol(PROTO_ID_UDP, offset, 8, 0);
	}

	private void dissectIcmp(ByteBuf buffer, int offset) {
		if (offset + 8 > captureLength) return;

		// ICMP header is at least 8 bytes, but message can be longer
		// For now, record just the header
		addProtocol(PROTO_ID_ICMP, offset, 8, 0);
	}

	private void dissectIcmpv6(ByteBuf buffer, int offset) {
		if (offset + 8 > captureLength) return;
		
		addProtocol(PROTO_ID_ICMPV6, offset, 8, 0);
	}

	private void dissectIpsecAh(ByteBuf buffer, int offset) {
		if (offset + 12 > captureLength) return;

		buffer.position(offset + 1);
		int payloadLen = buffer.get() & 0xFF;
		int ahLen = (payloadLen + 2) * 4;

		if (offset + ahLen > captureLength) {
			addProtocol(PROTO_ID_IPSEC_AH, offset, 12, 0);
			return;
		}

		addProtocol(PROTO_ID_IPSEC_AH, offset, ahLen, 0);

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
		if (offset + 8 > captureLength) return;

		// ESP header is 8 bytes, but payload is encrypted
		// We can only record the header, cannot parse further
		addProtocol(PROTO_ID_IPSEC_ESP, offset, 8, 0);
		
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

		if (protocolIsFragment[idx]) entry |= IS_FRAGMENT_BIT;
		if (protocolIsTunneled[idx]) entry |= IS_TUNNELED_BIT;
		if (protocolHasError[idx]) entry |= HAS_ERRORS_BIT;

		return entry;
	}

	private int getInlineSlot(int protocolId) {
		return switch (protocolId) {
			case PROTO_ID_ETHERNET -> INLINE_ETHERNET;
			case PROTO_ID_VLAN -> INLINE_VLAN;
			case PROTO_ID_IPV4 -> INLINE_IPV4;
			case PROTO_ID_IPV6 -> INLINE_IPV6;
			case PROTO_ID_TCP -> INLINE_TCP;
			case PROTO_ID_UDP -> INLINE_UDP;
			case PROTO_ID_ICMP, PROTO_ID_ICMPV6 -> INLINE_ICMP;
			case PROTO_ID_ARP -> INLINE_ARP;
			default -> -1;  // MPLS, IPsec go to extended table
		};
	}

	private int getProtocolBitPosition(int protocolId) {
		return switch (protocolId) {
			case PROTO_ID_ETHERNET -> 0;
			case PROTO_ID_VLAN -> 1;
			case PROTO_ID_IPV4 -> 2;
			case PROTO_ID_IPV6 -> 3;
			case PROTO_ID_TCP -> 4;
			case PROTO_ID_UDP -> 5;
			case PROTO_ID_ICMP, PROTO_ID_ICMPV6 -> 6;
			case PROTO_ID_ARP -> 7;
			// Extended bitmap positions (8+)
			case PROTO_ID_MPLS -> 8;
			case PROTO_ID_IPSEC_AH -> 9;
			case PROTO_ID_IPSEC_ESP -> 10;
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
		String[] slotNames = {"Ethernet", "VLAN", "IPv4", "IPv6", "TCP", "UDP", "ICMP", "ARP"};

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
						i, getProtocolName(id), offset, length, instance));
			}
		}

		return p;
	}

	private String getProtocolName(int protocolId) {
		return switch (protocolId) {
			case PROTO_ID_ETHERNET -> "Ethernet";
			case PROTO_ID_VLAN -> "VLAN";
			case PROTO_ID_MPLS -> "MPLS";
			case PROTO_ID_IPV4 -> "IPv4";
			case PROTO_ID_IPV6 -> "IPv6";
			case PROTO_ID_TCP -> "TCP";
			case PROTO_ID_UDP -> "UDP";
			case PROTO_ID_ICMP -> "ICMP";
			case PROTO_ID_ICMPV6 -> "ICMPv6";
			case PROTO_ID_ARP -> "ARP";
			case PROTO_ID_IPSEC_AH -> "IPsec-AH";
			case PROTO_ID_IPSEC_ESP -> "IPsec-ESP";
			default -> String.format("Unknown(0x%04X)", protocolId);
		};
	}

	@Override
	public String toString() {
		return format(new StructFormat()).toString();
	}
}