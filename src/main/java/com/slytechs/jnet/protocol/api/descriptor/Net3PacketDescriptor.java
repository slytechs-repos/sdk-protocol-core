/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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
package com.slytechs.jnet.protocol.api.descriptor;

import static com.slytechs.jnet.core.api.memory.MemoryStructure.*;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;

import com.slytechs.jnet.core.api.format.StructFormat;
import com.slytechs.jnet.core.api.format.StructFormattable;
import com.slytechs.jnet.core.api.memory.ByteBuf;
import com.slytechs.jnet.core.api.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.Header;
import com.slytechs.jnet.protocol.api.builtin.L2FrameType;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * Net3 Packet Descriptor - Optimized protocol dissection with inline table.
 * 
 * <p>
 * This descriptor stores protocol dissection results with O(1) access for
 * 8 common protocols via an inline table, plus extended table support.
 * Options/extensions are parsed by headers themselves, not stored here.
 * </p>
 * 
 * <h2>Memory Layout (96 bytes)</h2>
 * <ul>
 * <li>0x00-0x0F: NetPacketDescriptor base (16 bytes)</li>
 * <li>0x10: proto_bitmap (8 bytes) - fast presence check</li>
 * <li>0x18: proto_counts (2 bytes) - protocol/VLAN/MPLS counts</li>
 * <li>0x1A: extended_offset (2 bytes)</li>
 * <li>0x1C: extended_size (2 bytes)</li>
 * <li>0x1E: reserved (2 bytes)</li>
 * <li>0x20-0x5F: inline_table[8] (64 bytes)</li>
 * </ul>
 * 
 * <h2>Protocol Entry Format (64 bits)</h2>
 * <ul>
 * <li>Bits 0-15: Protocol ID</li>
 * <li>Bits 16-31: Header offset (16 bits)</li>
 * <li>Bits 32-47: Extended length (16 bits)</li>
 * <li>Bits 48-55: Encounter order (8 bits)</li>
 * <li>Bits 56-58: Instance number (3 bits)</li>
 * <li>Bit 59: Fragment flag</li>
 * <li>Bit 60: Tunneled flag</li>
 * <li>Bit 61: Error flag</li>
 * <li>Bits 62-63: Reserved</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class Net3PacketDescriptor
		extends NetPacketDescriptor
		implements PacketDescriptor, StructFormattable {

	// Memory Layout
	public static final MemoryLayout LAYOUT = structLayout(
			NetPacketDescriptor.LAYOUT.withName("net_base"),     // 16 bytes
			U64.withName("proto_bitmap"),                         // 8 bytes
			U16.withName("proto_counts"),                         // 2 bytes - packed counts
			U16.withName("extended_offset"),                      // 2 bytes
			U16.withName("extended_size"),                        // 2 bytes
			U16.withName("reserved"),                             // 2 bytes
			sequenceLayout(8, U64).withName("inline_table")       // 64 bytes
	);

	// VarHandles
	private static final VarHandle PROTO_BITMAP = LAYOUT.varHandle(groupElement("proto_bitmap"));
	private static final VarHandle PROTO_COUNTS = LAYOUT.varHandle(groupElement("proto_counts"));
	private static final VarHandle EXTENDED_OFFSET = LAYOUT.varHandle(groupElement("extended_offset"));
	private static final VarHandle EXTENDED_SIZE = LAYOUT.varHandle(groupElement("extended_size"));
	private static final VarHandle INLINE_TABLE = LAYOUT.varHandle(
			groupElement("inline_table"),
			sequenceElement());

	// Protocol entry bit layout (64 bits)
	private static final long PROTOCOL_ID_MASK = 0xFFFFL;           // Bits 0-15
	private static final int HEADER_OFFSET_SHIFT = 16;
	private static final int HEADER_OFFSET_MASK = 0xFFFF;           // Bits 16-31 (16 bits)
	private static final int EXTENDED_LENGTH_SHIFT = 32;
	private static final int EXTENDED_LENGTH_MASK = 0xFFFF;         // Bits 32-47 (16 bits)
	private static final int ENCOUNTER_ORDER_SHIFT = 48;
	private static final int ENCOUNTER_ORDER_MASK = 0xFF;           // Bits 48-55 (8 bits)
	private static final int INSTANCE_NUM_SHIFT = 56;
	private static final int INSTANCE_NUM_MASK = 0x7;               // Bits 56-58 (3 bits)
	private static final long IS_FRAGMENT_BIT = 1L << 59;           // Bit 59
	private static final long IS_TUNNELED_BIT = 1L << 60;           // Bit 60
	private static final long HAS_ERRORS_BIT = 1L << 61;            // Bit 61
	// Bits 62-63 reserved

	// Proto counts bit layout (16 bits)
	private static final int PROTOCOL_COUNT_MASK = 0xFF;            // Bits 0-7 (8 bits)
	private static final int VLAN_COUNT_SHIFT = 8;
	private static final int VLAN_COUNT_MASK = 0xF;                 // Bits 8-11 (4 bits)
	private static final int MPLS_COUNT_SHIFT = 12;
	private static final int MPLS_COUNT_MASK = 0xF;                 // Bits 12-15 (4 bits)

	// Inline table slots
	private static final int INLINE_ETHERNET = 0;
	private static final int INLINE_VLAN = 1;
	private static final int INLINE_IPV4 = 2;
	private static final int INLINE_IPV6 = 3;
	private static final int INLINE_TCP = 4;
	private static final int INLINE_UDP = 5;
	private static final int INLINE_ICMP = 6;
	private static final int INLINE_ARP = 7;
	private static final int INLINE_TABLE_SIZE = 8;

	// Common protocol IDs
	private static final int PROTO_ID_ETHERNET = 0x0201;
	private static final int PROTO_ID_VLAN = 0x0209;
	private static final int PROTO_ID_IPV4 = 0x0215;
	private static final int PROTO_ID_IPV6 = 0x0216;
	private static final int PROTO_ID_TCP = 0x021E;
	private static final int PROTO_ID_UDP = 0x021F;
	private static final int PROTO_ID_ICMP = 0x0220;
	private static final int PROTO_ID_ARP = 0x0203;

	// Extended table tracking
	private int extendedIndex = 0;
	private int encounterOrder = 0;

	/**
	 * Creates a Net3PacketDescriptor with specified timestamp unit.
	 */
	public Net3PacketDescriptor(TimestampUnit unit) {
		super(unit);
	}

	/**
	 * Creates a Net3PacketDescriptor with L2 type and timestamp unit.
	 */
	public Net3PacketDescriptor(L2FrameType l2Type, TimestampUnit unit) {
		super(l2Type, unit);
	}

	/**
	 * Adds a protocol entry.
	 * 
	 * @param protocolId protocol ID
	 * @param offset header offset in packet
	 * @param extendedLength total length including options/extensions
	 */
	public void addProtocol(int protocolId, int offset, int extendedLength) {
		addProtocolInstance(protocolId, offset, extendedLength, 0);
	}

	/**
	 * Adds a protocol with instance number.
	 * 
	 * @param protocolId protocol ID
	 * @param offset header offset
	 * @param extendedLength total length including options/extensions
	 * @param instanceNum instance number (0-7)
	 */
	public void addProtocolInstance(int protocolId, int offset, int extendedLength, int instanceNum) {
		// Build protocol entry
		long entry = buildProtocolEntry(protocolId, offset, extendedLength, 
				encounterOrder++, instanceNum, false, false, false);
		
		// Check if inline protocol
		int inlineSlot = getInlineSlot(protocolId);
		
		if (inlineSlot >= 0) {
			// Store in inline table
			INLINE_TABLE.set(segment(), view().start(), inlineSlot, entry);
		} else {
			// Store in extended table
			writeProtocolToExtended(entry);
		}
		
		// Update counts and bitmap
		incrementProtocolCount();
		updateBitmap(protocolId);
		
		// Track VLAN/MPLS
		if (protocolId == PROTO_ID_VLAN) {
			incrementVlanCount();
		}
		// Add MPLS protocol ID check when needed
	}

	/**
	 * Builds a protocol entry.
	 */
	private long buildProtocolEntry(int protocolId, int offset, int extendedLength,
			int encounterOrder, int instanceNum, boolean isFragment, 
			boolean isTunneled, boolean hasError) {
		long entry = protocolId & PROTOCOL_ID_MASK;
		entry |= ((long)(offset & HEADER_OFFSET_MASK)) << HEADER_OFFSET_SHIFT;
		entry |= ((long)(extendedLength & EXTENDED_LENGTH_MASK)) << EXTENDED_LENGTH_SHIFT;
		entry |= ((long)(encounterOrder & ENCOUNTER_ORDER_MASK)) << ENCOUNTER_ORDER_SHIFT;
		entry |= ((long)(instanceNum & INSTANCE_NUM_MASK)) << INSTANCE_NUM_SHIFT;
		if (isFragment) entry |= IS_FRAGMENT_BIT;
		if (isTunneled) entry |= IS_TUNNELED_BIT;
		if (hasError) entry |= HAS_ERRORS_BIT;
		return entry;
	}

	/**
	 * Writes protocol to extended table.
	 */
	private void writeProtocolToExtended(long protocolEntry) {
		MemorySegment extended = getExtendedSegment();
		extended.set(ValueLayout.JAVA_LONG, extendedIndex * 8, protocolEntry);
		extendedIndex++;
		setExtendedSize((short) extendedIndex);
	}

	/**
	 * Gets inline slot for protocol.
	 */
	private int getInlineSlot(int protocolId) {
		return switch (protocolId & 0xFFFF) {
			case PROTO_ID_ETHERNET -> INLINE_ETHERNET;
			case PROTO_ID_VLAN -> INLINE_VLAN;
			case PROTO_ID_IPV4 -> INLINE_IPV4;
			case PROTO_ID_IPV6 -> INLINE_IPV6;
			case PROTO_ID_TCP -> INLINE_TCP;
			case PROTO_ID_UDP -> INLINE_UDP;
			case PROTO_ID_ICMP -> INLINE_ICMP;
			case PROTO_ID_ARP -> INLINE_ARP;
			default -> -1;
		};
	}

	// Protocol count management
	private void incrementProtocolCount() {
		int counts = getProtoCounts();
		int protoCount = (counts & PROTOCOL_COUNT_MASK) + 1;
		counts = (counts & ~PROTOCOL_COUNT_MASK) | (protoCount & PROTOCOL_COUNT_MASK);
		setProtoCounts(counts);
	}

	private void incrementVlanCount() {
		int counts = getProtoCounts();
		int vlanCount = ((counts >> VLAN_COUNT_SHIFT) & VLAN_COUNT_MASK) + 1;
		counts = (counts & ~(VLAN_COUNT_MASK << VLAN_COUNT_SHIFT)) | 
				((vlanCount & VLAN_COUNT_MASK) << VLAN_COUNT_SHIFT);
		setProtoCounts(counts);
	}

	public int getProtocolCount() {
		return getProtoCounts() & PROTOCOL_COUNT_MASK;
	}

	public int getVlanCount() {
		return (getProtoCounts() >> VLAN_COUNT_SHIFT) & VLAN_COUNT_MASK;
	}

	public int getMplsCount() {
		return (getProtoCounts() >> MPLS_COUNT_SHIFT) & MPLS_COUNT_MASK;
	}

	// Clear all protocols
	public void clearProtocols() {
		// Clear inline table
		MemorySegment base = segment();
		long baseOffset = view().start();
		for (int i = 0; i < INLINE_TABLE_SIZE; i++) {
			INLINE_TABLE.set(base, baseOffset, i, 0L);
		}
		
		setProtoBitmap(0L);
		setProtoCounts(0);
		setExtendedOffset((short) 0);
		setExtendedSize((short) 0);
		extendedIndex = 0;
		encounterOrder = 0;
	}

	@Override
	public boolean bindProtocol(ByteBuf packet, Header header, int protocolId, int depth) {
		// Check inline table first
		int inlineSlot = getInlineSlot(protocolId);
		
		if (inlineSlot >= 0 && depth == 0) {
			long entry = (long) INLINE_TABLE.get(segment(), view().start(), inlineSlot);
			if (entry != 0) {
				int offset = (int)((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
				int extendedLength = (int)((entry >> EXTENDED_LENGTH_SHIFT) & EXTENDED_LENGTH_MASK);
				return header.bindHeader(packet, protocolId, depth, offset, extendedLength);
			}
		}
		
		// Search extended table
		if (getExtendedSize() > 0) {
			MemorySegment extended = getExtendedSegment();
			int matchCount = 0;
			
			for (int i = 0; i < getExtendedSize(); i++) {
				long entry = extended.get(ValueLayout.JAVA_LONG, i * 8);
				
				if ((entry & PROTOCOL_ID_MASK) == protocolId) {
					int instance = (int)((entry >> INSTANCE_NUM_SHIFT) & INSTANCE_NUM_MASK);
					if (instance == depth || matchCount == depth) {
						int offset = (int)((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
						int extendedLength = (int)((entry >> EXTENDED_LENGTH_SHIFT) & EXTENDED_LENGTH_MASK);
						return header.bindHeader(packet, protocolId, depth, offset, extendedLength);
					}
					matchCount++;
				}
			}
		}
		
		return super.bindProtocol(packet, header, protocolId, depth);
	}

	@Override
	public long mapProtocol(int protocolId, int depth) {
		// Fast path for common protocols at depth 0
		if (depth == 0) {
			int inlineSlot = getInlineSlot(protocolId);
			if (inlineSlot >= 0) {
				long entry = (long) INLINE_TABLE.get(segment(), view().start(), inlineSlot);
				if (entry != 0) {
					int offset = (int)((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
					int length = (int)((entry >> EXTENDED_LENGTH_SHIFT) & EXTENDED_LENGTH_MASK);
					return PacketDescriptor.encodeLengthAndOffset(offset, length);
				}
			}
		}
		
		// Search extended table
		return mapProtocolSearch(protocolId, depth);
	}

	private long mapProtocolSearch(int protocolId, int depth) {
		if (getExtendedSize() > 0) {
			MemorySegment extended = getExtendedSegment();
			int matchCount = 0;
			
			for (int i = 0; i < getExtendedSize(); i++) {
				long entry = extended.get(ValueLayout.JAVA_LONG, i * 8);
				
				if ((entry & PROTOCOL_ID_MASK) == protocolId) {
					int instance = (int)((entry >> INSTANCE_NUM_SHIFT) & INSTANCE_NUM_MASK);
					if (instance == depth || matchCount == depth) {
						int offset = (int)((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
						int length = (int)((entry >> EXTENDED_LENGTH_SHIFT) & EXTENDED_LENGTH_MASK);
						return PacketDescriptor.encodeLengthAndOffset(offset, length);
					}
					matchCount++;
				}
			}
		}
		
		return super.mapProtocol(protocolId, depth);
	}

	// Fast presence checks
	public boolean hasEthernet() {
		long entry = (long) INLINE_TABLE.get(segment(), view().start(), INLINE_ETHERNET);
		return entry != 0;
	}

	public boolean hasIpv4() {
		long entry = (long) INLINE_TABLE.get(segment(), view().start(), INLINE_IPV4);
		return entry != 0;
	}

	public boolean hasIpv6() {
		long entry = (long) INLINE_TABLE.get(segment(), view().start(), INLINE_IPV6);
		return entry != 0;
	}

	public boolean hasTcp() {
		long entry = (long) INLINE_TABLE.get(segment(), view().start(), INLINE_TCP);
		return entry != 0;
	}

	public boolean hasUdp() {
		long entry = (long) INLINE_TABLE.get(segment(), view().start(), INLINE_UDP);
		return entry != 0;
	}

	// Field accessors
	private long getProtoBitmap() {
		return (long) PROTO_BITMAP.get(segment(), view().start());
	}

	private void setProtoBitmap(long bitmap) {
		PROTO_BITMAP.set(segment(), view().start(), bitmap);
	}

	private int getProtoCounts() {
		return (short) PROTO_COUNTS.get(segment(), view().start()) & 0xFFFF;
	}

	private void setProtoCounts(int counts) {
		PROTO_COUNTS.set(segment(), view().start(), (short)(counts & 0xFFFF));
	}

	private short getExtendedOffset() {
		return (short) EXTENDED_OFFSET.get(segment(), view().start());
	}

	private void setExtendedOffset(short offset) {
		EXTENDED_OFFSET.set(segment(), view().start(), offset);
	}

	private short getExtendedSize() {
		return (short) EXTENDED_SIZE.get(segment(), view().start());
	}

	private void setExtendedSize(short size) {
		EXTENDED_SIZE.set(segment(), view().start(), size);
	}

	private MemorySegment getExtendedSegment() {
		int offset = captureLength() + getExtendedOffset();
		return segment().asSlice(offset);
	}

	private void updateBitmap(int protocolId) {
		int bitPos = getBitmapPosition(protocolId);
		if (bitPos >= 0) {
			long bitmap = getProtoBitmap();
			bitmap |= (1L << bitPos);
			setProtoBitmap(bitmap);
		}
	}

	private int getBitmapPosition(int protocolId) {
		return switch (protocolId & 0xFFFF) {
			case PROTO_ID_ETHERNET -> 0;
			case PROTO_ID_VLAN -> 1;
			case PROTO_ID_IPV4 -> 2;
			case PROTO_ID_IPV6 -> 3;
			case PROTO_ID_TCP -> 4;
			case PROTO_ID_UDP -> 5;
			case PROTO_ID_ICMP -> 6;
			case PROTO_ID_ARP -> 7;
			default -> -1;
		};
	}

	@Override
	public long length() {
		return LAYOUT.byteSize();
	}

	@Override
	public DescriptorType type() {
		return DescriptorType.DESCRIPTOR_TYPE_NET3;
	}

	@Override
	public int descriptorId() {
		return DescriptorType.DESCRIPTOR_TYPE_NET3.getValue();
	}

	@Override
	public StructFormat format(StructFormat p) {
		p = p.openln("Net3PacketDescriptor").indent();
		
		p = super.format(p);
		
		p = p.println("=== Protocol Dissection ===")
			.println("protocolCount", getProtocolCount())
			.println("vlanCount", getVlanCount())
			.println("mplsCount", getMplsCount())
			.println("extendedSize", getExtendedSize())
			.println("protoBitmap", String.format("0x%016X", getProtoBitmap()));
		
		// Display inline table
		p.println("=== Inline Table ===");
		String[] slotNames = {"Ethernet", "VLAN", "IPv4", "IPv6", "TCP", "UDP", "ICMP", "ARP"};
		
		for (int i = 0; i < INLINE_TABLE_SIZE; i++) {
			long entry = (long) INLINE_TABLE.get(segment(), view().start(), i);
			if (entry != 0) {
				int offset = (int)((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
				int length = (int)((entry >> EXTENDED_LENGTH_SHIFT) & EXTENDED_LENGTH_MASK);
				int order = (int)((entry >> ENCOUNTER_ORDER_SHIFT) & ENCOUNTER_ORDER_MASK);
				
				p.println(String.format("  [%d] %s: offset=%d, length=%d, order=%d",
						i, slotNames[i], offset, length, order));
			}
		}
		
		return p.close();
	}
}