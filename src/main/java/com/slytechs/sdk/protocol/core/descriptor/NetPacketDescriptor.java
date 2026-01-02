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
package com.slytechs.sdk.protocol.core.descriptor;

import static com.slytechs.sdk.common.memory.MemoryStructure.*;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Iterator;

import com.slytechs.sdk.common.detail.DetailBuilder;
import com.slytechs.sdk.common.detail.Detailable;
import com.slytechs.sdk.common.detail.ExpertLevel;
import com.slytechs.sdk.common.format.StructFormat;
import com.slytechs.sdk.common.memory.BindableView;
import com.slytechs.sdk.common.memory.BoundView;
import com.slytechs.sdk.common.memory.MemoryHandle.LongHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.ShortHandle;
import com.slytechs.sdk.common.time.TimestampUnit;
import com.slytechs.sdk.protocol.core.Header;
import com.slytechs.sdk.protocol.core.ProtocolId;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * SDK Packet Descriptor with protocol dissection table.
 * 
 * <p>
 * This is the standard SDK descriptor that stores protocol dissection results
 * with O(1) access for 8 common protocols via an inline table, plus extended
 * table support. Includes RX/TX metadata for capture and transmission control.
 * </p>
 * 
 * <h2>Memory Layout (96 bytes)</h2>
 * 
 * <pre>
 * Offset  Size  Field            Description
 * -------------------------------------------------------
 * 0x00    8     timestamp        Capture timestamp
 * 0x08    2     caplen           Captured length
 * 0x0A    2     rx_info          RX metadata (port, l2type, ts_unit)
 * 0x0C    2     wirelen          Wire length
 * 0x0E    2     tx_info          TX metadata (port, flags)
 * 0x10    8     proto_bitmap     Fast protocol presence check
 * 0x18    2     proto_counts     Protocol/VLAN/MPLS counts
 * 0x1A    2     extended_offset  Offset to extended table
 * 0x1C    2     extended_size    Size of extended table
 * 0x1E    2     reserved         Reserved
 * 0x20    64    inline_table[8]  8 protocol entries (8 bytes each)
 * </pre>
 * 
 * <h2>RX_INFO Bit Layout (16 bits)</h2>
 * 
 * <pre>
 * Bits [15-10]: RX_PORT (6 bits) - Receive port number (0-63)
 * Bit [9]:      L2_EXTENSION - Has L2 extensions (VLAN, MPLS)
 * Bits [8-3]:   L2_FRAME_TYPE (6 bits) - Layer 2 frame type (0-63)
 * Bits [2-0]:   TIMESTAMP_UNIT (3 bits) - Timestamp unit encoding (0-7)
 * </pre>
 * 
 * <h2>TX_INFO Bit Layout (16 bits)</h2>
 * 
 * <pre>
 * Bits [15-8]: TX_PORT (8 bits) - Transmit port number (0-255)
 * Bit [7]:     TX_ENABLED - Packet should be transmitted
 * Bit [6]:     TX_IMMEDIATE - Transmit immediately  
 * Bit [5]:     TX_CRC_RECALC - Recalculate CRC on transmit
 * Bit [4]:     TX_TIMESTAMP_SYNC - Sync transmission with timestamp
 * Bits [3-0]:  Reserved
 * </pre>
 * 
 * <h2>Protocol Entry Format (64 bits)</h2>
 * 
 * <pre>
 * Bits [0-15]:  Protocol ID
 * Bits [16-31]: Header offset (16 bits)
 * Bits [32-47]: Header length (16 bits)
 * Bits [48-55]: Encounter order (8 bits)
 * Bits [56-58]: Instance number (3 bits)
 * Bit [59]:     Fragment flag
 * Bit [60]:     Tunneled flag
 * Bit [61]:     Error flag
 * Bits [62-63]: Reserved
 * </pre>
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public class NetPacketDescriptor
		extends AbstractPacketDescriptor
		implements RxCapabilities, TxCapabilities, Detailable, BindableView {

	// ========== Memory Layout (96 bytes) ==========

	public static final MemoryLayout LAYOUT = structLayout(
			// Base fields (16 bytes) - pcap compatible
			structLayout(
					U64.withName("timestamp"), // 0x00: 8 bytes
					U16.withName("caplen"), // 0x08: 2 bytes
					U16.withName("rx_info"), // 0x0A: 2 bytes
					U16.withName("wirelen"), // 0x0C: 2 bytes
					U16.withName("tx_info") // 0x0E: 2 bytes
			).withName("base"),

			// Protocol dissection fields (16 bytes)
			U64.withName("proto_bitmap"), // 0x10: 8 bytes
			U16.withName("proto_counts"), // 0x18: 2 bytes
			U16.withName("extended_offset"), // 0x1A: 2 bytes
			U16.withName("extended_size"), // 0x1C: 2 bytes
			U16.withName("reserved"), // 0x1E: 2 bytes

			// Inline protocol table (64 bytes)
			sequenceLayout(8, U64).withName("inline_table") // 0x20: 64 bytes
	);

	public static final int BYTE_SIZE = (int) LAYOUT.byteSize(); // 96 bytes

	/** Base layout (16 bytes) - pcap compatible, reusable by other descriptors */
	public static final MemoryLayout BASE_LAYOUT = LAYOUT.select(groupElement("base"));

	// ========== Type-safe Handles (JIT-inlinable) ==========

	// Base fields - using dot notation for nested struct
	private static final LongHandle TIMESTAMP = new LongHandle(LAYOUT, "base", "timestamp");
	private static final ShortHandle CAPLEN = new ShortHandle(LAYOUT, "base", "caplen");
	private static final ShortHandle RX_INFO = new ShortHandle(LAYOUT, "base", "rx_info");
	private static final ShortHandle WIRELEN = new ShortHandle(LAYOUT, "base", "wirelen");
	private static final ShortHandle TX_INFO = new ShortHandle(LAYOUT, "base", "tx_info");

	// Protocol dissection fields
	private static final LongHandle PROTO_BITMAP = new LongHandle(LAYOUT, "proto_bitmap");
	private static final ShortHandle PROTO_COUNTS = new ShortHandle(LAYOUT, "proto_counts");
	private static final ShortHandle EXTENDED_OFFSET = new ShortHandle(LAYOUT, "extended_offset");
	private static final ShortHandle EXTENDED_SIZE = new ShortHandle(LAYOUT, "extended_size");

	// Inline table - array access with [] syntax
	private static final LongHandle INLINE_TABLE = new LongHandle(LAYOUT, "inline_table[]");

	// ========== RX_INFO bit layout ==========

	private static final int RX_PORT_SHIFT = 10;
	private static final int RX_PORT_MASK = 0x3F; // 6 bits: 64 ports
	private static final int L2_EXTENSION_BIT = 9; // 1 bit: has L2 extensions
	private static final int L2_FRAME_TYPE_SHIFT = 3;
	private static final int L2_FRAME_TYPE_MASK = 0x3F; // // 6 bits: 64 types
	private static final int TIMESTAMP_UNIT_SHIFT = 0;
	private static final int TIMESTAMP_UNIT_MASK = 0x7; // 3 bits: 8 units

	// ========== TX_INFO bit layout ==========

	private static final int TX_PORT_SHIFT = 8;
	private static final int TX_PORT_MASK = 0xFF; // 8 bits
	private static final int TX_ENABLED_BIT = 7;
	private static final int TX_IMMEDIATE_BIT = 6;
	private static final int TX_CRC_RECALC_BIT = 5;
	private static final int TX_TIMESTAMP_SYNC_BIT = 4;

	// ========== Protocol entry bit layout ==========

	private static final long PROTOCOL_ID_MASK = 0xFFFFL;
	private static final int HEADER_OFFSET_SHIFT = 16;
	private static final int HEADER_OFFSET_MASK = 0xFFFF;
	private static final int HEADER_LENGTH_SHIFT = 32;
	private static final int HEADER_LENGTH_MASK = 0xFFFF;
	private static final int ENCOUNTER_ORDER_SHIFT = 48;
	private static final int ENCOUNTER_ORDER_MASK = 0xFF;
	private static final int INSTANCE_NUM_SHIFT = 56;
	private static final int INSTANCE_NUM_MASK = 0x7;
	private static final long IS_FRAGMENT_BIT = 1L << 59;
	private static final long IS_TUNNELED_BIT = 1L << 60;
	private static final long HAS_ERRORS_BIT = 1L << 61;

	// ========== Proto counts bit layout ==========

	private static final int PROTOCOL_COUNT_MASK = 0xFF;
	private static final int VLAN_COUNT_SHIFT = 8;
	private static final int VLAN_COUNT_MASK = 0xF;
	private static final int MPLS_COUNT_SHIFT = 12;
	private static final int MPLS_COUNT_MASK = 0xF;

	// ========== Inline table slots ==========

	private static final int INLINE_ETHERNET = 0;
	private static final int INLINE_VLAN = 1;
	private static final int INLINE_IPV4 = 2;
	private static final int INLINE_IPV6 = 3;
	private static final int INLINE_TCP = 4;
	private static final int INLINE_UDP = 5;
	private static final int INLINE_ICMP = 6;
	private static final int INLINE_ARP = 7;
	private static final int INLINE_TABLE_SIZE = 8;

	private static final String[] INLINE_SLOT_NAMES = {
			"Ethernet",
			"VLAN",
			"IPv4",
			"IPv6",
			"TCP",
			"UDP",
			"ICMP",
			"ARP"
	};

	private static final long TX_CAPABILITIES = TxCapabilities.TX_NONE;
	private static final long RX_CAPABILITIES = RxCapabilities.RX_NONE;
	private static final int DESCRIPTOR_ID = DescriptorType.NET;
	private int extendedIndex = 0;
	private int encounterOrder = 0;

	private final BoundView view = new BoundView();

	public NetPacketDescriptor() {
		this(TimestampUnit.EPOCH_MILLI);
	}

	public NetPacketDescriptor(TimestampUnit unit) {
		super(DescriptorInfo.NET, unit);
	}

	public void addProtocol(int protocolId, int offset, int length) {
		addProtocolInstance(protocolId, offset, length, 0);
	}

	public void addProtocolInstance(int protocolId, int offset, int length, int instanceNum) {
		long entry = buildProtocolEntry(protocolId, offset, length,
				encounterOrder++, instanceNum, false, false, false);

		int inlineSlot = getInlineSlot(protocolId);

		if (inlineSlot >= 0) {
			INLINE_TABLE.setLongAtIndex(view(), inlineSlot, entry);
		} else {
			writeProtocolToExtended(entry);
		}

		incrementProtocolCount();
		updateBitmap(protocolId);

		if (protocolId == ProtocolId.VLAN) {
			incrementVlanCount();
		}
	}

	@Override
	public boolean bindHeader(BindableView packet, Header header, int protocolId, int depth) {
		int inlineSlot = getInlineSlot(protocolId);

		if (inlineSlot >= 0 && depth == 0) {
			long entry = INLINE_TABLE.getLongAtIndex(view(), inlineSlot);
			if (entry != 0) {
				int offset = (int) ((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
				int length = (int) ((entry >> HEADER_LENGTH_SHIFT) & HEADER_LENGTH_MASK);
				return header.bindHeader(packet, protocolId, depth, offset, length);
			}
		}

		// Search extended table
		short extSize = EXTENDED_SIZE.getShort(view());
		if (extSize > 0) {
			MemorySegment extended = getExtendedSegment();
			int matchCount = 0;

			for (int i = 0; i < extSize; i++) {
				long entry = extended.get(ValueLayout.JAVA_LONG, i * 8);
				if ((entry & PROTOCOL_ID_MASK) == protocolId) {
					int instance = (int) ((entry >> INSTANCE_NUM_SHIFT) & INSTANCE_NUM_MASK);
					if (instance == depth || matchCount == depth) {
						int offset = (int) ((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
						int length = (int) ((entry >> HEADER_LENGTH_SHIFT) & HEADER_LENGTH_MASK);
						return header.bindHeader(packet, protocolId, depth, offset, length);
					}
					matchCount++;
				}
			}
		}

		return false;
	}

	/**
	 * @see com.slytechs.sdk.common.memory.BindableView#boundView()
	 */
	@Override
	public BoundView boundView() {
		return view;
	}

	/**
	 * Builds a detailed tree representation of this descriptor for UI display.
	 * 
	 * @param b the detail builder
	 */
	@Override
	public void buildDetail(DetailBuilder b) {
		b.header("Net Packet Descriptor", "NET", DESCRIPTOR_ID, 0, BYTE_SIZE, h -> {

			// Summary line
			h.summaryf("cap=%d wire=%d ts=%d %s",
					captureLength(), wireLength(), timestamp(),
					timestampUnit().name());

			// Base section (pcap-compatible 16 bytes)
			h.section("Base", "base", s -> {
				s.field("Timestamp", timestamp(),
						String.format("%d (%s)", timestamp(), timestampUnit()),
						DetailBuilder.longAt(0x00));
				s.field("Capture Length", captureLength(), DetailBuilder.shortAt(0x08));
				s.field("Wire Length", wireLength(), DetailBuilder.shortAt(0x0C));

				// RX Info expandable
				int rxInfoVal = rxInfo();
				s.section("RX Info", "rx", rx -> {
					rx.fieldHex("Raw", rxInfoVal, 4, DetailBuilder.shortAt(0x0A));
					rx.field("RX Port", rxPort());
					rx.field("L2 Frame Type", l2FrameInfo().l2FrameId(), l2FrameInfo().toString());
					rx.field("L2 Extensions", hasL2Extensions());
					rx.field("Timestamp Unit", timestampUnit().name());
				});

				// TX Info expandable
				int txInfoVal = txInfo();
				s.section("TX Info", "tx", tx -> {
					tx.fieldHex("Raw", txInfoVal, 4, DetailBuilder.shortAt(0x0E));
					tx.field("TX Port", txPort());
					tx.field("TX Enabled", isTxEnabled());
					tx.field("TX Immediate", isTxImmediate());
					tx.field("TX CRC Recalc", isTxCrcRecalc());
					tx.field("TX Timestamp Sync", isTxSyncTimestamp());
				});
			});

			// Protocol dissection section
			h.section("Protocol Dissection", "proto", s -> {
				s.fieldHex("Protocol Bitmap", (int) (getProtoBitmap() & 0xFFFFFFFF), 8,
						formatBitmapFlags(), DetailBuilder.longAt(0x10));
				s.field("Protocol Count", getProtocolCount(), DetailBuilder.shortAt(0x18));
				s.field("VLAN Count", getVlanCount());
				s.field("MPLS Count", getMplsCount());
				s.field("Extended Offset", getExtendedOffset(), DetailBuilder.shortAt(0x1A));
				s.field("Extended Size", getExtendedSize(), DetailBuilder.shortAt(0x1C));
			});

			// Inline table section
			h.section("Inline Protocol Table", "inline", s -> {
				for (int i = 0; i < INLINE_TABLE_SIZE; i++) {
					long entry = INLINE_TABLE.getLongAtIndex(view(), i);
					if (entry != 0) {
						int protoId = (int) (entry & PROTOCOL_ID_MASK);
						int offset = (int) ((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
						int length = (int) ((entry >> HEADER_LENGTH_SHIFT) & HEADER_LENGTH_MASK);
						int order = (int) ((entry >> ENCOUNTER_ORDER_SHIFT) & ENCOUNTER_ORDER_MASK);
						int instance = (int) ((entry >> INSTANCE_NUM_SHIFT) & INSTANCE_NUM_MASK);
						boolean fragment = (entry & IS_FRAGMENT_BIT) != 0;
						boolean tunneled = (entry & IS_TUNNELED_BIT) != 0;
						boolean error = (entry & HAS_ERRORS_BIT) != 0;

						s.section(INLINE_SLOT_NAMES[i], INLINE_SLOT_NAMES[i].toLowerCase(), slot -> {
							slot.fieldHex("Protocol ID", protoId, 4);
							slot.field("Offset", offset);
							slot.field("Length", length);
							slot.field("Order", order);
							if (instance > 0)
								slot.field("Instance", instance);
							if (fragment)
								slot.field("Fragment", true);
							if (tunneled)
								slot.field("Tunneled", true);
							if (error)
								slot.expert(ExpertLevel.ERROR, "Protocol parse error");
						});
					}
				}
			});

			// Extended table section (if populated)
//			short extSize = getExtendedSize();
//			if (extSize > 0) {
//				h.section("Extended Protocol Table", "extended", s -> {
//					MemorySegment extended = getExtendedSegment();
//					for (int i = 0; i < extSize; i++) {
//						long entry = extended.get(ValueLayout.JAVA_LONG, i * 8);
//						int protoId = (int) (entry & PROTOCOL_ID_MASK);
//						int offset = (int) ((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
//						int length = (int) ((entry >> HEADER_LENGTH_SHIFT) & HEADER_LENGTH_MASK);
//						int order = (int) ((entry >> ENCOUNTER_ORDER_SHIFT) & ENCOUNTER_ORDER_MASK);
//
//						s.fieldf("Entry[%d]", protoId,
//								"id=0x%04X off=%d len=%d order=%d",
//								protoId, offset, length, order);
//					}
//				});
//			}
		});
	}

	private long buildProtocolEntry(int protocolId, int offset, int length,
			int encounterOrder, int instanceNum, boolean isFragment,
			boolean isTunneled, boolean hasError) {

		long entry = protocolId & PROTOCOL_ID_MASK;
		entry |= ((long) (offset & HEADER_OFFSET_MASK)) << HEADER_OFFSET_SHIFT;
		entry |= ((long) (length & HEADER_LENGTH_MASK)) << HEADER_LENGTH_SHIFT;
		entry |= ((long) (encounterOrder & ENCOUNTER_ORDER_MASK)) << ENCOUNTER_ORDER_SHIFT;
		entry |= ((long) (instanceNum & INSTANCE_NUM_MASK)) << INSTANCE_NUM_SHIFT;
		if (isFragment)
			entry |= IS_FRAGMENT_BIT;
		if (isTunneled)
			entry |= IS_TUNNELED_BIT;
		if (hasError)
			entry |= HAS_ERRORS_BIT;
		return entry;
	}

	@Override
	public int captureLength() {
		return CAPLEN.getShort(view()) & 0xFFFF;
	}

	public StructFormat format(StructFormat p) {
		p.openln("NetPacketDescriptor").indent();

		p.println("timestamp", timestamp())
				.println("timestampUnit", timestampUnit())
				.println("captureLength", captureLength())
				.println("wireLength", wireLength())
				.println("rxPort", rxPort())
				.println("l2FrameType", l2FrameInfo())
				.println("l2Extensions", hasL2Extensions())
				.println("txPort", txPort())
				.println("txEnabled", isTxEnabled())
				.println("txImmediate", isTxImmediate());

		p.println("--- Protocol Table ---")
				.println("protocolCount", getProtocolCount())
				.println("vlanCount", getVlanCount())
				.println("mplsCount", getMplsCount())
				.println("protoBitmap", String.format("0x%016X", getProtoBitmap()));

		p.println("--- Inline Table ---");
		for (int i = 0; i < INLINE_TABLE_SIZE; i++) {
			long entry = INLINE_TABLE.getLongAtIndex(view(), i);
			if (entry != 0) {
				int offset = (int) ((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
				int length = (int) ((entry >> HEADER_LENGTH_SHIFT) & HEADER_LENGTH_MASK);
				int order = (int) ((entry >> ENCOUNTER_ORDER_SHIFT) & ENCOUNTER_ORDER_MASK);
				p.println(String.format("  [%d] %s: offset=%d, length=%d, order=%d",
						i, INLINE_SLOT_NAMES[i], offset, length, order));
			}
		}

		return p.close();
	}

	private String formatBitmapFlags() {
		long bitmap = getProtoBitmap();
		if (bitmap == 0)
			return "none";

		StringBuilder sb = new StringBuilder();
		if ((bitmap & (1L << 0)) != 0)
			sb.append("ETH ");
		if ((bitmap & (1L << 1)) != 0)
			sb.append("VLAN ");
		if ((bitmap & (1L << 2)) != 0)
			sb.append("IPv4 ");
		if ((bitmap & (1L << 3)) != 0)
			sb.append("IPv6 ");
		if ((bitmap & (1L << 4)) != 0)
			sb.append("TCP ");
		if ((bitmap & (1L << 5)) != 0)
			sb.append("UDP ");
		if ((bitmap & (1L << 6)) != 0)
			sb.append("ICMP ");
		if ((bitmap & (1L << 7)) != 0)
			sb.append("ARP ");
		return sb.toString().trim();
	}

	// ========== RX Port & Extensions ==========

	private int getBitmapPosition(int protocolId) {
		return switch (protocolId & 0xFFFF) {
		case ProtocolId.ETHERNET -> 0;
		case ProtocolId.VLAN -> 1;
		case ProtocolId.IPv4 -> 2;
		case ProtocolId.IPv6 -> 3;
		case ProtocolId.TCP -> 4;
		case ProtocolId.UDP -> 5;
		case ProtocolId.ICMP -> 6;
		case ProtocolId.ARP -> 7;
		default -> -1;
		};
	}

	private short getExtendedOffset() {
		return EXTENDED_OFFSET.getShort(view());
	}

	private MemorySegment getExtendedSegment() {
		int offset = captureLength() + getExtendedOffset();
		return view().segment().asSlice(view().start() + offset);
	}

	private short getExtendedSize() {
		return EXTENDED_SIZE.getShort(view());
	}

	private int getInlineSlot(int protocolId) {
		return switch (protocolId & 0xFFFF) {
		case ProtocolId.ETHERNET -> INLINE_ETHERNET;
		case ProtocolId.VLAN -> INLINE_VLAN;
		case ProtocolId.IPv4 -> INLINE_IPV4;
		case ProtocolId.IPv6 -> INLINE_IPV6;
		case ProtocolId.TCP -> INLINE_TCP;
		case ProtocolId.UDP -> INLINE_UDP;
		case ProtocolId.ICMP -> INLINE_ICMP;
		case ProtocolId.ARP -> INLINE_ARP;
		default -> -1;
		};
	}

	public int getMplsCount() {
		return (PROTO_COUNTS.getShort(view()) >> MPLS_COUNT_SHIFT) & MPLS_COUNT_MASK;
	}

	// ========== TransmitControl implementation ==========

	public long getProtoBitmap() {
		return PROTO_BITMAP.getLong(view());
	}

	public int getProtocolCount() {
		return PROTO_COUNTS.getShort(view()) & PROTOCOL_COUNT_MASK;
	}

	public int getVlanCount() {
		return (PROTO_COUNTS.getShort(view()) >> VLAN_COUNT_SHIFT) & VLAN_COUNT_MASK;
	}

	public boolean hasArp() {
		return INLINE_TABLE.getLongAtIndex(view(), INLINE_ARP) != 0;
	}

	public boolean hasEthernet() {
		return INLINE_TABLE.getLongAtIndex(view(), INLINE_ETHERNET) != 0;
	}

	public boolean hasIcmp() {
		return INLINE_TABLE.getLongAtIndex(view(), INLINE_ICMP) != 0;
	}

	public boolean hasIpv4() {
		return INLINE_TABLE.getLongAtIndex(view(), INLINE_IPV4) != 0;
	}

	public boolean hasIpv6() {
		return INLINE_TABLE.getLongAtIndex(view(), INLINE_IPV6) != 0;
	}

	public boolean hasL2Extensions() {
		return (rxInfo() & (1 << L2_EXTENSION_BIT)) != 0;
	}

	public boolean hasTcp() {
		return INLINE_TABLE.getLongAtIndex(view(), INLINE_TCP) != 0;
	}

	public boolean hasUdp() {
		return INLINE_TABLE.getLongAtIndex(view(), INLINE_UDP) != 0;
	}

	public boolean hasVlan() {
		return INLINE_TABLE.getLongAtIndex(view(), INLINE_VLAN) != 0;
	}

	private void incrementProtocolCount() {
		int counts = PROTO_COUNTS.getShort(view()) & 0xFFFF;
		int protoCount = (counts & PROTOCOL_COUNT_MASK) + 1;
		counts = (counts & ~PROTOCOL_COUNT_MASK) | (protoCount & PROTOCOL_COUNT_MASK);
		PROTO_COUNTS.setShort(view(), (short) counts);
	}

	// ========== Protocol Table ==========

	private void incrementVlanCount() {
		int counts = PROTO_COUNTS.getShort(view()) & 0xFFFF;
		int vlanCount = ((counts >> VLAN_COUNT_SHIFT) & VLAN_COUNT_MASK) + 1;
		counts = (counts & ~(VLAN_COUNT_MASK << VLAN_COUNT_SHIFT))
				| ((vlanCount & VLAN_COUNT_MASK) << VLAN_COUNT_SHIFT);
		PROTO_COUNTS.setShort(view(), (short) counts);
	}

	public boolean isTxCrcRecalc() {
		return (txInfo() & (1 << TX_CRC_RECALC_BIT)) != 0;
	}

	@Override
	public boolean isTxEnabled() {
		return (txInfo() & (1 << TX_ENABLED_BIT)) != 0;
	}

	@Override
	public boolean isTxImmediate() {
		return (txInfo() & (1 << TX_IMMEDIATE_BIT)) != 0;
	}

	@Override
	public boolean isTxSyncTimestamp() {
		return (txInfo() & (1 << TX_TIMESTAMP_SYNC_BIT)) != 0;
	}

	@Override
	public Iterator<BindingInfo> iterator() {
		var list = new ArrayList<BindingInfo>();

		for (int i = 0; i < INLINE_TABLE_SIZE; i++) {
			long entry = INLINE_TABLE.getLongAtIndex(view(), i);
			if (entry != 0) {
				int id = (int) (entry & PROTOCOL_ID_MASK);
				int offset = (int) ((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
				int length = (int) ((entry >> HEADER_LENGTH_SHIFT) & HEADER_LENGTH_MASK);
				int order = (int) ((entry >> ENCOUNTER_ORDER_SHIFT) & ENCOUNTER_ORDER_MASK);
				list.add(new BindingInfo(order, id, offset, length));
			}
		}

		// Add extended table entries
		short extSize = getExtendedSize();
		if (extSize > 0) {
			MemorySegment extended = getExtendedSegment();
			for (int i = 0; i < extSize; i++) {
				long entry = extended.get(ValueLayout.JAVA_LONG, i * 8);
				int id = (int) (entry & PROTOCOL_ID_MASK);
				int offset = (int) ((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
				int length = (int) ((entry >> HEADER_LENGTH_SHIFT) & HEADER_LENGTH_MASK);
				int order = (int) ((entry >> ENCOUNTER_ORDER_SHIFT) & ENCOUNTER_ORDER_MASK);
				list.add(new BindingInfo(order, id, offset, length));
			}
		}

		// Sort by encounter order
		list.sort((a, b) -> Integer.compare(a.order(), b.order()));

		return list.iterator();
	}

	public int l2FrameId() {
		return (rxInfo() >> L2_FRAME_TYPE_SHIFT) & L2_FRAME_TYPE_MASK;
	}

	@Override
	public long length() {
		return LAYOUT.byteSize();
	}

	@Override
	public long mapProtocol(int protocolId, int depth) {
		if (depth == 0) {
			int inlineSlot = getInlineSlot(protocolId);
			if (inlineSlot >= 0) {
				long entry = INLINE_TABLE.getLongAtIndex(view(), inlineSlot);
				if (entry != 0) {
					int offset = (int) ((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
					int length = (int) ((entry >> HEADER_LENGTH_SHIFT) & HEADER_LENGTH_MASK);
					return PacketDescriptor.encodeLengthAndOffset(length, offset);
				}
			}
		}
		return mapProtocolExtended(protocolId, depth);
	}

	private long mapProtocolExtended(int protocolId, int depth) {
		short extSize = EXTENDED_SIZE.getShort(view());
		if (extSize > 0) {
			MemorySegment extended = getExtendedSegment();
			int matchCount = 0;

			for (int i = 0; i < extSize; i++) {
				long entry = extended.get(ValueLayout.JAVA_LONG, i * 8);
				if ((entry & PROTOCOL_ID_MASK) == protocolId) {
					int instance = (int) ((entry >> INSTANCE_NUM_SHIFT) & INSTANCE_NUM_MASK);
					if (instance == depth || matchCount == depth) {
						int offset = (int) ((entry >> HEADER_OFFSET_SHIFT) & HEADER_OFFSET_MASK);
						int length = (int) ((entry >> HEADER_LENGTH_SHIFT) & HEADER_LENGTH_MASK);
						return PacketDescriptor.encodeLengthAndOffset(length, offset);
					}
					matchCount++;
				}
			}
		}
		return PacketDescriptor.PROTOCOL_NOT_FOUND;
	}

	/**
	 * @see com.slytechs.sdk.common.memory.pool.Persistable#newUnbound()
	 */
	@Override
	public PacketDescriptor newUnbound() {
		return new NetPacketDescriptor();
	}

	@Override
	public ByteOrder order() {
		return ByteOrder.nativeOrder();
	}

	public void reset() {
		extendedIndex = 0;
		encounterOrder = 0;
		setProtoBitmap(0);
		PROTO_COUNTS.setShort(view(), (short) 0);
		EXTENDED_SIZE.setShort(view(), (short) 0);

		// Clear inline table
		for (int i = 0; i < INLINE_TABLE_SIZE; i++) {
			INLINE_TABLE.setLongAtIndex(view(), i, 0L);
		}
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#rxCapabilities()
	 */
	@Override
	public RxCapabilities rxCapabilities() {
		return this;
	}

	// ========== Protocol counts ==========

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#rxCapabilitiesBitmask()
	 */
	@Override
	public long rxCapabilitiesBitmask() {
		return RX_CAPABILITIES;
	}

	private int rxInfo() {
		return RX_INFO.getShort(view()) & 0xFFFF;
	}

	public int rxPort() {
		return (rxInfo() >> RX_PORT_SHIFT) & RX_PORT_MASK;
	}

	@Override
	public NetPacketDescriptor setCaptureLength(int length) {
		CAPLEN.setShort(view(), (short) (length & 0xFFFF));

		return this;
	}

	public NetPacketDescriptor setL2Extensions(boolean hasExtensions) {
		int info = rxInfo();
		if (hasExtensions) {
			info |= (1 << L2_EXTENSION_BIT);
		} else {
			info &= ~(1 << L2_EXTENSION_BIT);
		}
		setRxInfo(info);

		return this;
	}

	public void setL2FrameId(int l2Type) {
		int info = rxInfo() & ~(L2_FRAME_TYPE_MASK << L2_FRAME_TYPE_SHIFT);
		info |= ((l2Type & L2_FRAME_TYPE_MASK) << L2_FRAME_TYPE_SHIFT);
		setRxInfo(info);
	}

	/**
	 * @return
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#setL2FrameType(com.slytechs.sdk.protocol.core.descriptor.L2FrameInfo)
	 */
	@Override
	public NetPacketDescriptor setL2FrameType(L2FrameInfo l2FrameInfo) {
		setL2FrameId(l2FrameInfo.l2FrameId());

		return this;
	}

	private void setProtoBitmap(long bitmap) {
		PROTO_BITMAP.setLong(view(), bitmap);
	}

	private void setRxInfo(int info) {
		RX_INFO.setShort(view(), (short) (info & 0xFFFF));
	}

	@Override
	public NetPacketDescriptor setRxPort(int port) {
		if (port > RX_PORT_MASK) {
			throw new IllegalArgumentException("RX port must be 0-63, got: " + port);
		}
		int info = rxInfo() & ~(RX_PORT_MASK << RX_PORT_SHIFT);
		info |= ((port & RX_PORT_MASK) << RX_PORT_SHIFT);
		setRxInfo(info);

		return this;
	}

	@Override
	public NetPacketDescriptor setTimestamp(long timestamp) {
		TIMESTAMP.setLong(view(), timestamp);

		return this;
	}

	@Override
	public NetPacketDescriptor setTimestamp(long timestamp, TimestampUnit unit) {
		if (unit != timestampUnit())
			timestamp = timestampUnit().convert(timestamp, unit);

		setTimestamp(timestamp);

		return this;
	}

	@Override
	public NetPacketDescriptor setTimestampUnit(TimestampUnit unit) {
		super.setTimestampUnit(unit);

		setTimestampUnitEncoded(unit);

		return this;
	}

	private NetPacketDescriptor setTimestampUnitEncoded(TimestampUnit unit) {
		int info = rxInfo() & ~(TIMESTAMP_UNIT_MASK << TIMESTAMP_UNIT_SHIFT);
		info |= ((unit.ordinal() & TIMESTAMP_UNIT_MASK) << TIMESTAMP_UNIT_SHIFT);
		setRxInfo(info);

		return this;
	}

	private void setTxBit(int bit, boolean value) {
		int info = txInfo();
		if (value) {
			info |= (1 << bit);
		} else {
			info &= ~(1 << bit);
		}
		setTxInfo(info);
	}

	public NetPacketDescriptor setTxCrcRecalc(boolean recalc) {
		setTxBit(TX_CRC_RECALC_BIT, recalc);
		return this;
	}

	@Override
	public NetPacketDescriptor setTxEnabled(boolean enabled) {
		setTxBit(TX_ENABLED_BIT, enabled);
		return this;
	}

	@Override
	public NetPacketDescriptor setTxImmediate(boolean immediate) {
		setTxBit(TX_IMMEDIATE_BIT, immediate);
		return this;
	}

	private void setTxInfo(int info) {
		TX_INFO.setShort(view(), (short) (info & 0xFFFF));
	}

	@Override
	public NetPacketDescriptor setTxPort(int port) {
		if (port > TX_PORT_MASK) {
			throw new IllegalArgumentException("TX port must be 0-255, got: " + port);
		}
		int info = txInfo() & ~(TX_PORT_MASK << TX_PORT_SHIFT);
		info |= ((port & TX_PORT_MASK) << TX_PORT_SHIFT);
		setTxInfo(info);
		return this;
	}

	@Override
	public NetPacketDescriptor setTxSyncTimestamp(boolean sync) {
		setTxBit(TX_TIMESTAMP_SYNC_BIT, sync);
		return this;
	}

	@Override
	public NetPacketDescriptor setWireLength(int length) {
		WIRELEN.setShort(view(), (short) (length & 0xFFFF));

		return this;
	}

	@Override
	public long timestamp() {
		return TIMESTAMP.getLong(view());
	}

	@Override
	public String toString() {
		return toDetailString();
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#txCapabilities()
	 */
	@Override
	public TxCapabilities txCapabilities() {
		return this;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#txCapabilitiesBitmask()
	 */
	@Override
	public long txCapabilitiesBitmask() {
		return TX_CAPABILITIES;
	}

	private int txInfo() {
		return TX_INFO.getShort(view()) & 0xFFFF;
	}

	@Override
	public int txPort() {
		return (txInfo() >> TX_PORT_SHIFT) & TX_PORT_MASK;
	}

	private void updateBitmap(int protocolId) {
		int bitPos = getBitmapPosition(protocolId);
		if (bitPos >= 0) {
			long bitmap = getProtoBitmap();
			bitmap |= (1L << bitPos);
			setProtoBitmap(bitmap);
		}
	}

	@Override
	public int wireLength() {
		return WIRELEN.getShort(view()) & 0xFFFF;
	}

	private void writeProtocolToExtended(long entry) {
		MemorySegment extended = getExtendedSegment();
		extended.set(ValueLayout.JAVA_LONG, extendedIndex * 8, entry);
		extendedIndex++;
		EXTENDED_SIZE.setShort(view(), (short) extendedIndex);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#l2FrameInfo()
	 */
	@Override
	public L2FrameInfo l2FrameInfo() {
		return L2FrameInfo.of(l2FrameId());
	}

}