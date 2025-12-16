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
import java.lang.invoke.VarHandle;

import com.slytechs.jnet.core.api.format.StructFormat;
import com.slytechs.jnet.core.api.format.StructFormattable;
import com.slytechs.jnet.core.api.memory.ByteBuf;
import com.slytechs.jnet.core.api.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.Header;
import com.slytechs.jnet.protocol.api.ProtocolIds;
import com.slytechs.jnet.protocol.api.builtin.L2FrameType;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * Net1 Packet Descriptor - 32-byte descriptor for streamlined packet
 * dissection.
 * 
 * <p>
 * This descriptor extends NetPacketDescriptor with protocol dissection
 * information optimized for software-based packet processing. It provides
 * direct access to L2-L4 protocol offsets and lengths while maintaining
 * backward compatibility with the pcap format through its base descriptor. The
 * design focuses on single memory read operations for performance-critical
 * packet analysis.
 * </p>
 * 
 * <h2>Memory Layout</h2>
 * 
 * <pre>
 * Offset  Size  Field         Description
 * ------------------------------------------------------
 * 0x00    16    net_base      NetPacketDescriptor (pcap-compatible)
 * 0x10    8     proto_info    Protocol dissection information
 * 0x18    8     dynamic0      Configurable hash/color field
 * </pre>
 * 
 * <h2>PROTO_INFO Bit Layout (64 bits)</h2>
 * 
 * <pre>
 * Bits [4-0]:   L2_TYPE (5 bits)         - Layer 2 frame type (0-31)
 * Bits [11-5]:  L2_LEN (7 bits)          - L2 header length in bytes (0-127)
 * Bits [15-12]: L3_TYPE (4 bits)         - Layer 3 protocol type (0-15)
 * Bits [25-16]: L3_OFFSET (10 bits)      - L3 header offset (0-1023)
 * Bits [39-26]: L3_LEN (14 bits)         - L3 total length (0-16383)
 * Bits [43-40]: L4_TYPE (4 bits)         - Layer 4 protocol type (0-15)
 * Bits [53-44]: L4_OFFSET (10 bits)      - L4 header offset (0-1023)
 * Bits [61-54]: L4_LEN (8 bits)          - L4 length in 4-byte units (0-1020)
 * Bit  [62]:    L4_PRESENT (1 bit)       - L4 header exists
 * Bit  [63]:    L3_FRAGMENTED (1 bit)    - IP fragmentation flag
 * </pre>
 * 
 * <h2>DYNAMIC0 Field Configurations</h2>
 * 
 * <h3>Default Configuration (Self-Describing)</h3>
 * 
 * <pre>
 * Bits [51-0]:  HASH_VALUE (52 bits)     - Computed hash value
 * Bits [55-52]: COLOR (4 bits)           - User-defined color
 * Bits [58-56]: HASH_BITS (3 bits)       - Hash size encoding (0-7)
 *                                           0 = no hash (color only)
 *                                           1 = 8-bit hash
 *                                           2 = 16-bit hash
 *                                           ...
 *                                           7 = 56-bit hash
 * Bits [63-59]: HASH_TYPE (5 bits)       - Hash algorithm ID (0-31)
 * </pre>
 * 
 * <h3>Alternative Configurations</h3>
 * 
 * <pre>
 * Production Mode:
 * Bits [63-0]:  HASH_VALUE (64 bits)     - Full 64-bit hash
 * 
 * Custom Split:
 * Bits [47-0]:  HASH_VALUE (48 bits)     - Hash value
 * Bits [63-48]: COLOR (16 bits)          - Extended user metadata
 * 
 * User-Defined:
 * Bits [63-0]:  USER_DATA (64 bits)      - Application-specific data
 * </pre>
 * 
 * <h2>Protocol Type Encodings</h2>
 * 
 * <h3>L2 Frame Types</h3>
 * 
 * <pre>
 * 1 - Ethernet II
 * 2 - IEEE 802.3
 * 3 - LLC
 * 4 - SNAP
 * </pre>
 * 
 * <h3>L3 Protocol Types</h3>
 * 
 * <pre>
 * 0 - Unknown
 * 1 - IPv4
 * 2 - IPv6
 * 3 - ARP
 * 4 - RARP
 * 5 - IPX
 * </pre>
 * 
 * <h3>L4 Protocol Types</h3>
 * 
 * <pre>
 * 0 - Unknown
 * 1 - TCP
 * 2 - UDP
 * 3 - ICMP
 * 4 - ICMPv6
 * 5 - SCTP
 * </pre>
 * 
 * <h2>Usage Example</h2>
 * 
 * <pre>{@code
 * // Create descriptor for packet dissection
 * Net1PacketDescriptor desc = new Net1PacketDescriptor(TimestampUnit.PCAP_NANO);
 * 
 * // Set base pcap information (inherited from NetPacketDescriptor)
 * desc.setTimestamp(System.nanoTime());
 * desc.setCaptureLength(packet.length());
 * desc.setWireLength(originalLength);
 * 
 * // Dissect and record protocol information
 * desc.setL2Type(L2_TYPE_ETHERNET);
 * desc.setL2Length(14);
 * desc.setL3Type(L3_TYPE_IPV4);
 * desc.setL3Offset(14);
 * desc.setL3Length(totalIpLength);
 * 
 * if (hasTransportLayer) {
 * 	desc.setL4Type(L4_TYPE_TCP);
 * 	desc.setL4Offset(34); // 14 (Ethernet) + 20 (IP)
 * 	desc.setL4Length(tcpTotalLength);
 * 	desc.setL4Present(true);
 * }
 * 
 * // Configure hash with metadata (default configuration)
 * desc.setHashType(HASH_TYPE_CRC32);
 * desc.setHashBits(4); // 32-bit hash
 * desc.setHashValue(computedCrc32);
 * desc.setColor(flowId & 0xF);
 * 
 * // Or use full 64-bit for production
 * desc.setDynamic0Value(computed64BitHash);
 * 
 * // Access dissection results efficiently
 * int ipOffset = desc.getL3Offset();
 * int tcpOffset = desc.getL4Offset();
 * }</pre>
 * 
 * <h2>Design Notes</h2>
 * <ul>
 * <li>All protocol information fits in a single 64-bit word for optimal
 * access</li>
 * <li>Dynamic field supports multiple configurations based on deployment
 * needs</li>
 * <li>Self-describing mode includes metadata for debugging and monitoring</li>
 * <li>Production mode maximizes hash precision using full 64 bits</li>
 * <li>Maintains pcap compatibility through base NetPacketDescriptor</li>
 * <li>Optimized for software dissection without hardware offload
 * dependencies</li>
 * </ul>
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 * @see NetPacketDescriptor
 * @see Net2PacketDescriptor
 */
public class Net1PacketDescriptor
		extends NetPacketDescriptor
		implements PacketDescriptor, StructFormattable {

	// Memory Layout - extends NetPacketDescriptor
	public static final MemoryLayout LAYOUT = structLayout(
			NetPacketDescriptor.LAYOUT.withName("net_base"), // 16 bytes
			U64.withName("proto_info"), // 8 bytes
			U64.withName("dynamic0") // 8 bytes
	);

	// VarHandles for extended fields
	private static final VarHandle PROTO_INFO = LAYOUT.varHandle(groupElement("proto_info"));
	private static final VarHandle DYNAMIC0 = LAYOUT.varHandle(groupElement("dynamic0"));

	// proto_info bit positions (64 bits aligned)
	private static final long L2_TYPE_MASK = 0x1FL; // 5 bits: 0-4
	private static final int L2_LEN_SHIFT = 5;
	private static final long L2_LEN_MASK = 0x7FL; // 7 bits: 5-11
	private static final int L3_TYPE_SHIFT = 12;
	private static final long L3_TYPE_MASK = 0xFL; // 4 bits: 12-15
	private static final int L3_OFFSET_SHIFT = 16;
	private static final long L3_OFFSET_MASK = 0x3FFL; // 10 bits: 16-25
	private static final int L3_LEN_SHIFT = 26;
	private static final long L3_LEN_MASK = 0x3FFFL; // 14 bits: 26-39
	private static final int L4_TYPE_SHIFT = 40;
	private static final long L4_TYPE_MASK = 0xFL; // 4 bits: 40-43
	private static final int L4_OFFSET_SHIFT = 44;
	private static final long L4_OFFSET_MASK = 0x3FFL; // 10 bits: 44-53
	private static final int L4_LEN_SHIFT = 54;
	private static final long L4_LEN_MASK = 0xFFL; // 8 bits: 54-61
	private static final int L4_PRESENT_BIT = 62; // 1 bit: 62
	private static final int L3_FRAGMENTED_BIT = 63; // 1 bit: 63

	// dynamic0 default configuration bit positions
	private static final long HASH_VALUE_MASK = 0xFFFFFFFFFFFFL; // 52 bits: 0-51
	private static final int COLOR_SHIFT = 52;
	private static final long COLOR_MASK = 0xFL; // 4 bits: 52-55
	private static final int HASH_BITS_SHIFT = 56;
	private static final long HASH_BITS_MASK = 0x7L; // 3 bits: 56-58
	private static final int HASH_TYPE_SHIFT = 59;
	private static final long HASH_TYPE_MASK = 0x1FL; // 5 bits: 59-63

	// L2 Frame types (simplified)
	public static final int L2_TYPE_ETHERNET = 1;
	public static final int L2_TYPE_802_3 = 2;
	public static final int L2_TYPE_LLC = 3;
	public static final int L2_TYPE_SNAP = 4;

	// L3 Protocol types
	public static final int L3_TYPE_UNKNOWN = 0;
	public static final int L3_TYPE_IPV4 = 1;
	public static final int L3_TYPE_IPV6 = 2;
	public static final int L3_TYPE_ARP = 3;
	public static final int L3_TYPE_RARP = 4;
	public static final int L3_TYPE_IPX = 5;

	// L4 Protocol types
	public static final int L4_TYPE_UNKNOWN = 0;
	public static final int L4_TYPE_TCP = 1;
	public static final int L4_TYPE_UDP = 2;
	public static final int L4_TYPE_ICMP = 3;
	public static final int L4_TYPE_ICMPV6 = 4;
	public static final int L4_TYPE_SCTP = 5;

	/**
	 * Creates a Net1PacketDescriptor with default timestamp unit.
	 */
	public Net1PacketDescriptor() {
		this(TimestampUnit.EPOCH_MICRO);
	}

	/**
	 * Creates a Net1PacketDescriptor with specified L2 type and timestamp unit.
	 *
	 * @param l2Type        the L2 frame type
	 * @param timestampUnit the timestamp unit to use
	 */
	public Net1PacketDescriptor(L2FrameType l2Type, TimestampUnit timestampUnit) {
		super(l2Type, timestampUnit);
	}

	/**
	 * Creates a Net1PacketDescriptor with specified timestamp unit.
	 * 
	 * @param timestampUnit the timestamp unit to use
	 */
	public Net1PacketDescriptor(TimestampUnit timestampUnit) {
		super(timestampUnit);
	}

	@Override
	public int descriptorId() {
		return DescriptorType.DESCRIPTOR_TYPE_NET1.getValue();
	}

	// Formatting
	@Override
	public StructFormat format(StructFormat p) {
		p = super.format(p); // Format base fields

		p.println("=== Net1 Protocol Information ===");

		// L2 info
		p.println("l2Type", getL2TypeString(getL2Type()));
		p.println("l2Length", getL2Length());

		// L3 info
		p.println("l3Type", getL3TypeString(getL3Type()));
		p.println("l3Offset", getL3Offset());
		p.println("l3Length", getL3Length());
		if (isL3Fragmented()) {
			p.println("l3Fragmented", true);
		}

		// L4 info
		if (isL4Present()) {
			p.println("l4Type", getL4TypeString(getL4Type()));
			p.println("l4Offset", getL4Offset());
			p.println("l4Length", getL4Length());
		} else {
			p.println("l4Present", false);
		}

		// Dynamic field info
		p.println("=== Dynamic Field ===");
		int hashBits = getHashBits();
		if (hashBits > 0) {
			int actualBits = hashBits * 8;
			p.println("hashType", getHashType());
			p.println("hashValue", String.format("0x%X (%d bits)",
					getHashValue(), Math.min(actualBits, 52)));
		}
		if (getColor() != 0) {
			p.println("color", String.format("0x%X", getColor()));
		}
		p.println("dynamic0Raw", String.format("0x%016X", getDynamic0Value()));

		return p;
	}

	/**
	 * Gets the color value from dynamic0 field.
	 * 
	 * @return color value (4 bits in default config)
	 */
	public int getColor() {
		return (int) ((getDynamic0() >> COLOR_SHIFT) & COLOR_MASK);
	}

	private long getDynamic0() {
		return (long) DYNAMIC0.get(segment(), view().start());
	}

	// Protocol Info accessors

	/**
	 * Gets the entire dynamic0 field value.
	 * 
	 * @return 64-bit dynamic field value
	 */
	public long getDynamic0Value() {
		return getDynamic0();
	}

	/**
	 * Gets the hash bits configuration.
	 * 
	 * @return hash bits (0-7, multiply by 8 for actual bit count)
	 */
	public int getHashBits() {
		return (int) ((getDynamic0() >> HASH_BITS_SHIFT) & HASH_BITS_MASK);
	}

	/**
	 * Gets the hash algorithm type.
	 * 
	 * @return hash type (0-31)
	 */
	public int getHashType() {
		return (int) ((getDynamic0() >> HASH_TYPE_SHIFT) & HASH_TYPE_MASK);
	}

	/**
	 * Gets the hash value from dynamic0 field.
	 * 
	 * @return hash value (up to 52 bits in default config)
	 */
	public long getHashValue() {
		return getDynamic0() & HASH_VALUE_MASK;
	}

	/**
	 * Gets the L2 header length.
	 * 
	 * @return L2 header length in bytes
	 */
	public int getL2Length() {
		return (int) ((getProtoInfo() >> L2_LEN_SHIFT) & L2_LEN_MASK);
	}

	/**
	 * Gets the L2 frame type.
	 * 
	 * @return L2 frame type
	 */
	public int getL2Type() {
		return (int) (getProtoInfo() & L2_TYPE_MASK);
	}

	// Helper methods for string conversion
	private String getL2TypeString(int type) {
		return switch (type) {
		case L2_TYPE_ETHERNET -> "Ethernet";
		case L2_TYPE_802_3 -> "802.3";
		case L2_TYPE_LLC -> "LLC";
		case L2_TYPE_SNAP -> "SNAP";
		default -> "Unknown(" + type + ")";
		};
	}

	/**
	 * Gets the L3 total length.
	 * 
	 * @return L3 total length in bytes
	 */
	public int getL3Length() {
		return (int) ((getProtoInfo() >> L3_LEN_SHIFT) & L3_LEN_MASK);
	}

	/**
	 * Gets the L3 offset.
	 * 
	 * @return L3 offset in bytes
	 */
	public int getL3Offset() {
		return (int) ((getProtoInfo() >> L3_OFFSET_SHIFT) & L3_OFFSET_MASK);
	}

	/**
	 * Gets the L3 protocol type.
	 * 
	 * @return L3 protocol type
	 */
	public int getL3Type() {
		return (int) ((getProtoInfo() >> L3_TYPE_SHIFT) & L3_TYPE_MASK);
	}

	private String getL3TypeString(int type) {
		return switch (type) {
		case L3_TYPE_IPV4 -> "IPv4";
		case L3_TYPE_IPV6 -> "IPv6";
		case L3_TYPE_ARP -> "ARP";
		case L3_TYPE_RARP -> "RARP";
		case L3_TYPE_IPX -> "IPX";
		default -> "Unknown(" + type + ")";
		};
	}

	/**
	 * Gets the L4 total length.
	 * 
	 * @return L4 total length in bytes
	 */
	public int getL4Length() {
		return (int) ((getProtoInfo() >> L4_LEN_SHIFT) & L4_LEN_MASK) * 4;
	}

	/**
	 * Gets the L4 offset.
	 * 
	 * @return L4 offset in bytes
	 */
	public int getL4Offset() {
		return (int) ((getProtoInfo() >> L4_OFFSET_SHIFT) & L4_OFFSET_MASK);
	}

	/**
	 * Gets the L4 protocol type.
	 * 
	 * @return L4 protocol type
	 */
	public int getL4Type() {
		return (int) ((getProtoInfo() >> L4_TYPE_SHIFT) & L4_TYPE_MASK);
	}

	private String getL4TypeString(int type) {
		return switch (type) {
		case L4_TYPE_TCP -> "TCP";
		case L4_TYPE_UDP -> "UDP";
		case L4_TYPE_ICMP -> "ICMP";
		case L4_TYPE_ICMPV6 -> "ICMPv6";
		case L4_TYPE_SCTP -> "SCTP";
		default -> "Unknown(" + type + ")";
		};
	}

	// Helper methods for field access
	private long getProtoInfo() {
		return (long) PROTO_INFO.get(segment(), view().start());
	}

	/**
	 * Checks if L3 packet is fragmented.
	 * 
	 * @return true if fragmented
	 */
	public boolean isL3Fragmented() {
		return (getProtoInfo() & (1L << L3_FRAGMENTED_BIT)) != 0;
	}

	/**
	 * Checks if L4 header is present.
	 * 
	 * @return true if L4 header exists
	 */
	public boolean isL4Present() {
		return (getProtoInfo() & (1L << L4_PRESENT_BIT)) != 0;
	}

	@Override
	public long length() {
		return LAYOUT.byteSize();
	}

	/**
	 * Sets the color value in dynamic0 field.
	 * 
	 * @param color color value
	 */
	public void setColor(int color) {
		long dynamic = getDynamic0();
		dynamic &= ~(COLOR_MASK << COLOR_SHIFT);
		dynamic |= ((color & COLOR_MASK) << COLOR_SHIFT);
		setDynamic0(dynamic);
	}

	// Dynamic field accessors (default configuration with metadata)

	private void setDynamic0(long value) {
		DYNAMIC0.set(segment(), view().start(), value);
	}

	/**
	 * Sets the entire dynamic0 field value.
	 * 
	 * @param value 64-bit dynamic field value
	 */
	public void setDynamic0Value(long value) {
		setDynamic0(value);
	}

	/**
	 * Sets the hash bits configuration.
	 * 
	 * @param bits hash bits (0-7)
	 */
	public void setHashBits(int bits) {
		long dynamic = getDynamic0();
		dynamic &= ~(HASH_BITS_MASK << HASH_BITS_SHIFT);
		dynamic |= ((bits & HASH_BITS_MASK) << HASH_BITS_SHIFT);
		setDynamic0(dynamic);
	}

	/**
	 * Sets the hash algorithm type.
	 * 
	 * @param type hash type (0-31)
	 */
	public void setHashType(int type) {
		long dynamic = getDynamic0();
		dynamic &= ~(HASH_TYPE_MASK << HASH_TYPE_SHIFT);
		dynamic |= ((type & HASH_TYPE_MASK) << HASH_TYPE_SHIFT);
		setDynamic0(dynamic);
	}

	/**
	 * Sets the hash value in dynamic0 field.
	 * 
	 * @param hash hash value
	 */
	public void setHashValue(long hash) {
		long dynamic = getDynamic0();
		dynamic = (dynamic & ~HASH_VALUE_MASK) | (hash & HASH_VALUE_MASK);
		setDynamic0(dynamic);
	}

	/**
	 * Sets the L2 header length.
	 * 
	 * @param length L2 header length in bytes
	 */
	public void setL2Length(int length) {
		long info = getProtoInfo();
		info &= ~(L2_LEN_MASK << L2_LEN_SHIFT);
		info |= ((length & L2_LEN_MASK) << L2_LEN_SHIFT);
		setProtoInfo(info);
	}

	/**
	 * Sets the L2 frame type.
	 * 
	 * @param type L2 frame type
	 */
	public void setL2Type(int type) {
		long info = getProtoInfo();
		info = (info & ~L2_TYPE_MASK) | (type & L2_TYPE_MASK);
		setProtoInfo(info);
	}

	/**
	 * Sets the L3 fragmented flag.
	 * 
	 * @param fragmented true if fragmented
	 */
	public void setL3Fragmented(boolean fragmented) {
		long info = getProtoInfo();
		if (fragmented) {
			info |= (1L << L3_FRAGMENTED_BIT);
		} else {
			info &= ~(1L << L3_FRAGMENTED_BIT);
		}
		setProtoInfo(info);
	}

	/**
	 * Sets the L3 total length.
	 * 
	 * @param length L3 total length in bytes
	 */
	public void setL3Length(int length) {
		long info = getProtoInfo();
		info &= ~(L3_LEN_MASK << L3_LEN_SHIFT);
		info |= ((length & L3_LEN_MASK) << L3_LEN_SHIFT);
		setProtoInfo(info);
	}

	/**
	 * Sets the L3 offset.
	 * 
	 * @param offset L3 offset in bytes
	 */
	public void setL3Offset(int offset) {
		long info = getProtoInfo();
		info &= ~(L3_OFFSET_MASK << L3_OFFSET_SHIFT);
		info |= ((offset & L3_OFFSET_MASK) << L3_OFFSET_SHIFT);
		setProtoInfo(info);
	}

	/**
	 * Sets the L3 protocol type.
	 * 
	 * @param type L3 protocol type
	 */
	public void setL3Type(int type) {
		long info = getProtoInfo();
		info &= ~(L3_TYPE_MASK << L3_TYPE_SHIFT);
		info |= ((type & L3_TYPE_MASK) << L3_TYPE_SHIFT);
		setProtoInfo(info);
	}

	/**
	 * Sets the L4 total length.
	 * 
	 * @param length L4 total length in bytes
	 */
	public void setL4Length(int length) {
		long info = getProtoInfo();
		int units = length / 4; // Store in 4-byte units
		info &= ~(L4_LEN_MASK << L4_LEN_SHIFT);
		info |= ((units & L4_LEN_MASK) << L4_LEN_SHIFT);
		setProtoInfo(info);
	}

	/**
	 * Sets the L4 offset.
	 * 
	 * @param offset L4 offset in bytes
	 */
	public void setL4Offset(int offset) {
		long info = getProtoInfo();
		info &= ~(L4_OFFSET_MASK << L4_OFFSET_SHIFT);
		info |= ((offset & L4_OFFSET_MASK) << L4_OFFSET_SHIFT);
		setProtoInfo(info);
	}

	/**
	 * Sets the L4 present flag.
	 * 
	 * @param present true if L4 header exists
	 */
	public void setL4Present(boolean present) {
		long info = getProtoInfo();
		if (present) {
			info |= (1L << L4_PRESENT_BIT);
		} else {
			info &= ~(1L << L4_PRESENT_BIT);
		}
		setProtoInfo(info);
	}

	/**
	 * Sets the L4 protocol type.
	 * 
	 * @param type L4 protocol type
	 */
	public void setL4Type(int type) {
		long info = getProtoInfo();
		info &= ~(L4_TYPE_MASK << L4_TYPE_SHIFT);
		info |= ((type & L4_TYPE_MASK) << L4_TYPE_SHIFT);
		setProtoInfo(info);
	}

	private void setProtoInfo(long value) {
		PROTO_INFO.set(segment(), view().start(), value);
	}

	@Override
	public String toString() {
		return format(new StructFormat()).toString();
	}

	// Descriptor type and identification
	@Override
	public DescriptorType type() {
		return DescriptorType.DESCRIPTOR_TYPE_NET1;
	}

	/**
	 * Binds a protocol header to the packet based on descriptor information.
	 * 
	 * <p>
	 * The depth parameter indicates the tunnel encapsulation depth:
	 * <ul>
	 * <li>depth 0 - Non-tunneled packet (outer/only packet)</li>
	 * <li>depth 1 - Single tunnel encapsulation</li>
	 * <li>depth 2 - Double tunnel encapsulation</li>
	 * </ul>
	 * 
	 * Net1PacketDescriptor only supports depth 0 (non-tunneled) packets. For
	 * tunneled packets, use Net2PacketDescriptor which provides tunnel metadata and
	 * inner packet information.
	 * </p>
	 * 
	 * @param packet     the packet memory buffer
	 * @param header     the header to bind
	 * @param protocolId the protocol identifier to match
	 * @param depth      the tunnel encapsulation depth (0=no tunnel)
	 * @return true if the protocol was successfully bound, false otherwise
	 */
	@Override
	public boolean bindProtocol(ByteBuf packet, Header header, int protocolId, int depth) {
		// Net1 only handles non-tunneled packets (depth 0)
		if (depth != 0) {
			return false; // Tunneled packets not supported in Net1
		}

		// For depth 0, check all stored protocol layers
		// Try L2 frame type
		L2FrameType frameType = l2FrameType();
		if (frameType != null && frameType.protocolId() == protocolId) {
			return header.bindHeader(packet, protocolId, depth, 0, getL2Length());
		}

		// Try L3 protocol
		if (matchesL3ProtocolId(getL3Type(), protocolId)) {
			return header.bindHeader(packet, protocolId, depth, getL3Offset(), getL3Length());
		}

		// Try L4 protocol if present
		if (isL4Present() && matchesL4ProtocolId(getL4Type(), protocolId)) {
			return header.bindHeader(packet, protocolId, depth, getL4Offset(), getL4Length());
		}

		return false;
	}

	/**
	 * Helper method to match L3 type to protocol ID.
	 */
	protected boolean matchesL3ProtocolId(int l3Type, int protocolId) {
		return switch (l3Type) {
		case L3_TYPE_IPV4 -> protocolId == ProtocolIds.PROTO_ID_IPV4;
		case L3_TYPE_IPV6 -> protocolId == ProtocolIds.PROTO_ID_IPV6;
		case L3_TYPE_ARP -> protocolId == ProtocolIds.PROTO_ID_ARP;
		default -> false;
		};
	}

	/**
	 * Helper method to match L4 type to protocol ID.
	 */
	protected boolean matchesL4ProtocolId(int l4Type, int protocolId) {
		return switch (l4Type) {
		case L4_TYPE_TCP -> protocolId == ProtocolIds.PROTO_ID_TCP;
		case L4_TYPE_UDP -> protocolId == ProtocolIds.PROTO_ID_UDP;
		case L4_TYPE_ICMP -> protocolId == ProtocolIds.PROTO_ID_ICMP;
		default -> false;
		};
	}
}