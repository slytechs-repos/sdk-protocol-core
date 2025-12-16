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
 * Net2 Packet Descriptor - 48-byte descriptor for tunneled and
 * hardware-accelerated packets.
 * 
 * <p>
 * This descriptor extends Net1PacketDescriptor with support for tunnel
 * encapsulation and hardware offload features. It provides an additional
 * dynamic field (dynamic1) and extended information for tunnel metadata and
 * hardware acceleration flags. The design maintains 64-bit alignment for
 * optimal memory access patterns.
 * </p>
 * 
 * <h2>Memory Layout</h2>
 * 
 * <pre>
 * Offset  Size  Field          Description
 * ------------------------------------------------------
 * 0x00    32    net1_base      Net1PacketDescriptor (pcap + proto + dynamic0)
 * 0x20    8     dynamic1       Second configurable field
 * 0x28    8     extended_info  Tunnel metadata and offload flags
 * </pre>
 * 
 * <h2>DYNAMIC1 Field Configurations</h2>
 * 
 * <pre>
 * Default Configuration:
 * Bits [63-0]:  USER_DATA (64 bits)      - Application-specific data
 * 
 * Alternative - Inner Flow Hash:
 * Bits [51-0]:  INNER_HASH (52 bits)     - Inner packet hash
 * Bits [55-52]: INNER_COLOR (4 bits)     - Inner flow color
 * Bits [58-56]: HASH_BITS (3 bits)       - Hash size encoding
 * Bits [63-59]: HASH_TYPE (5 bits)       - Hash algorithm
 * 
 * Alternative - Extended Metadata:
 * Bits [31-0]:  METADATA_A (32 bits)     - Custom metadata A
 * Bits [63-32]: METADATA_B (32 bits)     - Custom metadata B
 * </pre>
 * 
 * <h2>DYNAMIC1 Field Configuration for Inner Packet Dissection</h2>
 * 
 * <pre>
 * When configured for inner packet dissection (mirrors proto_info structure):
 * Bits [4-0]:   INNER_L2_TYPE (5 bits)     - Inner L2 frame type
 * Bits [11-5]:  INNER_L2_LEN (7 bits)      - Inner L2 header length
 * Bits [15-12]: INNER_L3_TYPE (4 bits)     - Inner L3 protocol type
 * Bits [25-16]: INNER_L3_OFFSET (10 bits)  - Inner L3 offset from tunnel end
 * Bits [39-26]: INNER_L3_LEN (14 bits)     - Inner L3 total length
 * Bits [43-40]: INNER_L4_TYPE (4 bits)     - Inner L4 protocol type
 * Bits [53-44]: INNER_L4_OFFSET (10 bits)  - Inner L4 offset from tunnel end
 * Bits [61-54]: INNER_L4_LEN (8 bits)      - Inner L4 length (4-byte units)
 * Bit  [62]:    INNER_L4_PRESENT (1 bit)   - Inner L4 exists
 * Bit  [63]:    INNER_DISSECTED (1 bit)    - Dynamic1 contains dissection data
 * </pre>
 * 
 * *
 * <h2>EXTENDED_INFO Bit Layout (64 bits)</h2>
 * 
 * <pre>
 * Bits [3-0]:   TUNNEL_TYPE (4 bits)     - Tunnel protocol type
 * Bits [13-4]:  TUNNEL_OFFSET (10 bits)  - Offset to tunnel header
 * Bits [21-14]: TUNNEL_LEN (8 bits)      - Tunnel header length
 * Bits [45-22]: TUNNEL_ID (24 bits)      - VNI/Key/Tunnel identifier
 * Bits [47-46]: ENCAP_DEPTH (2 bits)     - Encapsulation depth (0-3)
 * 
 * Hardware Offload Flags:
 * Bit  [48]:    CHECKSUM_OFFLOAD         - HW checksum enabled
 * Bit  [49]:    TSO_ENABLED              - TCP segmentation offload
 * Bit  [50]:    RSS_HASH_VALID           - RSS hash computed
 * Bit  [51]:    VLAN_STRIPPED            - VLAN removed by HW
 * Bit  [52]:    LRO_AGGREGATED           - Large receive offload
 * 
 * Fragment Reassembly:
 * Bit  [53]:    FRAG_REASSEMBLED         - Packet was reassembled
 * Bits [61-54]: FRAG_CONTEXT_ID (8 bits) - Reassembly context
 * Bits [63-62]: RESERVED (2 bits)        - Future use
 * </pre>
 * 
 * <h2>Tunnel Type Encodings</h2>
 * 
 * <pre>
 * 0  - No tunnel
 * 1  - GRE
 * 2  - VXLAN
 * 3  - IP-in-IP
 * 4  - L2TP
 * 5  - MPLS
 * 6  - NVGRE
 * 7  - GENEVE
 * 8  - IPsec ESP
 * 9  - IPsec AH
 * 10 - GTP
 * </pre>
 * 
 * <h2>Usage Example</h2>
 * 
 * <pre>{@code
 * // Create descriptor for VXLAN-encapsulated packet
 * Net2PacketDescriptor desc = new Net2PacketDescriptor(TimestampUnit.PCAP_NANO);
 * 
 * // Set base packet info (outer headers via Net1)
 * desc.setTimestamp(System.nanoTime());
 * desc.setCaptureLength(totalLength);
 * desc.setL3Type(L3_TYPE_IPV4); // Outer IPv4
 * desc.setL3Offset(14); // After Ethernet
 * desc.setL4Type(L4_TYPE_UDP); // VXLAN over UDP
 * desc.setL4Offset(34); // After Eth + IP
 * 
 * // Configure tunnel information
 * desc.setTunnelType(TUNNEL_TYPE_VXLAN);
 * desc.setTunnelOffset(42); // After Eth + IP + UDP
 * desc.setTunnelLength(8); // VXLAN header size
 * desc.setTunnelId(0x123456); // VNI
 * 
 * // Set hash values for flow tracking
 * desc.setDynamic0Value(outerFlowHash); // Outer flow hash
 * desc.setDynamic1Value(innerFlowHash); // Inner flow hash
 * 
 * // Hardware offload flags
 * desc.setChecksumOffload(true);
 * desc.setRssHashValid(true);
 * 
 * // Access tunnel info
 * if (desc.getTunnelType() == TUNNEL_TYPE_VXLAN) {
 * 	int vni = desc.getTunnelId();
 * 	int innerPacketOffset = desc.getTunnelOffset() + desc.getTunnelLength();
 * }
 * }</pre>
 * 
 * <h2>Design Notes</h2>
 * <ul>
 * <li>Extends Net1 for backward compatibility while adding tunnel support</li>
 * <li>Two 64-bit dynamic fields provide 128 bits of configurable space</li>
 * <li>Hardware offload flags support modern NIC acceleration features</li>
 * <li>Single tunnel layer design covers most common use cases</li>
 * <li>Fragment reassembly support for hardware that performs this function</li>
 * <li>Maintains 64-bit alignment throughout for optimal performance</li>
 * </ul>
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 * @see Net1PacketDescriptor
 * @see NetPacketDescriptor
 */
public class Net2PacketDescriptor
		extends Net1PacketDescriptor
		implements PacketDescriptor, StructFormattable {

	// Memory Layout - extends Net1PacketDescriptor
	public static final MemoryLayout LAYOUT = structLayout(
			Net1PacketDescriptor.LAYOUT.withName("net1_base"), // 32 bytes
			U64.withName("dynamic1"), // 8 bytes
			U64.withName("extended_info") // 8 bytes
	);

	// VarHandles for Net2-specific fields
	private static final VarHandle DYNAMIC1 = LAYOUT.varHandle(groupElement("dynamic1"));
	private static final VarHandle EXTENDED_INFO = LAYOUT.varHandle(groupElement("extended_info"));

	// extended_info bit positions - Tunnel information (lower 48 bits)
	private static final long TUNNEL_TYPE_MASK = 0xFL; // 4 bits: 0-3
	private static final int TUNNEL_OFFSET_SHIFT = 4;
	private static final long TUNNEL_OFFSET_MASK = 0x3FFL; // 10 bits: 4-13
	private static final int TUNNEL_LEN_SHIFT = 14;
	private static final long TUNNEL_LEN_MASK = 0xFFL; // 8 bits: 14-21
	private static final int TUNNEL_ID_SHIFT = 22;
	private static final long TUNNEL_ID_MASK = 0xFFFFFFL; // 24 bits: 22-45
	private static final int ENCAP_DEPTH_SHIFT = 46;
	private static final long ENCAP_DEPTH_MASK = 0x3L; // 2 bits: 46-47

	// Hardware offload flags (bits 48-52)
	private static final int CHECKSUM_OFFLOAD_BIT = 48;
	private static final int TSO_ENABLED_BIT = 49;
	private static final int RSS_HASH_VALID_BIT = 50;
	private static final int VLAN_STRIPPED_BIT = 51;
	private static final int LRO_AGGREGATED_BIT = 52;

	// Fragment reassembly (bits 53-61)
	private static final int FRAG_REASSEMBLED_BIT = 53;
	private static final int FRAG_CONTEXT_ID_SHIFT = 54;
	private static final long FRAG_CONTEXT_ID_MASK = 0xFFL; // 8 bits: 54-61
	// Bits 62-63 reserved

	// Tunnel type constants
	public static final int TUNNEL_TYPE_NONE = 0;
	public static final int TUNNEL_TYPE_GRE = 1;
	public static final int TUNNEL_TYPE_VXLAN = 2;
	public static final int TUNNEL_TYPE_IPINIP = 3;
	public static final int TUNNEL_TYPE_L2TP = 4;
	public static final int TUNNEL_TYPE_MPLS = 5;
	public static final int TUNNEL_TYPE_NVGRE = 6;
	public static final int TUNNEL_TYPE_GENEVE = 7;
	public static final int TUNNEL_TYPE_IPSEC_ESP = 8;
	public static final int TUNNEL_TYPE_IPSEC_AH = 9;
	public static final int TUNNEL_TYPE_GTP = 10;

	/**
	 * Creates a Net2PacketDescriptor with default timestamp unit.
	 */
	public Net2PacketDescriptor() {
		super();
	}

	/**
	 * Creates a Net2PacketDescriptor with specified L2 type and timestamp unit.
	 *
	 * @param l2Type        the L2 frame type
	 * @param timestampUnit the timestamp unit to use
	 */
	public Net2PacketDescriptor(L2FrameType l2Type, TimestampUnit timestampUnit) {
		super(l2Type, timestampUnit);
	}

	/**
	 * Creates a Net2PacketDescriptor with specified timestamp unit.
	 * 
	 * @param timestampUnit the timestamp unit to use
	 */
	public Net2PacketDescriptor(TimestampUnit timestampUnit) {
		super(timestampUnit);
	}

	@Override
	public int descriptorId() {
		return DescriptorType.DESCRIPTOR_TYPE_NET2.getValue();
	}

	// Formatting
	@Override
	public StructFormat format(StructFormat p) {
		p = super.format(p); // Format Net1 fields

		p.println("=== Net2 Extended Information ===");

		// Tunnel information
		if (getTunnelType() != TUNNEL_TYPE_NONE) {
			p.println("=== Tunnel Information ===");
			p.println("tunnelType", getTunnelTypeString(getTunnelType()));
			p.println("tunnelOffset", getTunnelOffset());
			p.println("tunnelLength", getTunnelLength());
			p.println("tunnelId", String.format("0x%06X", getTunnelId()));
			if (getEncapsulationDepth() > 0) {
				p.println("encapsulationDepth", getEncapsulationDepth());
			}
		}

		// Hardware offload
		if (isChecksumOffload() || isTsoEnabled() || isRssHashValid() ||
				isVlanStripped() || isLroAggregated()) {
			p.println("=== Hardware Offload ===");
			if (isChecksumOffload())
				p.println("checksumOffload", true);
			if (isTsoEnabled())
				p.println("tsoEnabled", true);
			if (isRssHashValid())
				p.println("rssHashValid", true);
			if (isVlanStripped())
				p.println("vlanStripped", true);
			if (isLroAggregated())
				p.println("lroAggregated", true);
		}

		// Fragment reassembly
		if (isFragmentReassembled()) {
			p.println("=== Fragment Reassembly ===");
			p.println("fragmentReassembled", true);
			p.println("fragmentContextId", getFragmentContextId());
		}

		// Dynamic fields
		p.println("=== Dynamic Fields ===");
		p.println("dynamic0", String.format("0x%016X", getDynamic0Value()));
		p.println("dynamic1", String.format("0x%016X", getDynamic1Value()));

		return p;
	}

	// Helper methods for field access
	private long getDynamic1() {
		return (long) DYNAMIC1.get(segment(), view().start());
	}

	/**
	 * Gets the entire dynamic1 field value.
	 * 
	 * @return 64-bit dynamic field value
	 */
	public long getDynamic1Value() {
		return getDynamic1();
	}

	// Dynamic1 field accessors

	/**
	 * Gets the encapsulation depth.
	 * 
	 * @return number of encapsulation layers (0-3)
	 */
	public int getEncapsulationDepth() {
		return (int) ((getExtendedInfo() >> ENCAP_DEPTH_SHIFT) & ENCAP_DEPTH_MASK);
	}

	private long getExtendedInfo() {
		return (long) EXTENDED_INFO.get(segment(), view().start());
	}

	// Tunnel information accessors

	/**
	 * Gets the fragment reassembly context ID.
	 * 
	 * @return context ID (0-255)
	 */
	public int getFragmentContextId() {
		return (int) ((getExtendedInfo() >> FRAG_CONTEXT_ID_SHIFT) & FRAG_CONTEXT_ID_MASK);
	}

	/**
	 * Gets the tunnel identifier (VNI/Key/ID).
	 * 
	 * @return tunnel ID (24 bits)
	 */
	public int getTunnelId() {
		return (int) ((getExtendedInfo() >> TUNNEL_ID_SHIFT) & TUNNEL_ID_MASK);
	}

	/**
	 * Gets the tunnel header length.
	 * 
	 * @return tunnel header length in bytes
	 */
	public int getTunnelLength() {
		return (int) ((getExtendedInfo() >> TUNNEL_LEN_SHIFT) & TUNNEL_LEN_MASK);
	}

	/**
	 * Gets the offset to the tunnel header.
	 * 
	 * @return tunnel header offset in bytes
	 */
	public int getTunnelOffset() {
		return (int) ((getExtendedInfo() >> TUNNEL_OFFSET_SHIFT) & TUNNEL_OFFSET_MASK);
	}

	/**
	 * Gets the tunnel protocol type.
	 * 
	 * @return tunnel type (0-15)
	 */
	public int getTunnelType() {
		return (int) (getExtendedInfo() & TUNNEL_TYPE_MASK);
	}

	// Helper method for tunnel type string conversion
	private String getTunnelTypeString(int type) {
		return switch (type) {
		case TUNNEL_TYPE_NONE -> "None";
		case TUNNEL_TYPE_GRE -> "GRE";
		case TUNNEL_TYPE_VXLAN -> "VXLAN";
		case TUNNEL_TYPE_IPINIP -> "IP-in-IP";
		case TUNNEL_TYPE_L2TP -> "L2TP";
		case TUNNEL_TYPE_MPLS -> "MPLS";
		case TUNNEL_TYPE_NVGRE -> "NVGRE";
		case TUNNEL_TYPE_GENEVE -> "GENEVE";
		case TUNNEL_TYPE_IPSEC_ESP -> "IPsec ESP";
		case TUNNEL_TYPE_IPSEC_AH -> "IPsec AH";
		case TUNNEL_TYPE_GTP -> "GTP";
		default -> "Unknown(" + type + ")";
		};
	}

	/**
	 * Checks if hardware checksum offload is enabled.
	 * 
	 * @return true if checksum offload is enabled
	 */
	public boolean isChecksumOffload() {
		return (getExtendedInfo() & (1L << CHECKSUM_OFFLOAD_BIT)) != 0;
	}

	/**
	 * Checks if packet was reassembled from fragments.
	 * 
	 * @return true if reassembled
	 */
	public boolean isFragmentReassembled() {
		return (getExtendedInfo() & (1L << FRAG_REASSEMBLED_BIT)) != 0;
	}

	/**
	 * Checks if packet was aggregated by LRO.
	 * 
	 * @return true if LRO aggregated
	 */
	public boolean isLroAggregated() {
		return (getExtendedInfo() & (1L << LRO_AGGREGATED_BIT)) != 0;
	}

	/**
	 * Checks if RSS hash is valid.
	 * 
	 * @return true if RSS hash was computed
	 */
	public boolean isRssHashValid() {
		return (getExtendedInfo() & (1L << RSS_HASH_VALID_BIT)) != 0;
	}

	// Hardware offload flags

	/**
	 * Checks if TCP segmentation offload is enabled.
	 * 
	 * @return true if TSO is enabled
	 */
	public boolean isTsoEnabled() {
		return (getExtendedInfo() & (1L << TSO_ENABLED_BIT)) != 0;
	}

	/**
	 * Checks if VLAN was stripped by hardware.
	 * 
	 * @return true if VLAN was stripped
	 */
	public boolean isVlanStripped() {
		return (getExtendedInfo() & (1L << VLAN_STRIPPED_BIT)) != 0;
	}

	@Override
	public long length() {
		return LAYOUT.byteSize();
	}

	/**
	 * Sets hardware checksum offload flag.
	 * 
	 * @param enabled true to enable checksum offload
	 */
	public void setChecksumOffload(boolean enabled) {
		long info = getExtendedInfo();
		if (enabled) {
			info |= (1L << CHECKSUM_OFFLOAD_BIT);
		} else {
			info &= ~(1L << CHECKSUM_OFFLOAD_BIT);
		}
		setExtendedInfo(info);
	}

	private void setDynamic1(long value) {
		DYNAMIC1.set(segment(), view().start(), value);
	}

	/**
	 * Sets the entire dynamic1 field value.
	 * 
	 * @param value 64-bit dynamic field value
	 */
	public void setDynamic1Value(long value) {
		setDynamic1(value);
	}

	/**
	 * Sets the encapsulation depth.
	 * 
	 * @param depth number of encapsulation layers (0-3)
	 */
	public void setEncapsulationDepth(int depth) {
		long info = getExtendedInfo();
		info &= ~(ENCAP_DEPTH_MASK << ENCAP_DEPTH_SHIFT);
		info |= ((depth & ENCAP_DEPTH_MASK) << ENCAP_DEPTH_SHIFT);
		setExtendedInfo(info);
	}

	private void setExtendedInfo(long value) {
		EXTENDED_INFO.set(segment(), view().start(), value);
	}

	/**
	 * Sets the fragment reassembly context ID.
	 * 
	 * @param id context ID (0-255)
	 */
	public void setFragmentContextId(int id) {
		long info = getExtendedInfo();
		info &= ~(FRAG_CONTEXT_ID_MASK << FRAG_CONTEXT_ID_SHIFT);
		info |= ((id & FRAG_CONTEXT_ID_MASK) << FRAG_CONTEXT_ID_SHIFT);
		setExtendedInfo(info);
	}

	/**
	 * Sets fragment reassembled flag.
	 * 
	 * @param reassembled true if packet was reassembled
	 */
	public void setFragmentReassembled(boolean reassembled) {
		long info = getExtendedInfo();
		if (reassembled) {
			info |= (1L << FRAG_REASSEMBLED_BIT);
		} else {
			info &= ~(1L << FRAG_REASSEMBLED_BIT);
		}
		setExtendedInfo(info);
	}

	// Fragment reassembly

	/**
	 * Sets LRO aggregated flag.
	 * 
	 * @param aggregated true if LRO aggregated
	 */
	public void setLroAggregated(boolean aggregated) {
		long info = getExtendedInfo();
		if (aggregated) {
			info |= (1L << LRO_AGGREGATED_BIT);
		} else {
			info &= ~(1L << LRO_AGGREGATED_BIT);
		}
		setExtendedInfo(info);
	}

	/**
	 * Sets RSS hash valid flag.
	 * 
	 * @param valid true if RSS hash is valid
	 */
	public void setRssHashValid(boolean valid) {
		long info = getExtendedInfo();
		if (valid) {
			info |= (1L << RSS_HASH_VALID_BIT);
		} else {
			info &= ~(1L << RSS_HASH_VALID_BIT);
		}
		setExtendedInfo(info);
	}

	/**
	 * Sets TCP segmentation offload flag.
	 * 
	 * @param enabled true to enable TSO
	 */
	public void setTsoEnabled(boolean enabled) {
		long info = getExtendedInfo();
		if (enabled) {
			info |= (1L << TSO_ENABLED_BIT);
		} else {
			info &= ~(1L << TSO_ENABLED_BIT);
		}
		setExtendedInfo(info);
	}

	/**
	 * Sets the tunnel identifier (VNI/Key/ID).
	 * 
	 * @param id tunnel ID (24 bits)
	 */
	public void setTunnelId(int id) {
		long info = getExtendedInfo();
		info &= ~(TUNNEL_ID_MASK << TUNNEL_ID_SHIFT);
		info |= ((id & TUNNEL_ID_MASK) << TUNNEL_ID_SHIFT);
		setExtendedInfo(info);
	}

	/**
	 * Sets the tunnel header length.
	 * 
	 * @param length tunnel header length in bytes
	 */
	public void setTunnelLength(int length) {
		long info = getExtendedInfo();
		info &= ~(TUNNEL_LEN_MASK << TUNNEL_LEN_SHIFT);
		info |= ((length & TUNNEL_LEN_MASK) << TUNNEL_LEN_SHIFT);
		setExtendedInfo(info);
	}

	/**
	 * Sets the offset to the tunnel header.
	 * 
	 * @param offset tunnel header offset in bytes
	 */
	public void setTunnelOffset(int offset) {
		long info = getExtendedInfo();
		info &= ~(TUNNEL_OFFSET_MASK << TUNNEL_OFFSET_SHIFT);
		info |= ((offset & TUNNEL_OFFSET_MASK) << TUNNEL_OFFSET_SHIFT);
		setExtendedInfo(info);
	}

	/**
	 * Sets the tunnel protocol type.
	 * 
	 * @param type tunnel type (0-15)
	 */
	public void setTunnelType(int type) {
		long info = getExtendedInfo();
		info = (info & ~TUNNEL_TYPE_MASK) | (type & TUNNEL_TYPE_MASK);
		setExtendedInfo(info);
	}

	/**
	 * Sets VLAN stripped flag.
	 * 
	 * @param stripped true if VLAN was stripped
	 */
	public void setVlanStripped(boolean stripped) {
		long info = getExtendedInfo();
		if (stripped) {
			info |= (1L << VLAN_STRIPPED_BIT);
		} else {
			info &= ~(1L << VLAN_STRIPPED_BIT);
		}
		setExtendedInfo(info);
	}

	@Override
	public String toString() {
		return format(new StructFormat()).toString();
	}

	// Descriptor type and identification
	@Override
	public DescriptorType type() {
		return DescriptorType.DESCRIPTOR_TYPE_NET2;
	}

	// Add these constants to Net2PacketDescriptor class

	// Dynamic1 configured for inner packet dissection (mirrors proto_info layout)
	private static final long INNER_L2_TYPE_MASK = 0x1FL; // 5 bits: 0-4
	private static final int INNER_L2_LEN_SHIFT = 5;
	private static final long INNER_L2_LEN_MASK = 0x7FL; // 7 bits: 5-11
	private static final int INNER_L3_TYPE_SHIFT = 12;
	private static final long INNER_L3_TYPE_MASK = 0xFL; // 4 bits: 12-15
	private static final int INNER_L3_OFFSET_SHIFT = 16;
	private static final long INNER_L3_OFFSET_MASK = 0x3FFL; // 10 bits: 16-25
	private static final int INNER_L3_LEN_SHIFT = 26;
	private static final long INNER_L3_LEN_MASK = 0x3FFFL; // 14 bits: 26-39
	private static final int INNER_L4_TYPE_SHIFT = 40;
	private static final long INNER_L4_TYPE_MASK = 0xFL; // 4 bits: 40-43
	private static final int INNER_L4_OFFSET_SHIFT = 44;
	private static final long INNER_L4_OFFSET_MASK = 0x3FFL; // 10 bits: 44-53
	private static final int INNER_L4_LEN_SHIFT = 54;
	private static final long INNER_L4_LEN_MASK = 0xFFL; // 8 bits: 54-61
	private static final int INNER_L4_PRESENT_BIT = 62; // 1 bit: 62
	private static final int INNER_DISSECTED_BIT = 63; // 1 bit: 63

	// Inner packet dissection methods

	/**
	 * Checks if dynamic1 contains inner packet dissection data.
	 * 
	 * @return true if inner packet has been dissected
	 */
	public boolean isInnerDissected() {
		return (getDynamic1() & (1L << INNER_DISSECTED_BIT)) != 0;
	}

	/**
	 * Sets the inner dissected flag.
	 * 
	 * @param dissected true if dynamic1 contains dissection data
	 */
	public void setInnerDissected(boolean dissected) {
		long dynamic1 = getDynamic1();
		if (dissected) {
			dynamic1 |= (1L << INNER_DISSECTED_BIT);
		} else {
			dynamic1 &= ~(1L << INNER_DISSECTED_BIT);
		}
		setDynamic1(dynamic1);
	}

	// Inner L2 accessors
	public int getInnerL2Type() {
		return (int) (getDynamic1() & INNER_L2_TYPE_MASK);
	}

	public void setInnerL2Type(int type) {
		long dynamic1 = getDynamic1();
		dynamic1 = (dynamic1 & ~INNER_L2_TYPE_MASK) | (type & INNER_L2_TYPE_MASK);
		setDynamic1(dynamic1);
	}

	public int getInnerL2Length() {
		return (int) ((getDynamic1() >> INNER_L2_LEN_SHIFT) & INNER_L2_LEN_MASK);
	}

	public void setInnerL2Length(int length) {
		long dynamic1 = getDynamic1();
		dynamic1 &= ~(INNER_L2_LEN_MASK << INNER_L2_LEN_SHIFT);
		dynamic1 |= ((length & INNER_L2_LEN_MASK) << INNER_L2_LEN_SHIFT);
		setDynamic1(dynamic1);
	}

	// Inner L3 accessors
	public int getInnerL3Type() {
		return (int) ((getDynamic1() >> INNER_L3_TYPE_SHIFT) & INNER_L3_TYPE_MASK);
	}

	public void setInnerL3Type(int type) {
		long dynamic1 = getDynamic1();
		dynamic1 &= ~(INNER_L3_TYPE_MASK << INNER_L3_TYPE_SHIFT);
		dynamic1 |= ((type & INNER_L3_TYPE_MASK) << INNER_L3_TYPE_SHIFT);
		setDynamic1(dynamic1);
	}

	public int getInnerL3Offset() {
		return (int) ((getDynamic1() >> INNER_L3_OFFSET_SHIFT) & INNER_L3_OFFSET_MASK);
	}

	public void setInnerL3Offset(int offset) {
		long dynamic1 = getDynamic1();
		dynamic1 &= ~(INNER_L3_OFFSET_MASK << INNER_L3_OFFSET_SHIFT);
		dynamic1 |= ((offset & INNER_L3_OFFSET_MASK) << INNER_L3_OFFSET_SHIFT);
		setDynamic1(dynamic1);
	}

	public int getInnerL3Length() {
		return (int) ((getDynamic1() >> INNER_L3_LEN_SHIFT) & INNER_L3_LEN_MASK);
	}

	public void setInnerL3Length(int length) {
		long dynamic1 = getDynamic1();
		dynamic1 &= ~(INNER_L3_LEN_MASK << INNER_L3_LEN_SHIFT);
		dynamic1 |= ((length & INNER_L3_LEN_MASK) << INNER_L3_LEN_SHIFT);
		setDynamic1(dynamic1);
	}

	// Inner L4 accessors
	public int getInnerL4Type() {
		return (int) ((getDynamic1() >> INNER_L4_TYPE_SHIFT) & INNER_L4_TYPE_MASK);
	}

	public void setInnerL4Type(int type) {
		long dynamic1 = getDynamic1();
		dynamic1 &= ~(INNER_L4_TYPE_MASK << INNER_L4_TYPE_SHIFT);
		dynamic1 |= ((type & INNER_L4_TYPE_MASK) << INNER_L4_TYPE_SHIFT);
		setDynamic1(dynamic1);
	}

	public int getInnerL4Offset() {
		return (int) ((getDynamic1() >> INNER_L4_OFFSET_SHIFT) & INNER_L4_OFFSET_MASK);
	}

	public void setInnerL4Offset(int offset) {
		long dynamic1 = getDynamic1();
		dynamic1 &= ~(INNER_L4_OFFSET_MASK << INNER_L4_OFFSET_SHIFT);
		dynamic1 |= ((offset & INNER_L4_OFFSET_MASK) << INNER_L4_OFFSET_SHIFT);
		setDynamic1(dynamic1);
	}

	public int getInnerL4Length() {
		return (int) ((getDynamic1() >> INNER_L4_LEN_SHIFT) & INNER_L4_LEN_MASK) * 4;
	}

	public void setInnerL4Length(int length) {
		long dynamic1 = getDynamic1();
		int units = length / 4;
		dynamic1 &= ~(INNER_L4_LEN_MASK << INNER_L4_LEN_SHIFT);
		dynamic1 |= ((units & INNER_L4_LEN_MASK) << INNER_L4_LEN_SHIFT);
		setDynamic1(dynamic1);
	}

	public boolean isInnerL4Present() {
		return (getDynamic1() & (1L << INNER_L4_PRESENT_BIT)) != 0;
	}

	public void setInnerL4Present(boolean present) {
		long dynamic1 = getDynamic1();
		if (present) {
			dynamic1 |= (1L << INNER_L4_PRESENT_BIT);
		} else {
			dynamic1 &= ~(1L << INNER_L4_PRESENT_BIT);
		}
		setDynamic1(dynamic1);
	}

	// Updated bindProtocol method with inner dissection support
	@Override
	public boolean bindProtocol(ByteBuf packet, Header header, int protocolId, int depth) {
		if (depth == 0) {
			// Depth 0: Outer packet - delegate to Net1 or check tunnel
			if (super.bindProtocol(packet, header, protocolId, depth)) {
				return true;
			}

			// Check tunnel protocol itself
			if (matchesTunnelProtocolId(getTunnelType(), protocolId)) {
				return header.bindHeader(packet, protocolId, depth,
						getTunnelOffset(), getTunnelLength());
			}

			return false;
		} else if (depth == 1) {
			// Depth 1: Inner packet
			if (getTunnelType() == TUNNEL_TYPE_NONE) {
				return false; // No tunnel, no depth 1
			}

			// Check if inner dissection data is available
			if (!isInnerDissected()) {
				return false; // Inner packet not dissected
			}

			// Calculate base offset for inner packet (after tunnel header)
			int baseOffset = getTunnelOffset() + getTunnelLength();

			// Check inner L2
			int innerL2Type = getInnerL2Type();
			if (innerL2Type != 0 && matchesL2ProtocolId(innerL2Type, protocolId)) {
				return header.bindHeader(packet, protocolId, depth,
						baseOffset, getInnerL2Length());
			}

			// Check inner L3
			if (matchesL3ProtocolId(getInnerL3Type(), protocolId)) {
				return header.bindHeader(packet, protocolId, depth,
						baseOffset + getInnerL3Offset(), getInnerL3Length());
			}

			// Check inner L4
			if (isInnerL4Present() && matchesL4ProtocolId(getInnerL4Type(), protocolId)) {
				return header.bindHeader(packet, protocolId, depth,
						baseOffset + getInnerL4Offset(), getInnerL4Length());
			}

			return false;
		} else {
			// Depth > 1 not supported
			return false;
		}
	}
	// Add these methods to Net2PacketDescriptor class

	/**
	 * Helper method to match L2 type to protocol ID. This is needed for inner
	 * packet matching.
	 */
	protected boolean matchesL2ProtocolId(int l2Type, int protocolId) {
		return switch (l2Type) {
		case L2_TYPE_ETHERNET -> protocolId == ProtocolIds.PROTO_ID_ETHERNET;
		case L2_TYPE_802_3 -> protocolId == ProtocolIds.PROTO_ID_IEEE8023;
		case L2_TYPE_LLC -> protocolId == ProtocolIds.PROTO_ID_LLC;
		case L2_TYPE_SNAP -> protocolId == ProtocolIds.PROTO_ID_SNAP;
		default -> false;
		};
	}

	/**
	 * Helper method to match tunnel type to protocol ID.
	 */
	protected boolean matchesTunnelProtocolId(int tunnelType, int protocolId) {
		return switch (tunnelType) {
		case TUNNEL_TYPE_GRE -> protocolId == ProtocolIds.PROTO_ID_GRE;
		case TUNNEL_TYPE_VXLAN -> protocolId == ProtocolIds.PROTO_ID_VXLAN;
		case TUNNEL_TYPE_IPINIP -> protocolId == ProtocolIds.PROTO_ID_IP_IN_IP;
		case TUNNEL_TYPE_L2TP -> protocolId == ProtocolIds.PROTO_ID_L2TP;
		case TUNNEL_TYPE_MPLS -> protocolId == ProtocolIds.PROTO_ID_MPLS;
		case TUNNEL_TYPE_NVGRE -> protocolId == ProtocolIds.PROTO_ID_NVGRE;
		case TUNNEL_TYPE_GENEVE -> protocolId == ProtocolIds.PROTO_ID_GENEVE;
		case TUNNEL_TYPE_IPSEC_ESP -> protocolId == ProtocolIds.PROTO_ID_ESP;
		case TUNNEL_TYPE_IPSEC_AH -> protocolId == ProtocolIds.PROTO_ID_AH;
		case TUNNEL_TYPE_GTP -> protocolId == ProtocolIds.PROTO_ID_GTP;
		default -> false;
		};
	}
}