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

import java.nio.ByteOrder;

import com.slytechs.jnet.core.api.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.HeaderAccessor;
import com.slytechs.jnet.protocol.api.builtin.L2FrameType;
import com.slytechs.jnet.protocol.api.builtin.L3FrameType;
import com.slytechs.jnet.protocol.api.builtin.L4FrameType;

/**
 * Descriptor containing packet dissection results and protocol header metadata.
 * 
 * <p>
 * {@code PacketDescriptor} extends both {@link Descriptor} and
 * {@link HeaderAccessor} to provide comprehensive packet metadata along with
 * efficient header access capabilities. This interface is the primary
 * abstraction for storing and accessing the results of packet dissection in a
 * high-performance, cache-friendly format.
 * 
 * <h2>Architecture</h2>
 * 
 * <p>
 * A packet descriptor encapsulates:
 * <ol>
 * <li><strong>Packet Metrics:</strong> Capture and wire lengths</li>
 * <li><strong>Protocol Presence:</strong> Bitmasks indicating detected
 * protocols</li>
 * <li><strong>Header Locations:</strong> Offsets and lengths for each protocol
 * layer</li>
 * <li><strong>Hardware Offloads:</strong> TSO, checksum, and hash
 * information</li>
 * <li><strong>Processing Flags:</strong> Error conditions and special handling
 * markers</li>
 * </ol>
 * 
 * <h2>Memory Layout</h2>
 * 
 * <p>
 * PacketDescriptors are designed for optimal cache line usage:
 * 
 * <pre>
 * Cache Line 1 (64 bytes):
 * +--------+--------+--------+--------+
 * | Type   | ID     | Length | Flags  |  // 16 bytes
 * +--------+--------+--------+--------+
 * | CapLen | WireLen| L2Off  | L3Off  |  // 16 bytes
 * +--------+--------+--------+--------+
 * | L4Off  | L2Len  | L3Len  | L4Len  |  // 16 bytes
 * +--------+--------+--------+--------+
 * | Hash   | TSO    | Reserved        |  // 16 bytes
 * +--------+--------+--------+--------+
 * 
 * Cache Line 2+ (Protocol-specific data):
 * | Header presence masks              |
 * | Header offset/length pairs         |
 * | Extended metadata                  |
 * </pre>
 * 
 * <h2>Dissection Levels</h2>
 * 
 * <p>
 * The descriptor supports multiple dissection depths:
 * <ul>
 * <li><strong>L2 (Data Linked):</strong> Ethernet, VLAN, PPP</li>
 * <li><strong>L3 (Network):</strong> IPv4, IPv6, MPLS</li>
 * <li><strong>L4 (Transport):</strong> TCP, UDP, SCTP, ICMP</li>
 * <li><strong>L5+ (Application):</strong> HTTP, DNS, TLS (optional)</li>
 * </ul>
 * 
 * <h2>Usage Examples</h2>
 * 
 * <h3>Basic Packet Information</h3>
 * 
 * <pre>{@code
 * PacketDescriptor desc = packet.getPacketDescriptor();
 * 
 * // Get packet sizes
 * int captured = desc.captureLength();
 * int original = desc.wireLength();
 * 
 * if (captured < original) {
 * 	log.warn("Packet truncated: {} of {} bytes captured",
 * 			captured, original);
 * }
 * 
 * // Check for errors
 * long flags = desc.packetFlagBitmask();
 * if ((flags & PacketFlag.PKT_FLAG_CRC_ERROR) != 0) {
 * 	log.error("CRC error detected");
 * }
 * }</pre>
 * 
 * <h3>Layer Offset Access</h3>
 * 
 * <pre>{@code
 * // Direct layer access for fast processing
 * public void processLayers(PacketDescriptor desc, ByteBuffer packet) {
 * 	// Process L2 header
 * 	int l2Offset = desc.l2Offset();
 * 	int l2Length = desc.l2Length();
 * 	processEthernet(packet, l2Offset, l2Length);
 * 
 * 	// Process L3 header
 * 	int l3Offset = desc.l3Offset();
 * 	int l3Length = desc.l3Length();
 * 	if (l3Offset > 0) {
 * 		processIP(packet, l3Offset, l3Length);
 * 	}
 * 
 * 	// Process L4 header
 * 	int l4Offset = desc.l4Offset();
 * 	int l4Length = desc.l4Length();
 * 	if (l4Offset > 0) {
 * 		processTransport(packet, l4Offset, l4Length);
 * 	}
 * }
 * }</pre>
 * 
 * <h3>Hardware Offload Support</h3>
 * 
 * <pre>{@code
 * // TSO (TCP Segmentation Offload) handling
 * int tsoSize = desc.tsoSegmentSize();
 * if (tsoSize > 0) {
 * 	// Packet will be segmented by NIC
 * 	int segments = (desc.wireLength() + tsoSize - 1) / tsoSize;
 * 	log.info("TSO enabled: {} bytes -> {} segments of {} bytes",
 * 			desc.wireLength(), segments, tsoSize);
 * }
 * 
 * // Hardware hash for RSS (Receive Side Scaling)
 * long hash = desc.hash();
 * int queueIndex = (int) (hash % numQueues);
 * dispatchToQueue(packet, queueIndex);
 * }</pre>
 * 
 * <h3>Tunnel Support</h3>
 * 
 * <pre>{@code
 * // Handle tunneled packets (e.g., VXLAN, GRE)
 * public void processTunnel(PacketDescriptor desc) {
 * 	// Outer headers
 * 	int outerL2 = desc.l2OffsetOuter();
 * 	int outerL3 = desc.l3OffsetOuter();
 * 
 * 	if (outerL2 > 0 && outerL3 > 0) {
 * 		log.info("Tunnel detected: outer L2@{}, L3@{}",
 * 				outerL2, outerL3);
 * 
 * 		// Inner headers use standard offsets
 * 		int innerL2 = desc.l2Offset();
 * 		int innerL3 = desc.l3Offset();
 * 
 * 		// Process both outer and inner headers
 * 		processTunnelHeaders(desc);
 * 	}
 * }
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Descriptor
 * @see HeaderAccessor
 * @see PacketFlag
 * @since 1.0
 */
public interface OsiLayerDescriptor extends Descriptor {

	/** The default hash bit length. */
	int DEFAULT_HASH_BIT_LENGTH = 64;

	/**
	 * Encode length and offset.
	 *
	 * @param offset the offset
	 * @param length the length
	 * @return the long
	 */
	static long encodeLengthAndOffset(int offset, int length) {
		return ((long) length) << 32 | offset;
	}

	/**
	 * Returns the packet hash value for RSS and flow distribution.
	 * 
	 * <p>
	 * The hash is typically calculated by hardware based on packet headers (IP
	 * addresses, ports) and is used for:
	 * <ul>
	 * <li>RSS (Receive Side Scaling) queue selection</li>
	 * <li>Flow table lookups</li>
	 * <li>Load balancing across CPU cores</li>
	 * <li>Connection tracking</li>
	 * </ul>
	 * 
	 * <h3>Hash-Based Distribution</h3>
	 * 
	 * <pre>{@code
	 * public class PacketDistributor {
	 * 	private final int numQueues;
	 * 	private final PacketQueue[] queues;
	 * 
	 * 	public void distribute(PacketDescriptor desc) {
	 * 		long hash = desc.hash();
	 * 
	 * 		// Ensure same flow goes to same queue
	 * 		int queueIndex = (int) (hash % numQueues);
	 * 		queues[queueIndex].enqueue(desc);
	 * 
	 * 		// Log distribution for monitoring
	 * 		if (log.isTraceEnabled()) {
	 * 			log.trace("Packet hash {} -> queue {}",
	 * 					Long.toHexString(hash), queueIndex);
	 * 		}
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * <h3>Hash Types</h3>
	 * <p>
	 * Common hardware hash algorithms:
	 * <ul>
	 * <li><strong>Toeplitz:</strong> Microsoft RSS standard</li>
	 * <li><strong>CRC32:</strong> Simple and fast</li>
	 * <li><strong>Symmetric:</strong> Same hash for both directions</li>
	 * </ul>
	 * 
	 * @return the packet hash value, or 0 if not computed
	 */
	long hash();

	/**
	 * Hash bit length.
	 *
	 * @return the int
	 */
	default int hashBitLength() {
		return DEFAULT_HASH_BIT_LENGTH;
	}

	/**
	 * Returns the length of the Layer 3 header in bytes.
	 * 
	 * <p>
	 * For IPv4, this includes any options present. For IPv6, includes the base
	 * header but not extension headers (which are considered L4).
	 * 
	 * <h3>Typical L3 Header Sizes</h3>
	 * <ul>
	 * <li>IPv4: 20 bytes (no options) to 60 bytes (max options)</li>
	 * <li>IPv6: 40 bytes (fixed base header)</li>
	 * <li>MPLS: 4 bytes per label</li>
	 * </ul>
	 * 
	 * @return the L3 header length in bytes, or 0 if not present
	 * @see #l3Offset()
	 */
	int l3Length();

	/**
	 * Returns the length of the outer Layer 3 header in bytes.
	 * 
	 * <p>
	 * For tunneled packets, indicates the size of the encapsulating network layer
	 * header including any options or extensions.
	 * 
	 * @return the outer L3 header length, or 0 if not tunneled
	 * @see #l3OffsetOuter()
	 */
	int l3LengthOuter();

	/**
	 * Returns the offset to the Layer 3 (Network) header.
	 * 
	 * <p>
	 * This offset points to the beginning of the network layer protocol, typically
	 * IPv4 or IPv6. The offset accounts for all L2 headers including VLAN tags if
	 * present.
	 * 
	 * <h3>Calculation Example</h3>
	 * 
	 * <pre>{@code
	 * // Typical L3 offset calculation
	 * int l3Offset = 14; // Standard Ethernet header
	 * if (hasVlan)
	 * 	l3Offset += 4; // VLAN tag
	 * if (hasQinQ)
	 * 	l3Offset += 4; // Additional VLAN tag
	 * }</pre>
	 * 
	 * @return the byte offset to L3 header, or -1 if not present
	 * @see #l3Length()
	 */
	int l3Offset();

	/**
	 * Returns the offset to the outer Layer 3 header in tunneled packets.
	 * 
	 * <p>
	 * Points to the encapsulating network layer header in tunneled protocols. The
	 * inner L3 header is accessed via {@link #l3Offset()}.
	 * 
	 * @return the byte offset to outer L3 header, or -1 if not tunneled
	 * @see #l3Offset()
	 * @see #l3LengthOuter()
	 */
	int l3OffsetOuter();

	/**
	 * L3 frame type.
	 *
	 * @return the int
	 */
	int l3Type();

	/**
	 * L3 frame type as enum.
	 *
	 * @return the l 3 frame type
	 */
	default L3FrameType l3TypeAsEnum() {
		return L3FrameType.valueOf(l3Type());
	}

	/**
	 * Returns the length of the Layer 4 header in bytes.
	 * 
	 * <p>
	 * Includes the base transport header and any options. For protocols with
	 * variable-length headers, returns the actual header size.
	 * 
	 * <h3>Transport Header Sizes</h3>
	 * <ul>
	 * <li>TCP: 20 bytes (no options) to 60 bytes (with options)</li>
	 * <li>UDP: 8 bytes (fixed)</li>
	 * <li>SCTP: 12 bytes (common header) + chunks</li>
	 * <li>ICMP: 8 bytes (typical)</li>
	 * </ul>
	 * 
	 * @return the L4 header length in bytes, or 0 if not present
	 * @see #l4Offset()
	 */
	int l4Length();

	/**
	 * Returns the offset to the Layer 4 (Transport) header.
	 * 
	 * <p>
	 * Points to the transport protocol header (TCP, UDP, SCTP, etc.). The offset is
	 * calculated from the packet start, not from L3.
	 * 
	 * <h3>Example: Direct Transport Access</h3>
	 * 
	 * <pre>{@code
	 * int l4Off = desc.l4Offset();
	 * if (l4Off > 0) {
	 * 	// Read transport header directly
	 * 	int srcPort = packet.getShort(l4Off) & 0xFFFF;
	 * 	int dstPort = packet.getShort(l4Off + 2) & 0xFFFF;
	 * }
	 * }</pre>
	 * 
	 * @return the byte offset to L4 header, or -1 if not present
	 * @see #l4Length()
	 */
	int l4Offset();

	/**
	 * L4 frame type.
	 *
	 * @return the int
	 */
	int l4Type();

	/**
	 * L4 frame type as enum.
	 *
	 * @return the l 4 frame type
	 */
	default L4FrameType l4TypeAsEnum() {
		return L4FrameType.valueOf(l4Type());
	}
}
