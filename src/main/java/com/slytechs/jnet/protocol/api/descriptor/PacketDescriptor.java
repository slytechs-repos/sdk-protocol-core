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

import com.slytechs.jnet.protocol.api.HeaderAccessor;

/**
 * Descriptor containing packet dissection results and protocol header metadata.
 * 
 * <p>{@code PacketDescriptor} extends both {@link Descriptor} and {@link HeaderAccessor}
 * to provide comprehensive packet metadata along with efficient header access capabilities.
 * This interface is the primary abstraction for storing and accessing the results of
 * packet dissection in a high-performance, cache-friendly format.
 * 
 * <h2>Architecture</h2>
 * 
 * <p>A packet descriptor encapsulates:
 * <ol>
 *   <li><strong>Packet Metrics:</strong> Capture and wire lengths</li>
 *   <li><strong>Protocol Presence:</strong> Bitmasks indicating detected protocols</li>
 *   <li><strong>Header Locations:</strong> Offsets and lengths for each protocol layer</li>
 *   <li><strong>Hardware Offloads:</strong> TSO, checksum, and hash information</li>
 *   <li><strong>Processing Flags:</strong> Error conditions and special handling markers</li>
 * </ol>
 * 
 * <h2>Memory Layout</h2>
 * 
 * <p>PacketDescriptors are designed for optimal cache line usage:
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
 * <p>The descriptor supports multiple dissection depths:
 * <ul>
 *   <li><strong>L2 (Data Link):</strong> Ethernet, VLAN, PPP</li>
 *   <li><strong>L3 (Network):</strong> IPv4, IPv6, MPLS</li>
 *   <li><strong>L4 (Transport):</strong> TCP, UDP, SCTP, ICMP</li>
 *   <li><strong>L5+ (Application):</strong> HTTP, DNS, TLS (optional)</li>
 * </ul>
 * 
 * <h2>Usage Examples</h2>
 * 
 * <h3>Basic Packet Information</h3>
 * <pre>{@code
 * PacketDescriptor desc = packet.getPacketDescriptor();
 * 
 * // Get packet sizes
 * int captured = desc.captureLength();
 * int original = desc.wireLength();
 * 
 * if (captured < original) {
 *     log.warn("Packet truncated: {} of {} bytes captured", 
 *              captured, original);
 * }
 * 
 * // Check for errors
 * long flags = desc.packetFlagBitmask();
 * if ((flags & PacketFlag.PKT_FLAG_CRC_ERROR) != 0) {
 *     log.error("CRC error detected");
 * }
 * }</pre>
 * 
 * <h3>Layer Offset Access</h3>
 * <pre>{@code
 * // Direct layer access for fast processing
 * public void processLayers(PacketDescriptor desc, ByteBuffer packet) {
 *     // Process L2 header
 *     int l2Offset = desc.l2Offset();
 *     int l2Length = desc.l2Length();
 *     processEthernet(packet, l2Offset, l2Length);
 *     
 *     // Process L3 header
 *     int l3Offset = desc.l3Offset();
 *     int l3Length = desc.l3Length();
 *     if (l3Offset > 0) {
 *         processIP(packet, l3Offset, l3Length);
 *     }
 *     
 *     // Process L4 header
 *     int l4Offset = desc.l4Offset();
 *     int l4Length = desc.l4Length();
 *     if (l4Offset > 0) {
 *         processTransport(packet, l4Offset, l4Length);
 *     }
 * }
 * }</pre>
 * 
 * <h3>Hardware Offload Support</h3>
 * <pre>{@code
 * // TSO (TCP Segmentation Offload) handling
 * int tsoSize = desc.tsoSegmentSize();
 * if (tsoSize > 0) {
 *     // Packet will be segmented by NIC
 *     int segments = (desc.wireLength() + tsoSize - 1) / tsoSize;
 *     log.info("TSO enabled: {} bytes -> {} segments of {} bytes",
 *              desc.wireLength(), segments, tsoSize);
 * }
 * 
 * // Hardware hash for RSS (Receive Side Scaling)
 * long hash = desc.hash();
 * int queueIndex = (int) (hash % numQueues);
 * dispatchToQueue(packet, queueIndex);
 * }</pre>
 * 
 * <h3>Tunnel Support</h3>
 * <pre>{@code
 * // Handle tunneled packets (e.g., VXLAN, GRE)
 * public void processTunnel(PacketDescriptor desc) {
 *     // Outer headers
 *     int outerL2 = desc.l2OffsetOuter();
 *     int outerL3 = desc.l3OffsetOuter();
 *     
 *     if (outerL2 > 0 && outerL3 > 0) {
 *         log.info("Tunnel detected: outer L2@{}, L3@{}", 
 *                  outerL2, outerL3);
 *         
 *         // Inner headers use standard offsets
 *         int innerL2 = desc.l2Offset();
 *         int innerL3 = desc.l3Offset();
 *         
 *         // Process both outer and inner headers
 *         processTunnelHeaders(desc);
 *     }
 * }
 * }</pre>
 * 
 * @see Descriptor
 * @see HeaderAccessor
 * @see PacketFlag
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public interface PacketDescriptor extends Descriptor, HeaderAccessor {

	/**
	 * Returns the number of bytes captured for this packet.
	 * 
	 * <p>The capture length represents the actual number of bytes available
	 * for processing. This may be less than the wire length if the packet
	 * was truncated due to snapshot length (snaplen) settings during capture.
	 * 
	 * <h3>Capture Length Scenarios</h3>
	 * <ul>
	 *   <li><strong>Full capture:</strong> captureLength == wireLength</li>
	 *   <li><strong>Truncated:</strong> captureLength < wireLength (snaplen limited)</li>
	 *   <li><strong>Jumbo frames:</strong> captureLength may exceed standard MTU</li>
	 *   <li><strong>Minimum:</strong> typically 14 bytes (Ethernet header)</li>
	 * </ul>
	 * 
	 * <h3>Example: Validating Capture Length</h3>
	 * <pre>{@code
	 * public boolean isCompletePacket(PacketDescriptor desc) {
	 *     int captured = desc.captureLength();
	 *     int wire = desc.wireLength();
	 *     
	 *     if (captured < wire) {
	 *         // Packet was truncated during capture
	 *         double percentage = (captured * 100.0) / wire;
	 *         log.debug("Truncated packet: {:.1f}% captured", percentage);
	 *         return false;
	 *     }
	 *     
	 *     return true;
	 * }
	 * }</pre>
	 * 
	 * @return the number of bytes captured, always positive
	 * @see #wireLength()
	 * @see #setCaptureLength(int)
	 */
	int captureLength();

	/**
	 * Sets the capture length for this packet descriptor.
	 * 
	 * <p>This method is typically called by the dissector or capture engine
	 * when creating or updating the descriptor. The capture length must not
	 * exceed the available buffer size and should reflect the actual bytes
	 * available for processing.
	 * 
	 * <h3>Validation Requirements</h3>
	 * <pre>{@code
	 * public void setCaptureLength(int length) {
	 *     if (length < MIN_PACKET_SIZE) {
	 *         throw new IllegalArgumentException(
	 *             "Capture length below minimum: " + length);
	 *     }
	 *     if (length > MAX_PACKET_SIZE) {
	 *         throw new IllegalArgumentException(
	 *             "Capture length exceeds maximum: " + length);
	 *     }
	 *     this.captureLength = length;
	 * }
	 * }</pre>
	 * 
	 * @param length the capture length in bytes, must be positive
	 * @throws IllegalArgumentException if length is invalid
	 * @see #captureLength()
	 */
	void setCaptureLength(int length);

	/**
	 * Returns the original length of the packet on the wire.
	 * 
	 * <p>The wire length represents the packet's actual size as transmitted
	 * on the network, regardless of capture truncation. This value is essential
	 * for accurate statistics and bandwidth calculations.
	 * 
	 * <h3>Common Wire Lengths</h3>
	 * <table border="1">
	 *   <caption>Typical Packet Sizes</caption>
	 *   <tr><th>Type</th><th>Size</th><th>Description</th></tr>
	 *   <tr><td>Minimum Ethernet</td><td>64</td><td>Including padding</td></tr>
	 *   <tr><td>Standard MTU</td><td>1518</td><td>With Ethernet + FCS</td></tr>
	 *   <tr><td>VLAN Tagged</td><td>1522</td><td>Additional 4 bytes</td></tr>
	 *   <tr><td>Jumbo Frame</td><td>9000+</td><td>Extended MTU</td></tr>
	 * </table>
	 * 
	 * <h3>Example: Bandwidth Calculation</h3>
	 * <pre>{@code
	 * public class BandwidthMonitor {
	 *     private long totalBytes = 0;
	 *     private long startTime = System.nanoTime();
	 *     
	 *     public void addPacket(PacketDescriptor desc) {
	 *         // Use wire length for accurate bandwidth
	 *         totalBytes += desc.wireLength();
	 *     }
	 *     
	 *     public double getBandwidthMbps() {
	 *         long elapsed = System.nanoTime() - startTime;
	 *         double seconds = elapsed / 1_000_000_000.0;
	 *         double megabits = (totalBytes * 8) / 1_000_000.0;
	 *         return megabits / seconds;
	 *     }
	 * }
	 * }</pre>
	 * 
	 * @return the original packet size in bytes
	 * @see #captureLength()
	 * @see #setWireLength(int)
	 */
	int wireLength();

	/**
	 * Sets the wire length for this packet descriptor.
	 * 
	 * <p>Called by the capture engine or dissector to record the packet's
	 * original size. This value should represent the complete packet size
	 * including all headers and payload as seen on the network.
	 * 
	 * @param length the wire length in bytes, must be positive
	 * @throws IllegalArgumentException if length is invalid
	 * @see #wireLength()
	 */
	void setWireLength(int length);

	/**
	 * Returns the packet flag bitmask containing hardware and software indicators.
	 * 
	 * <p>The bitmask provides efficient access to multiple packet conditions
	 * and attributes set by hardware offload engines, drivers, or the dissector.
	 * Each bit represents a specific flag that can be tested using bitwise operations.
	 * 
	 * <h3>Flag Categories</h3>
	 * <ul>
	 *   <li><strong>Error flags:</strong> CRC, checksum, truncation errors</li>
	 *   <li><strong>Offload flags:</strong> TSO, GSO, checksum offload status</li>
	 *   <li><strong>Protocol flags:</strong> Fragmentation, tunneling indicators</li>
	 *   <li><strong>QoS flags:</strong> Priority, flow control markers</li>
	 * </ul>
	 * 
	 * <h3>Example: Comprehensive Flag Checking</h3>
	 * <pre>{@code
	 * public class PacketValidator {
	 *     public ValidationResult validate(PacketDescriptor desc) {
	 *         long flags = desc.packetFlagBitmask();
	 *         ValidationResult result = new ValidationResult();
	 *         
	 *         // Check for any errors
	 *         long errorMask = PacketFlag.Constants.PKT_MASK_ALL_BAD;
	 *         if ((flags & errorMask) != 0) {
	 *             result.hasErrors = true;
	 *             
	 *             // Identify specific errors
	 *             if ((flags & PacketFlag.PKT_FLAG_CRC_ERROR) != 0) {
	 *                 result.errors.add("CRC error");
	 *             }
	 *             if ((flags & PacketFlag.PKT_FLAG_IP_CSUM_ERROR) != 0) {
	 *                 result.errors.add("IP checksum error");
	 *             }
	 *             if ((flags & PacketFlag.PKT_FLAG_TCP_CSUM_ERROR) != 0) {
	 *                 result.errors.add("TCP checksum error");
	 *             }
	 *         }
	 *         
	 *         // Check offload status
	 *         if ((flags & PacketFlag.PKT_FLAG_TSO) != 0) {
	 *             result.tsoEnabled = true;
	 *         }
	 *         if ((flags & PacketFlag.PKT_FLAG_GSO) != 0) {
	 *             result.gsoEnabled = true;
	 *         }
	 *         
	 *         // Check special conditions
	 *         if ((flags & PacketFlag.PKT_FLAG_FRAGMENTED) != 0) {
	 *             result.isFragmented = true;
	 *         }
	 *         if ((flags & PacketFlag.PKT_FLAG_VLAN_TAGGED) != 0) {
	 *             result.hasVlanTag = true;
	 *         }
	 *         
	 *         return result;
	 *     }
	 * }
	 * }</pre>
	 * 
	 * <h3>Performance Note</h3>
	 * <p>Checking flags via bitmask operations is extremely efficient and
	 * should be preferred over individual boolean methods for multiple checks.
	 * 
	 * @return the packet flag bitmask, with bits set according to {@link PacketFlag}
	 * @see PacketFlag
	 * @see PacketFlag.Constants
	 */
	long packetFlagBitmask();
	
	/**
	 * Returns the offset to the Layer 2 (Data Link) header.
	 * 
	 * <p>For standard Ethernet frames, this is typically 0. For packets with
	 * preambles or special encapsulations, the offset may be non-zero.
	 * 
	 * <h3>Common L2 Protocols</h3>
	 * <ul>
	 *   <li>Ethernet II</li>
	 *   <li>IEEE 802.3 with LLC/SNAP</li>
	 *   <li>PPP (Point-to-Point Protocol)</li>
	 *   <li>FDDI (Fiber Distributed Data Interface)</li>
	 * </ul>
	 * 
	 * @return the byte offset to L2 header, or -1 if not present
	 * @see #l2Length()
	 */
	int l2Offset();
	
	/**
	 * Returns the offset to the Layer 3 (Network) header.
	 * 
	 * <p>This offset points to the beginning of the network layer protocol,
	 * typically IPv4 or IPv6. The offset accounts for all L2 headers including
	 * VLAN tags if present.
	 * 
	 * <h3>Calculation Example</h3>
	 * <pre>{@code
	 * // Typical L3 offset calculation
	 * int l3Offset = 14;  // Standard Ethernet header
	 * if (hasVlan) l3Offset += 4;  // VLAN tag
	 * if (hasQinQ) l3Offset += 4;  // Additional VLAN tag
	 * }</pre>
	 * 
	 * @return the byte offset to L3 header, or -1 if not present
	 * @see #l3Length()
	 */
	int l3Offset();
	
	/**
	 * Returns the offset to the Layer 4 (Transport) header.
	 * 
	 * <p>Points to the transport protocol header (TCP, UDP, SCTP, etc.).
	 * The offset is calculated from the packet start, not from L3.
	 * 
	 * <h3>Example: Direct Transport Access</h3>
	 * <pre>{@code
	 * int l4Off = desc.l4Offset();
	 * if (l4Off > 0) {
	 *     // Read transport header directly
	 *     int srcPort = packet.getShort(l4Off) & 0xFFFF;
	 *     int dstPort = packet.getShort(l4Off + 2) & 0xFFFF;
	 * }
	 * }</pre>
	 * 
	 * @return the byte offset to L4 header, or -1 if not present
	 * @see #l4Length()
	 */
	int l4Offset();
	
	/**
	 * Returns the length of the Layer 2 header in bytes.
	 * 
	 * <p>Includes the base L2 header and any extensions such as VLAN tags.
	 * Does not include preamble or FCS.
	 * 
	 * @return the L2 header length in bytes, or 0 if not present
	 * @see #l2Offset()
	 */
	int l2Length();
	
	/**
	 * Returns the length of the Layer 3 header in bytes.
	 * 
	 * <p>For IPv4, this includes any options present. For IPv6, includes
	 * the base header but not extension headers (which are considered L4).
	 * 
	 * <h3>Typical L3 Header Sizes</h3>
	 * <ul>
	 *   <li>IPv4: 20 bytes (no options) to 60 bytes (max options)</li>
	 *   <li>IPv6: 40 bytes (fixed base header)</li>
	 *   <li>MPLS: 4 bytes per label</li>
	 * </ul>
	 * 
	 * @return the L3 header length in bytes, or 0 if not present
	 * @see #l3Offset()
	 */
	int l3Length();
	
	/**
	 * Returns the length of the Layer 4 header in bytes.
	 * 
	 * <p>Includes the base transport header and any options. For protocols
	 * with variable-length headers, returns the actual header size.
	 * 
	 * <h3>Transport Header Sizes</h3>
	 * <ul>
	 *   <li>TCP: 20 bytes (no options) to 60 bytes (with options)</li>
	 *   <li>UDP: 8 bytes (fixed)</li>
	 *   <li>SCTP: 12 bytes (common header) + chunks</li>
	 *   <li>ICMP: 8 bytes (typical)</li>
	 * </ul>
	 * 
	 * @return the L4 header length in bytes, or 0 if not present
	 * @see #l4Offset()
	 */
	int l4Length();
	
	/**
	 * Returns the offset to the outer Layer 2 header in tunneled packets.
	 * 
	 * <p>For tunneled protocols (VXLAN, GRE, NVGRE), this points to the
	 * encapsulating L2 header. For non-tunneled packets, returns -1.
	 * 
	 * <h3>Tunnel Detection</h3>
	 * <pre>{@code
	 * public boolean isTunneled(PacketDescriptor desc) {
	 *     return desc.l2OffsetOuter() >= 0 && 
	 *            desc.l3OffsetOuter() >= 0;
	 * }
	 * }</pre>
	 * 
	 * @return the byte offset to outer L2 header, or -1 if not tunneled
	 * @see #l2Offset()
	 * @see #l2LengthOuter()
	 */
	int l2OffsetOuter();
	
	/**
	 * Returns the offset to the outer Layer 3 header in tunneled packets.
	 * 
	 * <p>Points to the encapsulating network layer header in tunneled protocols.
	 * The inner L3 header is accessed via {@link #l3Offset()}.
	 * 
	 * @return the byte offset to outer L3 header, or -1 if not tunneled
	 * @see #l3Offset()
	 * @see #l3LengthOuter()
	 */
	int l3OffsetOuter();
	
	/**
	 * Returns the length of the outer Layer 2 header in bytes.
	 * 
	 * <p>For tunneled packets, indicates the size of the encapsulating
	 * L2 header including any VLAN tags or extensions.
	 * 
	 * @return the outer L2 header length, or 0 if not tunneled
	 * @see #l2OffsetOuter()
	 */
	int l2LengthOuter();
	
	/**
	 * Returns the length of the outer Layer 3 header in bytes.
	 * 
	 * <p>For tunneled packets, indicates the size of the encapsulating
	 * network layer header including any options or extensions.
	 * 
	 * @return the outer L3 header length, or 0 if not tunneled
	 * @see #l3OffsetOuter()
	 */
	int l3LengthOuter();
	
	/**
	 * Returns the TSO (TCP Segmentation Offload) segment size.
	 * 
	 * <p>When TSO is enabled, large TCP segments are passed to the NIC
	 * which segments them into smaller packets. This value indicates the
	 * maximum segment size (MSS) to be used by the hardware.
	 * 
	 * <h3>TSO Processing</h3>
	 * <pre>{@code
	 * public void handleTsoPacket(PacketDescriptor desc) {
	 *     int tsoSize = desc.tsoSegmentSize();
	 *     
	 *     if (tsoSize > 0) {
	 *         // Calculate number of segments
	 *         int payloadSize = desc.wireLength() - desc.l4Offset() - desc.l4Length();
	 *         int segments = (payloadSize + tsoSize - 1) / tsoSize;
	 *         
	 *         log.info("TSO packet: {} bytes -> {} segments of max {} bytes",
	 *                  payloadSize, segments, tsoSize);
	 *         
	 *         // NIC will handle segmentation
	 *         transmitToNic(desc);
	 *     } else {
	 *         // Normal packet processing
	 *         transmitNormal(desc);
	 *     }
	 * }
	 * }</pre>
	 * 
	 * @return the TSO segment size in bytes, or 0 if TSO is not enabled
	 */
	int tsoSegmentSize();
	
	/**
	 * Returns the packet hash value for RSS and flow distribution.
	 * 
	 * <p>The hash is typically calculated by hardware based on packet headers
	 * (IP addresses, ports) and is used for:
	 * <ul>
	 *   <li>RSS (Receive Side Scaling) queue selection</li>
	 *   <li>Flow table lookups</li>
	 *   <li>Load balancing across CPU cores</li>
	 *   <li>Connection tracking</li>
	 * </ul>
	 * 
	 * <h3>Hash-Based Distribution</h3>
	 * <pre>{@code
	 * public class PacketDistributor {
	 *     private final int numQueues;
	 *     private final PacketQueue[] queues;
	 *     
	 *     public void distribute(PacketDescriptor desc) {
	 *         long hash = desc.hash();
	 *         
	 *         // Ensure same flow goes to same queue
	 *         int queueIndex = (int) (hash % numQueues);
	 *         queues[queueIndex].enqueue(desc);
	 *         
	 *         // Log distribution for monitoring
	 *         if (log.isTraceEnabled()) {
	 *             log.trace("Packet hash {} -> queue {}", 
	 *                       Long.toHexString(hash), queueIndex);
	 *         }
	 *     }
	 * }
	 * }</pre>
	 * 
	 * <h3>Hash Types</h3>
	 * <p>Common hardware hash algorithms:
	 * <ul>
	 *   <li><strong>Toeplitz:</strong> Microsoft RSS standard</li>
	 *   <li><strong>CRC32:</strong> Simple and fast</li>
	 *   <li><strong>Symmetric:</strong> Same hash for both directions</li>
	 * </ul>
	 * 
	 * @return the packet hash value, or 0 if not computed
	 */
	long hash();
}
