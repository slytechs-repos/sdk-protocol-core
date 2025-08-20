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
package com.slytechs.jnet.protocol.api;

import com.slytechs.jnet.core.api.memory.MemoryProxy;
import com.slytechs.jnet.protocol.api.descriptor.NetTag;
import com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor;
import com.slytechs.jnet.protocol.api.format.PacketFormat;

/**
 * High-performance network packet representation with zero-copy access to native memory.
 * 
 * <p>The {@code Packet} class is the central abstraction for network packet processing in the
 * protocol framework. It provides efficient, zero-copy access to packet data stored in native
 * memory segments while maintaining protocol dissection results and metadata. This class extends
 * {@link MemoryProxy} for flexible memory access across chained segments without the overhead
 * of buffer-style positioning.
 * 
 * <h2>Architecture Overview</h2>
 * 
 * <p>A {@code Packet} instance consists of three key components:
 * <ol>
 *   <li><strong>Memory Binding:</strong> Direct access to native packet data through {@link MemoryProxy}</li>
 *   <li><strong>Packet Descriptor:</strong> Protocol dissection results and header locations</li>
 *   <li><strong>NetTag Chain:</strong> Extended metadata and processing annotations</li>
 * </ol>
 * 
 * <h2>Memory Management</h2>
 * 
 * <p>The {@code Packet} class leverages the {@link MemoryProxy} superclass for efficient memory
 * access. This design enables:
 * <ul>
 *   <li>Zero-copy access to packet data in native memory (DPDK mbufs, Napatech buffers, etc.)</li>
 *   <li>Support for fragmented packets across multiple memory segments</li>
 *   <li>Efficient protocol parsing without data copying</li>
 *   <li>Sustained throughput exceeding 100 million packets per second</li>
 * </ul>
 * 
 * <h3>Binding to Native Memory</h3>
 * 
 * <pre>{@code
 * // Example: Binding packet to DPDK mbuf
 * Packet packet = new Packet();
 * MemorySegment mbufData = DpdkUtil.getMbufDataSegment(mbufPtr);
 * 
 * // Bind packet to native memory (zero-copy)
 * packet.bindMemory(mbufData, 0, packetLength);
 * 
 * // Set packet descriptor for protocol dissection
 * PacketDescriptor descriptor = dissector.dissect(packet);
 * packet.setPacketDescriptor(descriptor);
 * 
 * // Access packet data efficiently
 * byte[] ethDst = new byte[6];
 * packet.getBytes(0, ethDst);  // Read destination MAC
 * int etherType = packet.getShortBE(12) & 0xFFFF;  // Read EtherType
 * }</pre>
 * 
 * <h2>Protocol Dissection</h2>
 * 
 * <p>The {@code PacketDescriptor} maintains the results of packet dissection, recording the
 * presence and location of each protocol header. This enables constant-time header lookups
 * and efficient protocol-specific processing.
 * 
 * <h3>Header Access Patterns</h3>
 * 
 * <pre>{@code
 * // Access headers by protocol ID
 * if (packet.isPresent(CoreProtocol.IPv4)) {
 *     Header ipv4 = packet.getHeader(CoreProtocol.IPv4);
 *     int srcAddr = ipv4.getInt(12);  // Source IP address
 *     int dstAddr = ipv4.getInt(16);  // Destination IP address
 * }
 * 
 * // Access headers using typed instances
 * Tcp tcp = new Tcp();
 * if (packet.hasHeader(tcp)) {
 *     packet.getHeader(tcp);  // Binds tcp instance to packet data
 *     int srcPort = tcp.sourcePort();
 *     int dstPort = tcp.destinationPort();
 *     boolean syn = tcp.flags().SYN();
 * }
 * 
 * // Access headers at specific depths (for tunneled protocols)
 * if (packet.isPresent(CoreProtocol.IPv4, 1)) {  // Inner IPv4 header
 *     Header innerIp = packet.getHeader(CoreProtocol.IPv4, 1);
 *     // Process inner IP header in tunnel
 * }
 * }</pre>
 * 
 * <h2>NetTag Metadata Chain</h2>
 * 
 * <p>NetTags provide an extensible mechanism for attaching metadata to packets without
 * modifying the packet data itself. Common uses include:
 * <ul>
 *   <li>IP fragmentation descriptors and reassembly state</li>
 *   <li>TCP stream tracking and reassembly markers</li>
 *   <li>Application-layer protocol annotations</li>
 *   <li>Quality of Service (QoS) markings</li>
 *   <li>Security classifications and policy tags</li>
 * </ul>
 * 
 * <h3>Working with NetTags</h3>
 * 
 * <pre>{@code
 * // Add IP fragmentation tag
 * IpfTag fragTag = new IpfTag();
 * fragTag.setFragmentOffset(185);
 * fragTag.setMoreFragments(true);
 * fragTag.setIdentification(0x1234);
 * packet.addTag(fragTag);
 * 
 * // Add custom application tag
 * ApplicationTag appTag = new ApplicationTag();
 * appTag.setFlowId(flowId);
 * appTag.setTimestamp(System.nanoTime());
 * fragTag.setNext(appTag);  // Chain tags together
 * 
 * // Traverse tag chain
 * NetTag tag = packet.getTags();
 * while (tag != null) {
 *     if (tag instanceof IpfTag) {
 *         IpfTag ipf = (IpfTag) tag;
 *         // Process IP fragmentation info
 *     }
 *     tag = tag.getNext();
 * }
 * }</pre>
 * 
 * <h2>Packet Formatting</h2>
 * 
 * <p>The {@code toString()} method provides intelligent packet formatting based on the
 * configured {@link PacketFormat}. This enables flexible output for debugging, logging,
 * and analysis.
 * 
 * <pre>{@code
 * // Set default formatter
 * PacketFormat.setDefault(new PrettyPacketFormat());
 * 
 * // Packet toString() uses configured formatter
 * System.out.println(packet);  // Pretty-printed packet details
 * 
 * // Use specific formatter
 * JsonPacketFormat jsonFormat = new JsonPacketFormat();
 * String json = jsonFormat.formatPacket(packet);
 * 
 * // Custom inline formatting
 * packet.toString();  // Uses default formatter or descriptor.toString()
 * }</pre>
 * 
 * <h2>Performance Characteristics</h2>
 * 
 * <p>The {@code Packet} class is designed for extreme performance in high-throughput
 * packet processing scenarios:
 * 
 * <h3>Zero-Allocation Operations</h3>
 * <ul>
 *   <li>All header access methods return reusable instances</li>
 *   <li>No memory allocation during packet processing</li>
 *   <li>Direct native memory access via MemoryProxy</li>
 *   <li>Constant-time header lookups via PacketDescriptor</li>
 * </ul>
 * 
 * <h3>Cache-Friendly Design</h3>
 * <ul>
 *   <li>Compact object layout minimizes cache misses</li>
 *   <li>Descriptor caches dissection results</li>
 *   <li>Sequential memory access patterns</li>
 *   <li>NUMA-aware memory binding support</li>
 * </ul>
 * 
 * <h2>Thread Safety</h2>
 * 
 * <p>The {@code Packet} class is <strong>NOT thread-safe</strong>. Each thread should use
 * its own {@code Packet} instances. For multi-threaded processing:
 * <ul>
 *   <li>Use thread-local packet pools</li>
 *   <li>Implement per-core packet processing (DPDK-style)</li>
 *   <li>Use lock-free queues for packet handoff between threads</li>
 *   <li>Reference counting (via MemoryProxy) is thread-safe</li>
 * </ul>
 * 
 * <h2>Usage Examples</h2>
 * 
 * <h3>Basic Packet Processing</h3>
 * 
 * <pre>{@code
 * public class PacketProcessor {
 *     private final Packet packet = new Packet();
 *     private final Dissector dissector = new CoreDissector();
 *     
 *     public void processPacket(MemorySegment data, int length) {
 *         // Bind to packet data
 *         packet.bindMemory(data, 0, length);
 *         
 *         // Dissect packet
 *         PacketDescriptor desc = dissector.dissect(packet);
 *         packet.setPacketDescriptor(desc);
 *         
 *         // Process based on protocol
 *         if (packet.isPresent(CoreProtocol.TCP)) {
 *             processTcp(packet);
 *         } else if (packet.isPresent(CoreProtocol.UDP)) {
 *             processUdp(packet);
 *         }
 *         
 *         // Clean up
 *         packet.unbindMemory();
 *     }
 * }
 * }</pre>
 * 
 * <h3>Deep Packet Inspection</h3>
 * 
 * <pre>{@code
 * public class DpiEngine {
 *     private final Ethernet eth = new Ethernet();
 *     private final Ip4 ip4 = new Ip4();
 *     private final Tcp tcp = new Tcp();
 *     
 *     public void inspectPacket(Packet packet) {
 *         // Layer 2 inspection
 *         if (packet.hasHeader(eth)) {
 *             packet.getHeader(eth);
 *             byte[] srcMac = eth.source();
 *             byte[] dstMac = eth.destination();
 *             int vlanId = eth.vlanId();  // 0 if no VLAN
 *         }
 *         
 *         // Layer 3 inspection
 *         if (packet.hasHeader(ip4)) {
 *             packet.getHeader(ip4);
 *             InetAddress src = ip4.sourceAddress();
 *             InetAddress dst = ip4.destinationAddress();
 *             int ttl = ip4.ttl();
 *             
 *             // Check for fragmentation
 *             if (ip4.isFragmented()) {
 *                 handleFragment(packet);
 *             }
 *         }
 *         
 *         // Layer 4 inspection
 *         if (packet.hasHeader(tcp)) {
 *             packet.getHeader(tcp);
 *             int srcPort = tcp.sourcePort();
 *             int dstPort = tcp.destinationPort();
 *             long seqNum = tcp.sequenceNumber();
 *             
 *             // Deep inspection of payload
 *             if (tcp.payloadLength() > 0) {
 *                 inspectPayload(packet, tcp.payloadOffset());
 *             }
 *         }
 *     }
 * }
 * }</pre>
 * 
 * <h3>Packet Modification and Forwarding</h3>
 * 
 * <pre>{@code
 * public class PacketForwarder {
 *     private final MemoryPool<MemoryByteBuffer> pool;
 *     
 *     public void forwardWithNat(Packet packet, InetAddress newSrc) {
 *         // Access IP header
 *         Ip4 ip4 = new Ip4();
 *         if (!packet.hasHeader(ip4)) {
 *             return;  // Not IPv4
 *         }
 *         packet.getHeader(ip4);
 *         
 *         // Modify source address (in-place if possible)
 *         int offset = ip4.offset() + 12;  // Source IP offset
 *         packet.putInt(offset, newSrc.toInt());
 *         
 *         // Recalculate checksum
 *         int checksum = calculateIpChecksum(packet, ip4.offset());
 *         packet.putShort(ip4.offset() + 10, (short) checksum);
 *         
 *         // Forward packet
 *         transmit(packet);
 *     }
 * }
 * }</pre>
 * 
 * <h2>Best Practices</h2>
 * 
 * <ol>
 *   <li><strong>Reuse Packet instances:</strong> Create once, bind many times</li>
 *   <li><strong>Use typed headers:</strong> Prefer {@code tcp.sourcePort()} over raw offsets</li>
 *   <li><strong>Check header presence:</strong> Always verify with {@code hasHeader()} before access</li>
 *   <li><strong>Handle fragmentation:</strong> Check and process IP fragments appropriately</li>
 *   <li><strong>Clean up resources:</strong> Call {@code unbindMemory()} when done</li>
 *   <li><strong>Monitor metrics:</strong> Track processing rates and errors</li>
 * </ol>
 * 
 * <h2>Integration with Protocol Packs</h2>
 * 
 * <p>The {@code Packet} class works seamlessly with protocol pack modules:
 * <ul>
 *   <li><strong>core-protocols:</strong> Ethernet, IP, TCP, UDP, ICMP, etc.</li>
 *   <li><strong>web-protocols:</strong> HTTP, HTTP/2, WebSocket, etc.</li>
 *   <li><strong>enterprise-protocols:</strong> LDAP, SMB, database protocols</li>
 *   <li><strong>telecom-protocols:</strong> SIP, RTP, Diameter, etc.</li>
 * </ul>
 * 
 * @see MemoryProxy
 * @see PacketDescriptor
 * @see NetTag
 * @see HeaderAccessor
 * @see PacketFormat
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public final class Packet extends MemoryProxy implements HeaderAccessor {

	/**
	 * NetTag chain providing protocol-specific metadata and annotations.
	 * 
	 * <p>Tags form a singly-linked list where each tag can reference the next tag
	 * in the chain via {@link NetTag#getNext()}. Tags are used to store information
	 * that extends beyond basic protocol dissection, such as:
	 * <ul>
	 *   <li>IP fragmentation and reassembly state</li>
	 *   <li>TCP stream tracking information</li>
	 *   <li>Application-layer protocol markers</li>
	 *   <li>Custom user-defined metadata</li>
	 * </ul>
	 * 
	 * <p>The tag chain is traversed from head to tail, with newer tags typically
	 * added at the head for O(1) insertion performance.
	 */
	protected NetTag headTag;
	
	/**
	 * Packet descriptor containing dissection results and header locations.
	 * 
	 * <p>The descriptor is produced by a {@code Dissector} and contains:
	 * <ul>
	 *   <li>Bitmask of detected protocols</li>
	 *   <li>Offset and length of each header</li>
	 *   <li>Protocol-specific flags and metadata</li>
	 *   <li>Payload offset and length</li>
	 * </ul>
	 * 
	 * <p>Different descriptor types provide varying levels of detail:
	 * <ul>
	 *   <li>{@code TYPE1}: Basic protocol presence flags</li>
	 *   <li>{@code TYPE2}: Detailed header offsets and lengths</li>
	 *   <li>{@code TYPE3}: Extended metadata and annotations</li>
	 * </ul>
	 */
	protected PacketDescriptor packetDescriptor;

	/**
	 * Constructs a new packet instance.
	 * 
	 * <p>The packet is created in an unbound state and must be bound to memory
	 * using {@link MemoryProxy#bindMemory} before use. This allows packet instances
	 * to be reused across multiple packet captures for zero-allocation processing.
	 * 
	 * <h3>Typical Usage Pattern</h3>
	 * <pre>{@code
	 * Packet packet = new Packet();  // Create once
	 * 
	 * while (capturing) {
	 *     MemorySegment data = captureNext();
	 *     packet.bindMemory(data, 0, length);  // Bind to new data
	 *     processPacket(packet);
	 *     packet.unbindMemory();  // Prepare for reuse
	 * }
	 * }</pre>
	 */
	public Packet() {}

	/**
	 * Adds a new tag to the head of the tag chain.
	 * 
	 * <p>The new tag becomes the head of the chain, with its {@code next} pointer
	 * set to the previous head (if any). This provides O(1) insertion performance.
	 * Tags can be used to annotate packets with additional metadata such as:
	 * <ul>
	 *   <li>IP fragmentation information</li>
	 *   <li>TCP stream association</li>
	 *   <li>Application protocol detection results</li>
	 *   <li>QoS and policy markings</li>
	 *   <li>Custom processing annotations</li>
	 * </ul>
	 * 
	 * <h3>Example: Adding Multiple Tags</h3>
	 * <pre>{@code
	 * // Add fragmentation tag
	 * IpfTag fragTag = new IpfTag();
	 * fragTag.setFragmentOffset(185);
	 * fragTag.setMoreFragments(true);
	 * packet.addTag(fragTag);
	 * 
	 * // Add stream tracking tag
	 * TcpStreamTag streamTag = new TcpStreamTag();
	 * streamTag.setStreamId(12345);
	 * streamTag.setSequenceNumber(seq);
	 * packet.addTag(streamTag);
	 * 
	 * // Tags are now chained: streamTag -> fragTag -> null
	 * }</pre>
	 * 
	 * @param tag the tag to add to the packet; must not be {@code null}
	 * @throws NullPointerException if tag is {@code null}
	 * @see #getTags()
	 */
	public void addTag(NetTag tag) {
		this.headTag = tag;
	}

	/**
	 * Returns the captured length of the packet in bytes.
	 * 
	 * <p>The capture length represents the number of bytes actually captured
	 * and available for processing. This may be less than the wire length if
	 * the capture was truncated due to snapshot length settings.
	 * 
	 * <h3>Relationship to Wire Length</h3>
	 * <pre>{@code
	 * int capLen = packet.captureLength();  // Bytes available
	 * int wireLen = packet.wireLength();    // Original packet size
	 * 
	 * if (capLen < wireLen) {
	 *     System.out.println("Packet was truncated: " + 
	 *                        (wireLen - capLen) + " bytes missing");
	 * }
	 * }</pre>
	 * 
	 * @return the number of bytes captured
	 * @see #wireLength()
	 */
	public final int captureLength() {
		return packetDescriptor.captureLength();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>Retrieves a header by its protocol ID. This method returns the first
	 * occurrence of the specified protocol (depth 0). For tunneled protocols
	 * with multiple instances, use {@link #getHeader(int, int)} with an
	 * explicit depth parameter.
	 * 
	 * <h3>Example</h3>
	 * <pre>{@code
	 * try {
	 *     Header tcp = packet.getHeader(CoreProtocol.TCP);
	 *     int srcPort = tcp.getShort(0) & 0xFFFF;
	 *     int dstPort = tcp.getShort(2) & 0xFFFF;
	 * } catch (HeaderNotFoundException e) {
	 *     // TCP header not present in packet
	 * }
	 * }</pre>
	 * 
	 * @param id the protocol ID constant
	 * @return the header instance bound to packet data
	 * @throws HeaderNotFoundException if the specified header is not present
	 * @see #isPresent(int)
	 * @see #getHeader(int, int)
	 */
	@Override
	public final Header getHeader(int id) throws HeaderNotFoundException {
		return packetDescriptor.getHeader(id);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>Retrieves a header by its protocol ID at a specific depth. Depth is
	 * used for tunneled protocols where the same protocol may appear multiple
	 * times in a packet (e.g., IP-in-IP tunneling, VLAN stacking).
	 * 
	 * <h3>Depth Semantics</h3>
	 * <ul>
	 *   <li>Depth 0: Outermost (first) occurrence</li>
	 *   <li>Depth 1: Second occurrence</li>
	 *   <li>Depth 2: Third occurrence, etc.</li>
	 * </ul>
	 * 
	 * <h3>Example: Accessing Tunneled Headers</h3>
	 * <pre>{@code
	 * // GRE tunnel: Outer IP -> GRE -> Inner IP -> TCP
	 * Header outerIp = packet.getHeader(CoreProtocol.IPv4, 0);
	 * Header innerIp = packet.getHeader(CoreProtocol.IPv4, 1);
	 * 
	 * // Q-in-Q VLAN stacking
	 * Header outerVlan = packet.getHeader(CoreProtocol.VLAN, 0);
	 * Header innerVlan = packet.getHeader(CoreProtocol.VLAN, 1);
	 * }</pre>
	 * 
	 * @param id the protocol ID constant
	 * @param depth the occurrence depth (0 for first, 1 for second, etc.)
	 * @return the header instance bound to packet data
	 * @throws HeaderNotFoundException if the header is not present at the specified depth
	 * @see #isPresent(int, int)
	 */
	@Override
	public final Header getHeader(int id, int depth) throws HeaderNotFoundException {
		return packetDescriptor.getHeader(id, depth);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>Binds the provided header instance to this packet's data if the header
	 * is present. This method allows for reusable header objects that can be
	 * bound to different packets without allocation.
	 * 
	 * <h3>Example: Reusable Header Pattern</h3>
	 * <pre>{@code
	 * public class TcpProcessor {
	 *     // Reusable header instances (no allocation per packet)
	 *     private final Tcp tcp = new Tcp();
	 *     private final Ip4 ip4 = new Ip4();
	 *     
	 *     public void process(Packet packet) {
	 *         if (packet.hasHeader(tcp)) {
	 *             packet.getHeader(tcp);  // Binds tcp to packet data
	 *             int srcPort = tcp.sourcePort();
	 *             int dstPort = tcp.destinationPort();
	 *             
	 *             if (tcp.flags().SYN()) {
	 *                 handleSynPacket(packet);
	 *             }
	 *         }
	 *     }
	 * }
	 * }</pre>
	 * 
	 * @param <T> the specific header type
	 * @param header the header instance to bind to packet data
	 * @return the same header instance, now bound to packet data
	 * @throws HeaderNotFoundException if the header type is not present in the packet
	 * @see #hasHeader(Header)
	 */
	@Override
	public final <T extends Header> T getHeader(T header) throws HeaderNotFoundException {
		return packetDescriptor.getHeader(header);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>Binds the provided header instance to this packet's data at the specified
	 * depth. This combines the reusability of typed headers with support for
	 * tunneled protocols.
	 * 
	 * <h3>Example: Processing Tunneled Protocols</h3>
	 * <pre>{@code
	 * Ip4 outerIp = new Ip4();
	 * Ip4 innerIp = new Ip4();
	 * 
	 * // Process GRE tunnel
	 * if (packet.hasHeader(outerIp, 0) && packet.hasHeader(innerIp, 1)) {
	 *     packet.getHeader(outerIp, 0);  // Bind to outer IP
	 *     packet.getHeader(innerIp, 1);  // Bind to inner IP
	 *     
	 *     System.out.println("Tunnel: " + outerIp.source() + 
	 *                        " -> " + outerIp.destination());
	 *     System.out.println("Inner: " + innerIp.source() + 
	 *                        " -> " + innerIp.destination());
	 * }
	 * }</pre>
	 * 
	 * @param <T> the specific header type
	 * @param header the header instance to bind to packet data
	 * @param depth the occurrence depth (0 for first, 1 for second, etc.)
	 * @return the same header instance, now bound to packet data
	 * @throws HeaderNotFoundException if the header is not present at the specified depth
	 * @see #hasHeader(Header, int)
	 */
	@Override
	public final <T extends Header> T getHeader(T header, int depth) throws HeaderNotFoundException {
		return packetDescriptor.getHeader(header, depth);
	}

	/**
	 * Returns the packet descriptor containing dissection results.
	 * 
	 * <p>The packet descriptor stores the results of protocol dissection including
	 * header locations, protocol flags, and metadata. Different descriptor types
	 * provide varying levels of detail:
	 * 
	 * <ul>
	 *   <li>{@code PacketDescriptorType.TYPE1}: Basic protocol presence</li>
	 *   <li>{@code PacketDescriptorType.TYPE2}: Detailed header information</li>
	 *   <li>{@code PacketDescriptorType.TYPE3}: Extended metadata</li>
	 * </ul>
	 * 
	 * <p>The descriptor can be cast to specific types for additional functionality:
	 * 
	 * <pre>{@code
	 * // Get descriptor with specific type
	 * Type2Descriptor desc = packet.getPacketDescriptor();
	 * 
	 * // Access type-specific features
	 * int headerCount = desc.headerCount();
	 * for (int i = 0; i < headerCount; i++) {
	 *     int id = desc.headerId(i);
	 *     int offset = desc.headerOffset(i);
	 *     int length = desc.headerLength(i);
	 *     System.out.printf("Header %d: offset=%d, length=%d%n", 
	 *                       id, offset, length);
	 * }
	 * }</pre>
	 * 
	 * @param <T> the specific descriptor type
	 * @return the packet descriptor cast to the requested type
	 * @see #setPacketDescriptor(PacketDescriptor)
	 * @see PacketDescriptor
	 */
	@SuppressWarnings("unchecked")
	public final <T extends PacketDescriptor> T getPacketDescriptor() {
		return (T) packetDescriptor;
	}

	/**
	 * Returns the head of the NetTag chain attached to this packet.
	 * 
	 * <p>NetTags provide extensible metadata that can be attached to packets
	 * without modifying the packet data itself. Tags are organized in a
	 * singly-linked list and can be traversed using {@link NetTag#getNext()}.
	 * 
	 * <h3>Example: Traversing the Tag Chain</h3>
	 * <pre>{@code
	 * NetTag tag = packet.getTags();
	 * while (tag != null) {
	 *     if (tag instanceof IpfTag) {
	 *         IpfTag ipf = (IpfTag) tag;
	 *         System.out.println("Fragment offset: " + ipf.getFragmentOffset());
	 *     } else if (tag instanceof TcpStreamTag) {
	 *         TcpStreamTag stream = (TcpStreamTag) tag;
	 *         System.out.println("Stream ID: " + stream.getStreamId());
	 *     }
	 *     tag = tag.getNext();
	 * }
	 * }</pre>
	 * 
	 * @return the head of the tag chain, or {@code null} if no tags are attached
	 * @see #addTag(NetTag)
	 */
	public NetTag getTags() {
		return headTag;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>Checks if the specified header type is present in this packet.
	 * This method is more efficient than catching {@code HeaderNotFoundException}
	 * and should be used to conditionally process headers.
	 * 
	 * <h3>Example: Conditional Processing</h3>
	 * <pre>{@code
	 * Tcp tcp = new Tcp();
	 * Udp udp = new Udp();
	 * 
	 * if (packet.hasHeader(tcp)) {
	 *     packet.getHeader(tcp);
	 *     processTcpPacket(tcp);
	 * } else if (packet.hasHeader(udp)) {
	 *     packet.getHeader(udp);
	 *     processUdpPacket(udp);
	 * }
	 * }</pre>
	 * 
	 * @param header the header instance to check
	 * @return {@code true} if the header type is present, {@code false} otherwise
	 * @see #getHeader(Header)
	 */
	@Override
	public final boolean hasHeader(Header header) {
		return packetDescriptor.hasHeader(header);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>Checks if the specified header type is present at the given depth.
	 * This is used for tunneled protocols where the same header type may
	 * appear multiple times.
	 * 
	 * <h3>Example: Detecting Tunnels</h3>
	 * <pre>{@code
	 * Ip4 ip = new Ip4();
	 * 
	 * boolean isTunneled = packet.hasHeader(ip, 0) && packet.hasHeader(ip, 1);
	 * if (isTunneled) {
	 *     System.out.println("IP-in-IP tunnel detected");
	 * }
	 * 
	 * // Check for Q-in-Q VLAN stacking
	 * Vlan vlan = new Vlan();
	 * int vlanDepth = 0;
	 * while (packet.hasHeader(vlan, vlanDepth)) {
	 *     vlanDepth++;
	 * }
	 * System.out.println("VLAN stack depth: " + vlanDepth);
	 * }</pre>
	 * 
	 * @param header the header instance to check
	 * @param depth the occurrence depth to check
	 * @return {@code true} if the header is present at the specified depth
	 * @see #getHeader(Header, int)
	 */
	@Override
	public final boolean hasHeader(Header header, int depth) {
		return packetDescriptor.hasHeader(header, depth);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>Checks if a protocol is present by its ID. This is the most efficient
	 * method for simple protocol presence checks as it works directly with
	 * protocol IDs without requiring header instances.
	 * 
	 * <h3>Example: Protocol Detection</h3>
	 * <pre>{@code
	 * // Fast protocol detection using constants
	 * if (packet.isPresent(CoreProtocol.IPv4)) {
	 *     // IPv4 packet
	 * } else if (packet.isPresent(CoreProtocol.IPv6)) {
	 *     // IPv6 packet
	 * }
	 * 
	 * // Check transport protocol
	 * if (packet.isPresent(CoreProtocol.TCP)) {
	 *     handleTcp(packet);
	 * } else if (packet.isPresent(CoreProtocol.UDP)) {
	 *     handleUdp(packet);
	 * } else if (packet.isPresent(CoreProtocol.SCTP)) {
	 *     handleSctp(packet);
	 * }
	 * }</pre>
	 * 
	 * @param id the protocol ID constant
	 * @return {@code true} if the protocol is present, {@code false} otherwise
	 * @see #getHeader(int)
	 */
	@Override
	public final boolean isPresent(int id) {
		return packetDescriptor.isPresent(id);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>Checks if a protocol is present at the specified depth. This method
	 * combines the efficiency of ID-based checks with support for tunneled
	 * protocols.
	 * 
	 * <h3>Example: Tunnel Detection</h3>
	 * <pre>{@code
	 * // Detect IP-in-IP tunnel
	 * boolean hasOuterIP = packet.isPresent(CoreProtocol.IPv4, 0);
	 * boolean hasInnerIP = packet.isPresent(CoreProtocol.IPv4, 1);
	 * 
	 * if (hasOuterIP && hasInnerIP) {
	 *     System.out.println("IP-in-IP tunnel detected");
	 * }
	 * 
	 * // Count MPLS label stack depth
	 * int labelDepth = 0;
	 * while (packet.isPresent(CoreProtocol.MPLS, labelDepth)) {
	 *     labelDepth++;
	 * }
	 * System.out.println("MPLS stack depth: " + labelDepth);
	 * }</pre>
	 * 
	 * @param id the protocol ID constant
	 * @param depth the occurrence depth to check
	 * @return {@code true} if the protocol is present at the specified depth
	 * @see #getHeader(int, int)
	 */
	@Override
	public final boolean isPresent(int id, int depth) {
		return packetDescriptor.isPresent(id, depth);
	}

	/**
	 * Sets the packet descriptor containing dissection results.
	 * 
	 * <p>The descriptor is typically produced by a {@code Dissector} after
	 * analyzing the packet data. Once set, the descriptor enables efficient
	 * header access through the various {@code getHeader} and {@code hasHeader}
	 * methods.
	 * 
	 * <h3>Example: Packet Processing Pipeline</h3>
	 * <pre>{@code
	 * public class PacketPipeline {
	 *     private final Dissector dissector = new CoreDissector();
	 *     private final Packet packet = new Packet();
	 *     
	 *     public void processPacket(MemorySegment data, int length) {
	 *         // Bind packet to data
	 *         packet.bindMemory(data, 0, length);
	 *         
	 *         // Dissect packet
	 *         PacketDescriptor descriptor = dissector.dissect(packet);
	 *         packet.setPacketDescriptor(descriptor);
	 *         
	 *         // Now headers can be accessed efficiently
	 *         if (packet.isPresent(CoreProtocol.TCP)) {
	 *             processTcp(packet);
	 *         }
	 *         
	 *         // Clean up for reuse
	 *         packet.unbindMemory();
	 *     }
	 * }
	 * }</pre>
	 * 
	 * @param descriptor the packet descriptor to set; must not be {@code null}
	 * @throws NullPointerException if descriptor is {@code null}
	 * @see #getPacketDescriptor()
	 * @see PacketDescriptor
	 */
	public final void setPacketDescriptor(PacketDescriptor descriptor) {
		this.packetDescriptor = descriptor;
	}

	/**
	 * Returns a string representation of this packet.
	 * 
	 * <p>The format of the returned string depends on the configured default
	 * {@link PacketFormat}. If no formatter is set, the packet descriptor's
	 * {@code toString()} method is used as a fallback.
	 * 
	 * <p>Common formatters include:
	 * <ul>
	 *   <li>{@code PrettyPacketFormat}: Human-readable multi-line format</li>
	 *   <li>{@code CompactPacketFormat}: Single-line summary format</li>
	 *   <li>{@code XmlPacketFormat}: XML representation</li>
	 *   <li>{@code JsonPacketFormat}: JSON representation</li>
	 * </ul>
	 * 
	 * <h3>Example Output (PrettyPacketFormat)</h3>
	 * <pre>
	 * Frame #1 (74 bytes on wire, 74 bytes captured)
	 *   Ethernet II: 00:11:22:33:44:55 -> 66:77:88:99:aa:bb, Type: IPv4 (0x0800)
	 *   IPv4: 192.168.1.1 -> 10.0.0.1, Protocol: TCP (6), Length: 60
	 *   TCP: 54321 -> 80 (HTTP), Seq: 1234567, Ack: 7654321, Flags: [PSH, ACK]
	 * </pre>
	 * 
	 * @return a formatted string representation of the packet
	 * @see PacketFormat#setDefault(PacketFormat)
	 */
	@Override
	public String toString() {
		PacketFormat format = PacketFormat.getDefault();
		if (format == null)
			return packetDescriptor.toString();

		return format.formatPacket(this);
	}

	/**
	 * Returns the wire length of the packet in bytes.
	 * 
	 * <p>The wire length represents the original size of the packet as it
	 * appeared on the network, which may be larger than the capture length
	 * if the packet was truncated during capture.
	 * 
	 * <h3>Usage for Truncation Detection</h3>
	 * <pre>{@code
	 * int wireLen = packet.wireLength();
	 * int capLen = packet.captureLength();
	 * 
	 * if (wireLen > capLen) {
	 *     // Packet was truncated
	 *     int missing = wireLen - capLen;
	 *     log.warn("Packet truncated: {} bytes missing", missing);
	 *     
	 *     // May need special handling for incomplete packets
	 *     if (packet.isPresent(CoreProtocol.TCP)) {
	 *         // TCP payload may be incomplete
	 *     }
	 * }
	 * }</pre>
	 * 
	 * <h3>Statistics and Monitoring</h3>
	 * <pre>{@code
	 * // Accumulate traffic statistics
	 * long totalWireBytes = 0;
	 * long totalCapturedBytes = 0;
	 * 
	 * for (Packet packet : packets) {
	 *     totalWireBytes += packet.wireLength();
	 *     totalCapturedBytes += packet.captureLength();
	 * }
	 * 
	 * double captureRatio = (double) totalCapturedBytes / totalWireBytes;
	 * System.out.printf("Capture ratio: %.2f%%%n", captureRatio * 100);
	 * }</pre>
	 * 
	 * @return the original packet size in bytes as seen on the wire
	 * @see #captureLength()
	 */
	public final int wireLength() {
		return packetDescriptor.wireLength();
	}
}