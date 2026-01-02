/****
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

import java.nio.ByteOrder;
import java.util.Iterator;
import java.util.stream.Stream;

import com.slytechs.sdk.common.memory.BindableView;
import com.slytechs.sdk.common.memory.pool.Persistable;
import com.slytechs.sdk.common.time.TimestampUnit;
import com.slytechs.sdk.protocol.core.Header;
import com.slytechs.sdk.protocol.core.HeaderAccessor;
import com.slytechs.sdk.protocol.core.Protocol;
import com.slytechs.sdk.protocol.core.ProtocolId;
import com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor.BindingInfo;
import com.slytechs.sdk.protocol.core.spi.ProtocolProvider;

/**
 * Descriptor containing packet dissection results and protocol header metadata.
 * 
 * <p>
 * {@code PacketDescriptor} extends both {@link Descriptor} and
 * {@link HeaderAccessor} to provide comprehensive packet metadata along with
 * efficient header access capabilities. This interface is the primary
 * abstraction for storing and accessing the results of packet dissection in a
 * high-performance, cache-friendly format.
 * </p>
 * 
 * <h2>Architecture</h2>
 * 
 * <p>
 * A packet descriptor encapsulates:
 * </p>
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
 * </p>
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
 * </p>
 * <ul>
 * <li><strong>L2 (Data Link):</strong> Ethernet, VLAN, PPP</li>
 * <li><strong>L3 (Network):</strong> IPv4, IPv6, MPLS</li>
 * <li><strong>L4 (Transport):</strong> TCP, UDP, SCTP, ICMP</li>
 * <li><strong>L5+ (Application):</strong> HTTP, DNS, TLS (optional)</li>
 * </ul>
 * 
 * <h2>Capabilities</h2>
 * 
 * <p>
 * The descriptor reports supported RX and TX capabilities through bitmasks
 * defined in {@link DescriptorCapability}. These include support for
 * timestamps, checksum offloads, segmentation, tunneling, and more. Use
 * {@link #rxCapabilitiesBitmask()} and {@link #txCapabilitiesBitmask()} to
 * query available features.
 * </p>
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
 * @see DescriptorCapability
 * @since 1.0
 */
public interface PacketDescriptor
		extends Descriptor,
		Iterable<BindingInfo>,
		BindableView,
		Persistable<PacketDescriptor> {

	/**
	 * Encapsulates binding information for a protocol header entry in the
	 * descriptor.
	 * 
	 * <p>
	 * This record holds metadata about a specific protocol header's location and
	 * identity within a packet. It is primarily used for diagnostic purposes, such
	 * as generating string representations of the descriptor, rather than for
	 * hot-path protocol discovery where performance is critical.
	 * </p>
	 * 
	 * <h3>Usage Example</h3>
	 * 
	 * <pre>{@code
	 * // Iterate over all headers in the descriptor
	 * for (BindingInfo info : packetDescriptor) {
	 * 	System.out.printf("Header %d: protocol=%d, offset=%d, length=%d%n",
	 * 			info.order(), info.id(), info.offset(), info.length());
	 * 
	 * 	// Create and bind a header instance
	 * 	Header header = info.newBoundHeader(packet);
	 * 	if (header != null) {
	 * 		processHeader(header);
	 * 	}
	 * }
	 * }</pre>
	 *
	 * @param order  the sequential order of this header in the packet (0-based
	 *               index)
	 * @param id     the protocol identifier as defined by the protocol pack
	 * @param offset the byte offset from the start of the packet to this header
	 * @param length the length of this header in bytes
	 * @see PacketDescriptor#iterator()
	 * @see ProtocolId
	 * @since 1.0
	 */
	public record BindingInfo(int order, int id, long offset, long length) {

		/**
		 * Creates a new unbound header instance for this protocol.
		 * 
		 * <p>
		 * Looks up the protocol by its ID and creates a new header instance using the
		 * protocol's factory. The returned header is not bound to any packet data and
		 * must be bound before use.
		 * </p>
		 * 
		 * <h3>Example</h3>
		 * 
		 * <pre>{@code
		 * BindingInfo info = ...;
		 * Ip4Header ipHeader = info.newUnboundHeader();
		 * if (ipHeader != null) {
		 *     ipHeader.bindHeader(packet, info.id(), 0, info.offset(), info.length());
		 *     // Now the header is ready for use
		 * }
		 * }</pre>
		 *
		 * @param <T> the expected header type
		 * @return a new unbound header instance, or {@code null} if the protocol is not
		 *         found or not supported
		 * @see #newBoundHeader(BindableView)
		 * @see ProtocolProvider#lookupProtocol(int)
		 */
		@SuppressWarnings("unchecked")
		public <T extends Header> T newUnboundHeader() {
			Protocol protocol = ProtocolProvider.lookupProtocol(id);
			if (protocol == null)
				return null;

			Header header = protocol.headerFactory()
					.proxy()
					.newHeader();

			return (T) header;
		}

		/**
		 * Creates a new header instance and binds it to the specified packet.
		 * 
		 * <p>
		 * This is a convenience method that combines header creation and binding in a
		 * single operation. It creates a new header instance using
		 * {@link #newUnboundHeader()} and then binds it to the packet using the offset
		 * and length from this binding info.
		 * </p>
		 * 
		 * <h3>Example</h3>
		 * 
		 * <pre>{@code
		 * BindingInfo info = ...;
		 * BindableView packet = ...;
		 * 
		 * TcpHeader tcp = info.newBoundHeader(packet);
		 * if (tcp != null) {
		 *     int srcPort = tcp.sourcePort();
		 *     int dstPort = tcp.destinationPort();
		 *     // Process TCP header fields
		 * }
		 * }</pre>
		 *
		 * @param <T>    the expected header type
		 * @param packet the packet view to bind the header to
		 * @return a new header instance bound to the packet, or {@code null} if the
		 *         protocol is not found or not supported
		 * @see #newUnboundHeader()
		 * @see Header#bindHeader(BindableView, int, int, long, long)
		 */
		public <T extends Header> T newBoundHeader(BindableView packet) {
			T header = newUnboundHeader();
			if (header == null)
				return null;

			header.bindHeader(packet, id, 0, offset, length);

			return header;
		}
	}

	static void setUnsupportedProtocolBinding(HeaderBinding unsupportedBinding) {

		synchronized (PacketDescriptor.class) {
			if (unsupportedBinding == null)
				AbstractPacketDescriptor.UNSUPPORTED_HEADER_BINDING = HeaderBinding.INSTANCE;
			else
				AbstractPacketDescriptor.UNSUPPORTED_HEADER_BINDING = unsupportedBinding;
		}
	}

	/**
	 * Return code indicating that a protocol was not found in the descriptor.
	 * 
	 * <p>
	 * This constant is returned by {@link #mapProtocol(int, int)} when the
	 * requested protocol is not present in the packet or is not supported by this
	 * descriptor type.
	 * </p>
	 * 
	 * @see #mapProtocol(int, int)
	 */
	long PROTOCOL_NOT_FOUND = -1L;

	/** The protocol not supported. */
	long PROTOCOL_NOT_SUPPORTED = -2L;

	/**
	 * The default hash bit length used for RSS (Receive Side Scaling) hashing.
	 * 
	 * <p>
	 * This constant defines the standard 64-bit hash length used for hardware hash
	 * calculations. The hash value is typically computed by the NIC and used for
	 * distributing packets across multiple receive queues.
	 * </p>
	 */
	int DEFAULT_HASH_BIT_LENGTH = 64;

	/**
	 * The default descriptor size in bytes.
	 * 
	 * <p>
	 * This constant defines the standard size of a {@link NetPacketDescriptor},
	 * which is the most commonly used descriptor implementation. The size is
	 * optimized for cache line alignment and efficient memory access.
	 * </p>
	 * 
	 * @see NetPacketDescriptor#BYTE_SIZE
	 */
	long DEFAULT_DESCRIPTOR_SIZE = NetPacketDescriptor.BYTE_SIZE;

	/**
	 * Decodes the header length from an encoded offset/length value.
	 * 
	 * <p>
	 * Extracts the length component from a 64-bit encoded value where the length is
	 * stored in the upper 32 bits and the offset in the lower 32 bits. This
	 * encoding scheme allows efficient storage and retrieval of header location
	 * information.
	 * </p>
	 * 
	 * <h3>Encoding Format</h3>
	 * 
	 * <pre>
	 * 64-bit encoded value:
	 * +----------------+----------------+
	 * | Length (32-bit)| Offset (32-bit)|
	 * +----------------+----------------+
	 * Bits: 63      32  31            0
	 * </pre>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * long encoded = descriptor.mapProtocol(ProtocolId.TCP, 0);
	 * if (encoded != PROTOCOL_NOT_FOUND) {
	 * 	int length = PacketDescriptor.decodeLength(encoded);
	 * 	int offset = PacketDescriptor.decodeOffset(encoded);
	 * 	System.out.printf("TCP header at offset %d, length %d%n", offset, length);
	 * }
	 * }</pre>
	 *
	 * @param encoded the 64-bit encoded value containing length and offset
	 * @return the decoded length (upper 32 bits of the encoded value)
	 * @see #decodeOffset(long)
	 * @see #encodeLengthAndOffset(int, int)
	 * @see #mapProtocol(int, int)
	 */
	static int decodeLength(long encoded) {
		return (int) (encoded >>> 32);
	}

	/**
	 * Decodes the header offset from an encoded offset/length value.
	 * 
	 * <p>
	 * Extracts the offset component from a 64-bit encoded value where the length is
	 * stored in the upper 32 bits and the offset in the lower 32 bits. The offset
	 * represents the byte position of the header from the start of the packet.
	 * </p>
	 * 
	 * <h3>Encoding Format</h3>
	 * 
	 * <pre>
	 * 64-bit encoded value:
	 * +----------------+----------------+
	 * | Length (32-bit)| Offset (32-bit)|
	 * +----------------+----------------+
	 * Bits: 63      32  31            0
	 * </pre>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * long encoded = descriptor.mapProtocol(ProtocolId.UDP, 0);
	 * if (encoded != PROTOCOL_NOT_FOUND) {
	 * 	int offset = PacketDescriptor.decodeOffset(encoded);
	 * 	// Read UDP header starting at offset
	 * 	buffer.position(offset);
	 * }
	 * }</pre>
	 *
	 * @param encoded the 64-bit encoded value containing length and offset
	 * @return the decoded offset (lower 32 bits of the encoded value)
	 * @see #decodeLength(long)
	 * @see #encodeLengthAndOffset(int, int)
	 * @see #mapProtocol(int, int)
	 */
	static int decodeOffset(long encoded) {
		return (int) (encoded & 0xFFFF_FFFFL);
	}

	/**
	 * Encodes a header length and offset into a single 64-bit value.
	 * 
	 * <p>
	 * Combines the length and offset into a compact representation where the length
	 * occupies the upper 32 bits and the offset occupies the lower 32 bits. This
	 * encoding is used internally by the descriptor to efficiently store protocol
	 * header location information.
	 * </p>
	 * 
	 * <h3>Encoding Format</h3>
	 * 
	 * <pre>
	 * 64-bit encoded value:
	 * +----------------+----------------+
	 * | Length (32-bit)| Offset (32-bit)|
	 * +----------------+----------------+
	 * Bits: 63      32  31            0
	 * </pre>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * // Encode TCP header location: offset=34, length=20
	 * long encoded = PacketDescriptor.encodeLengthAndOffset(20, 34);
	 * 
	 * // Later decode the values
	 * int length = PacketDescriptor.decodeLength(encoded); // 20
	 * int offset = PacketDescriptor.decodeOffset(encoded); // 34
	 * }</pre>
	 *
	 * @param length the header length in bytes
	 * @param offset the header offset from packet start in bytes
	 * @return the encoded 64-bit value containing both length and offset
	 * @see #decodeLength(long)
	 * @see #decodeOffset(long)
	 */
	static long encodeLengthAndOffset(int length, int offset) {
		return ((long) length << 32) | (offset & 0xFFFF_FFFFL);
	}

	/**
	 * Binds a protocol header to its location within the packet.
	 * 
	 * <p>
	 * Maps the specified protocol ID to its offset and length in the packet, then
	 * binds the provided header object to that location. The length and offset are
	 * encoded in the upper and lower 32-bits of the returned long value
	 * respectively.
	 * </p>
	 * 
	 * <h3>Encoding Format</h3>
	 * 
	 * {@snippet lang = c:
	 * struct header_length_and_offset_s {
	 *     u64     length:32,
	 *             offset:32;
	 * }
	 * }
	 * 
	 * <p>
	 * If the header is not present or not supported, the method returns
	 * {@code false} and the header remains unbound.
	 * </p>
	 * 
	 * <h3>Depth Parameter</h3>
	 * 
	 * <p>
	 * The depth parameter supports tunneled protocols:
	 * </p>
	 * <ul>
	 * <li>{@code depth=0}: Outer/first occurrence of the protocol</li>
	 * <li>{@code depth=1}: Inner/second occurrence (after tunnel
	 * encapsulation)</li>
	 * <li>{@code depth=N}: Nth occurrence for deeply nested tunnels</li>
	 * </ul>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * Ip4Header ip = new Ip4Header();
	 * 
	 * // Bind to outer IP header
	 * if (descriptor.bindProtocol(packet, ip, ProtocolId.IP4, 0)) {
	 * 	System.out.println("Source IP: " + ip.sourceAddress());
	 * }
	 * 
	 * // For tunneled packets, bind to inner IP header
	 * if (descriptor.bindProtocol(packet, ip, ProtocolId.IP4, 1)) {
	 * 	System.out.println("Inner Source IP: " + ip.sourceAddress());
	 * }
	 * }</pre>
	 *
	 * @param packet     the source packet (a memory view) to bind to
	 * @param header     the header (a memory view) to bind to the packet using the
	 *                   header's specific bind method
	 * @param protocolId the protocol pack specific numeric protocol ID
	 * @param depth      the occurrence depth where 0 means outer/first occurrence,
	 *                   1 means inner/second occurrence, and so on for nested
	 *                   tunnels
	 * @return {@code true} if the protocol was found and the header was
	 *         successfully bound; {@code false} if the protocol is not present or
	 *         not supported
	 * @see Header#bindPacket(long, long, com.slytechs.sdk.protocol.core.Packet)
	 * @see #mapProtocol(int, int)
	 * @see ProtocolId
	 */
	boolean bindHeader(BindableView packet, Header header, int protocolId, int depth);

	/**
	 * Returns the number of bytes captured for this packet.
	 * 
	 * <p>
	 * The capture length represents the actual number of bytes available for
	 * processing. This may be less than the wire length if the packet was truncated
	 * due to snapshot length (snaplen) settings during capture.
	 * </p>
	 * 
	 * <h3>Capture Length Scenarios</h3>
	 * <ul>
	 * <li><strong>Full capture:</strong> captureLength == wireLength</li>
	 * <li><strong>Truncated:</strong> captureLength &lt; wireLength (snaplen
	 * limited)</li>
	 * <li><strong>Jumbo frames:</strong> captureLength may exceed standard MTU</li>
	 * <li><strong>Minimum:</strong> typically 14 bytes (Ethernet header)</li>
	 * </ul>
	 * 
	 * <h3>Example: Validating Capture Length</h3>
	 * 
	 * <pre>{@code
	 * public boolean isCompletePacket(PacketDescriptor desc) {
	 * 	int captured = desc.captureLength();
	 * 	int wire = desc.wireLength();
	 * 
	 * 	if (captured < wire) {
	 * 		// Packet was truncated during capture
	 * 		double percentage = (captured * 100.0) / wire;
	 * 		log.debug("Truncated packet: {:.1f}% captured", percentage);
	 * 		return false;
	 * 	}
	 * 
	 * 	return true;
	 * }
	 * }</pre>
	 * 
	 * @return the number of bytes captured, always positive
	 * @see #wireLength()
	 * @see #setCaptureLength(int)
	 */
	int captureLength();

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Returns an iterator over the binding information for all protocol headers
	 * detected in this packet descriptor. The iterator provides {@link BindingInfo}
	 * records in protocol order, starting from the outermost layer (typically L2).
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * for (BindingInfo info : packetDescriptor) {
	 * 	System.out.printf("Protocol %d at offset %d (length %d)%n",
	 * 			info.id(), info.offset(), info.length());
	 * }
	 * }</pre>
	 * 
	 * @return an iterator over the header binding information
	 * @see BindingInfo
	 */
	@Override
	default Iterator<BindingInfo> iterator() {
		var info = switch (l2FrameInfo()) {
		case L2FrameInfo.ETHER -> new BindingInfo(0, ProtocolId.ETHERNET, 0, 14);

		default -> throw new IllegalArgumentException("Unexpected value: " + l2FrameInfo());
		};

		return Stream.of(info).iterator();
	}

	/**
	 * Gets the Layer 2 frame type information.
	 * 
	 * <p>
	 * Returns the L2 frame type extracted from the RX_INFO field (bits 0-4) as an
	 * {@link L2FrameInfo} enumeration value. This method provides type-safe access
	 * to the frame type for determining the data link layer protocol.
	 * </p>
	 * 
	 * <h3>Supported Frame Types</h3>
	 * <ul>
	 * <li>{@code ETHER} - Ethernet II frame format</li>
	 * <li>{@code IEEE_802_3} - IEEE 802.3 frame format</li>
	 * <li>{@code LLC} - Logical Link Control frame</li>
	 * <li>{@code SNAP} - Subnetwork Access Protocol frame</li>
	 * </ul>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * L2FrameInfo frameInfo = descriptor.l2FrameInfo();
	 * switch (frameInfo) {
	 * case ETHER -> processEthernet(packet);
	 * case IEEE_802_3 -> process802_3(packet);
	 * case LLC -> processLLC(packet);
	 * case SNAP -> processSNAP(packet);
	 * }
	 * }</pre>
	 * 
	 * @return the L2 frame type information enumeration value
	 * @see L2FrameInfo
	 */
	L2FrameInfo l2FrameInfo();

	/**
	 * Maps a protocol ID to its header offset and length within the packet.
	 * 
	 * <p>
	 * Looks up the specified protocol in the descriptor and returns its location
	 * encoded as a 64-bit value. The length is stored in the upper 32 bits and the
	 * offset in the lower 32 bits.
	 * </p>
	 * 
	 * <h3>Encoding Format</h3>
	 * 
	 * {@snippet lang = c:
	 * struct header_length_and_offset_s {
	 *     u64     length:32,
	 *             offset:32;
	 * }
	 * }
	 * 
	 * <h3>Depth Parameter</h3>
	 * 
	 * <p>
	 * The depth parameter supports tunneled protocols where the same protocol may
	 * appear multiple times:
	 * </p>
	 * <ul>
	 * <li>{@code depth=0}: Outer/first occurrence of the protocol</li>
	 * <li>{@code depth=1}: Inner/second occurrence (e.g., after VXLAN tunnel)</li>
	 * <li>{@code depth=N}: Nth occurrence for deeply nested tunnels</li>
	 * </ul>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * // Look up TCP header location
	 * long encoded = descriptor.mapProtocol(ProtocolId.TCP, 0);
	 * if (encoded != PacketDescriptor.PROTOCOL_NOT_FOUND) {
	 * 	int offset = PacketDescriptor.decodeOffset(encoded);
	 * 	int length = PacketDescriptor.decodeLength(encoded);
	 * 
	 * 	buffer.position(offset);
	 * 	int srcPort = buffer.getShort() & 0xFFFF;
	 * 	int dstPort = buffer.getShort() & 0xFFFF;
	 * }
	 * }</pre>
	 *
	 * @param protocolId the protocol pack specific numeric protocol ID
	 * @param depth      the occurrence depth where 0 means outer/first occurrence,
	 *                   1 means inner/second occurrence, and so on
	 * @return the encoded length and offset as a 64-bit value, or
	 *         {@link #PROTOCOL_NOT_FOUND} (-1) if the protocol is not present
	 * @see #decodeLength(long)
	 * @see #decodeOffset(long)
	 * @see #bindHeader(BindableView, Header, int, int)
	 * @see ProtocolId
	 */
	long mapProtocol(int protocolId, int depth);

	/**
	 * Gets the byte order of the descriptor data.
	 * 
	 * <p>
	 * Returns the native byte order of the underlying platform for optimal
	 * performance when accessing descriptor fields. Network packet data itself is
	 * typically in network byte order (big-endian), but the descriptor metadata
	 * uses native order for efficient access.
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * ByteOrder order = descriptor.order();
	 * if (order == ByteOrder.LITTLE_ENDIAN) {
	 * 	// Descriptor uses little-endian format (x86/x64)
	 * } else {
	 * 	// Descriptor uses big-endian format (network order)
	 * }
	 * }</pre>
	 * 
	 * @return the byte order of the descriptor, typically
	 *         {@link ByteOrder#nativeOrder()}
	 */
	default ByteOrder order() {
		return ByteOrder.nativeOrder();
	}

	/**
	 * Sets the capture length of the received packet.
	 * 
	 * <p>
	 * Updates the descriptor's capture length field to reflect the number of bytes
	 * actually captured from the packet. This method supports method chaining for
	 * fluent configuration.
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * descriptor.setCaptureLength(1500)
	 * 		.setWireLength(1500)
	 * 		.setTimestamp(System.nanoTime());
	 * }</pre>
	 *
	 * @param length the number of bytes captured, must be non-negative
	 * @return this descriptor for method chaining
	 * @see #captureLength()
	 * @see #setWireLength(int)
	 */
	PacketDescriptor setCaptureLength(int length);

	/**
	 * Sets the L2 frame type.
	 * 
	 * <p>
	 * Updates the descriptor's L2 frame type field to indicate the data link layer
	 * protocol format. This information is used during packet processing to
	 * correctly parse the frame header.
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * descriptor.setL2FrameType(L2FrameInfo.ETHER)
	 * 		.setCaptureLength(packetLength);
	 * }</pre>
	 *
	 * @param l2FrameInfo the L2 frame information enumeration value
	 * @return this descriptor for method chaining
	 * @see #l2FrameInfo()
	 * @see L2FrameInfo
	 */
	PacketDescriptor setL2FrameType(L2FrameInfo l2FrameInfo);

	/**
	 * Sets the receive timestamp.
	 * 
	 * <p>
	 * Updates the descriptor's timestamp field with the specified value. The
	 * timestamp unit is determined by the current timestamp unit setting or
	 * defaults to the system's native unit.
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * // Set timestamp using system nanoseconds
	 * descriptor.setTimestamp(System.nanoTime());
	 * 
	 * // Or with explicit unit
	 * descriptor.setTimestamp(epochMillis, TimestampUnit.MILLISECONDS);
	 * }</pre>
	 *
	 * @param timestamp the timestamp value in the current or default unit
	 * @return this descriptor for method chaining
	 * @see #timestamp()
	 * @see #setTimestamp(long, TimestampUnit)
	 * @see #timestampUnit()
	 */
	PacketDescriptor setTimestamp(long timestamp);

	/**
	 * Sets the receive timestamp with the specified unit.
	 * 
	 * <p>
	 * Updates both the descriptor's timestamp field and timestamp unit. This method
	 * ensures the timestamp value is correctly interpreted according to the
	 * specified unit.
	 * </p>
	 * 
	 * <h3>Supported Units</h3>
	 * <ul>
	 * <li>{@code NANOSECONDS} - Nanosecond precision</li>
	 * <li>{@code MICROSECONDS} - Microsecond precision</li>
	 * <li>{@code MILLISECONDS} - Millisecond precision</li>
	 * <li>{@code SECONDS} - Second precision</li>
	 * <li>{@code EPOCH_MILLIS} - Milliseconds since Unix epoch</li>
	 * <li>{@code EPOCH_MICRO} - Microseconds since Unix epoch</li>
	 * </ul>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * // Set timestamp with microsecond precision
	 * long microTimestamp = System.currentTimeMillis() * 1000;
	 * descriptor.setTimestamp(microTimestamp, TimestampUnit.MICROSECONDS);
	 * }</pre>
	 *
	 * @param timestamp the timestamp value
	 * @param unit      the unit of the timestamp value
	 * @return this descriptor for method chaining
	 * @see #timestamp()
	 * @see #timestamp(TimestampUnit)
	 * @see #setTimestampUnit(TimestampUnit)
	 */
	PacketDescriptor setTimestamp(long timestamp, TimestampUnit unit);

	/**
	 * Sets the timestamp unit for this descriptor.
	 * 
	 * <p>
	 * Updates the descriptor's timestamp unit field without modifying the timestamp
	 * value. This is useful when the timestamp has already been set and only the
	 * unit interpretation needs to be changed.
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * descriptor.setTimestampUnit(TimestampUnit.NANOSECONDS);
	 * }</pre>
	 *
	 * @param unit the timestamp unit to use for interpreting timestamp values
	 * @return this descriptor for method chaining
	 * @see #timestampUnit()
	 * @see #setTimestamp(long, TimestampUnit)
	 */
	PacketDescriptor setTimestampUnit(TimestampUnit unit);

	/**
	 * Sets the wire length of the received packet.
	 * 
	 * <p>
	 * Updates the descriptor's wire length field to reflect the original packet
	 * size as transmitted on the network. This value may differ from the capture
	 * length if the packet was truncated during capture.
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * // Full packet capture
	 * descriptor.setCaptureLength(1500)
	 * 		.setWireLength(1500);
	 * 
	 * // Truncated capture (snaplen = 96)
	 * descriptor.setCaptureLength(96)
	 * 		.setWireLength(1500);
	 * }</pre>
	 *
	 * @param length the original packet size on the wire in bytes
	 * @return this descriptor for method chaining
	 * @see #wireLength()
	 * @see #setCaptureLength(int)
	 */
	PacketDescriptor setWireLength(int length);

	/**
	 * Gets the packet receive timestamp.
	 * 
	 * <p>
	 * Returns the raw timestamp value in the unit specified by
	 * {@link #timestampUnit()}. For timestamps in a specific unit, use
	 * {@link #timestamp(TimestampUnit)} instead.
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * long ts = descriptor.timestamp();
	 * TimestampUnit unit = descriptor.timestampUnit();
	 * System.out.printf("Timestamp: %d %s%n", ts, unit);
	 * }</pre>
	 *
	 * @return the timestamp value in the descriptor's native unit
	 * @see #timestamp(TimestampUnit)
	 * @see #timestampUnit()
	 * @see #setTimestamp(long)
	 */
	long timestamp();

	/**
	 * Gets the timestamp converted to the specified unit.
	 * 
	 * <p>
	 * Converts the descriptor's timestamp from its native unit to the requested
	 * unit. This is useful for comparing timestamps from different sources or
	 * displaying timestamps in a specific format.
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * // Get timestamp as epoch milliseconds
	 * long epochMs = descriptor.timestamp(TimestampUnit.EPOCH_MILLIS);
	 * Date captureTime = new Date(epochMs);
	 * 
	 * // Calculate inter-packet gap in microseconds
	 * long ts1 = desc1.timestamp(TimestampUnit.MICROSECONDS);
	 * long ts2 = desc2.timestamp(TimestampUnit.MICROSECONDS);
	 * long gapMicros = ts2 - ts1;
	 * }</pre>
	 *
	 * @param unit the target unit for the timestamp
	 * @return the timestamp converted to the specified unit
	 * @see #timestamp()
	 * @see #timestampUnit()
	 * @see TimestampUnit#convert(long, TimestampUnit)
	 */
	default long timestamp(TimestampUnit unit) {
		return unit.convert(timestamp(), timestampUnit());
	}

	/**
	 * Gets the timestamp unit used by this descriptor.
	 * 
	 * <p>
	 * Returns the unit in which the descriptor's timestamp is stored. This
	 * information is essential for correctly interpreting the raw timestamp value
	 * returned by {@link #timestamp()}.
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * TimestampUnit unit = descriptor.timestampUnit();
	 * if (unit == TimestampUnit.NANOSECONDS) {
	 * 	// High-precision hardware timestamp
	 * } else if (unit == TimestampUnit.MILLISECONDS) {
	 * 	// Software timestamp
	 * }
	 * }</pre>
	 *
	 * @return the timestamp unit enumeration value
	 * @see #timestamp()
	 * @see #timestamp(TimestampUnit)
	 * @see #setTimestampUnit(TimestampUnit)
	 */
	TimestampUnit timestampUnit();

	/**
	 * Returns the original length of the packet on the wire.
	 * 
	 * <p>
	 * The wire length represents the packet's actual size as transmitted on the
	 * network, regardless of capture truncation. This value is essential for
	 * accurate statistics and bandwidth calculations.
	 * </p>
	 * 
	 * <h3>Common Wire Lengths</h3>
	 * <table border="1">
	 * <caption>Typical Packet Sizes</caption>
	 * <tr>
	 * <th>Type</th>
	 * <th>Size</th>
	 * <th>Description</th>
	 * </tr>
	 * <tr>
	 * <td>Minimum Ethernet</td>
	 * <td>64</td>
	 * <td>Including padding</td>
	 * </tr>
	 * <tr>
	 * <td>Standard MTU</td>
	 * <td>1518</td>
	 * <td>With Ethernet + FCS</td>
	 * </tr>
	 * <tr>
	 * <td>VLAN Tagged</td>
	 * <td>1522</td>
	 * <td>Additional 4 bytes</td>
	 * </tr>
	 * <tr>
	 * <td>Jumbo Frame</td>
	 * <td>9000+</td>
	 * <td>Extended MTU</td>
	 * </tr>
	 * </table>
	 * 
	 * <h3>Example: Bandwidth Calculation</h3>
	 * 
	 * <pre>{@code
	 * public class BandwidthMonitor {
	 * 	private long totalBytes = 0;
	 * 	private long startTime = System.nanoTime();
	 * 
	 * 	public void addPacket(PacketDescriptor desc) {
	 * 		// Use wire length for accurate bandwidth
	 * 		totalBytes += desc.wireLength();
	 * 	}
	 * 
	 * 	public double getBandwidthMbps() {
	 * 		long elapsed = System.nanoTime() - startTime;
	 * 		double seconds = elapsed / 1_000_000_000.0;
	 * 		double megabits = (totalBytes * 8) / 1_000_000.0;
	 * 		return megabits / seconds;
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * @return the original packet size in bytes
	 * @see #captureLength()
	 * @see #setWireLength(int)
	 */
	int wireLength();

	/**
	 * Gets the RX capabilities bitmask.
	 * 
	 * <p>
	 * Returns a bitmask indicating supported receive-side capabilities, as defined
	 * in {@link DescriptorCapability}. These capabilities indicate what features
	 * the descriptor supports for received packets, such as hardware timestamps,
	 * checksum validation, and RSS hashing.
	 * </p>
	 * 
	 * <h3>Example: Checking RX Capabilities</h3>
	 * 
	 * <pre>{@code
	 * long rxCaps = desc.rxCapabilitiesBitmask();
	 * if ((rxCaps & DescriptorCapability.RX_TIMESTAMP) != 0) {
	 * 	long ts = desc.timestamp();
	 * 	// Process hardware timestamp
	 * }
	 * if ((rxCaps & DescriptorCapability.RX_CHECKSUM) != 0) {
	 * 	// Checksum was validated by hardware
	 * }
	 * }</pre>
	 *
	 * @return the RX capabilities bitmask
	 * @see DescriptorCapability
	 * @see RxCapabilities
	 * @see #rxCapabilities()
	 * @see #isRxSupported()
	 */
	long rxCapabilitiesBitmask();

	/**
	 * Gets the TX capabilities bitmask.
	 * 
	 * <p>
	 * Returns a bitmask indicating supported transmit-side capabilities, as defined
	 * in {@link DescriptorCapability}. These capabilities indicate what offload
	 * features are available for transmitted packets, such as TCP segmentation
	 * offload (TSO), checksum offload, and VLAN insertion.
	 * </p>
	 * 
	 * <h3>Example: Checking TX Capabilities</h3>
	 * 
	 * <pre>{@code
	 * long txCaps = desc.txCapabilitiesBitmask();
	 * if ((txCaps & DescriptorCapability.TX_TCP_SEGMENTATION) != 0) {
	 * 	// Enable TSO for large TCP transfers
	 * 	desc.setTsoSegmentSize(mss);
	 * }
	 * if ((txCaps & DescriptorCapability.TX_CHECKSUM) != 0) {
	 * 	// Hardware will compute checksum
	 * }
	 * }</pre>
	 *
	 * @return the TX capabilities bitmask
	 * @see DescriptorCapability
	 * @see TxCapabilities
	 * @see #txCapabilities()
	 * @see #isTxSupported()
	 */
	long txCapabilitiesBitmask();

	/**
	 * Checks if TX descriptor properties are supported.
	 * 
	 * <p>
	 * Returns {@code true} if this descriptor supports any transmit-side
	 * capabilities. This is a convenience method equivalent to checking if
	 * {@link #txCapabilitiesBitmask()} returns a non-zero value.
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * if (descriptor.isTxSupported()) {
	 * 	// Configure TX offloads
	 * 	TxCapabilities txCaps = descriptor.txCapabilities();
	 * 	if (txCaps.hasTsoSupport()) {
	 * 		enableTso(descriptor);
	 * 	}
	 * }
	 * }</pre>
	 *
	 * @return {@code true} if TX extended properties are supported, {@code false}
	 *         otherwise
	 * @see #txCapabilitiesBitmask()
	 * @see #txCapabilities()
	 * @see TxCapabilities#TX_NONE
	 */
	default boolean isTxSupported() {
		return txCapabilitiesBitmask() != TxCapabilities.TX_NONE;
	}

	/**
	 * Checks if extended RX descriptor properties are supported.
	 * 
	 * <p>
	 * Returns {@code true} if this descriptor supports any receive-side
	 * capabilities. This is a convenience method equivalent to checking if
	 * {@link #rxCapabilitiesBitmask()} returns a non-zero value.
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * if (descriptor.isRxSupported()) {
	 * 	// Access RX-specific information
	 * 	RxCapabilities rxCaps = descriptor.rxCapabilities();
	 * 	if (rxCaps.hasHardwareTimestamp()) {
	 * 		processTimestamp(descriptor.timestamp());
	 * 	}
	 * }
	 * }</pre>
	 *
	 * @return {@code true} if RX extended properties are supported, {@code false}
	 *         otherwise
	 * @see #rxCapabilitiesBitmask()
	 * @see #rxCapabilities()
	 * @see RxCapabilities#RX_NONE
	 */
	default boolean isRxSupported() {
		return rxCapabilitiesBitmask() != RxCapabilities.RX_NONE;
	}

	/**
	 * Gets the RX capabilities object.
	 * 
	 * <p>
	 * Returns an {@link RxCapabilities} object that provides a type-safe,
	 * object-oriented interface for querying receive-side capabilities. This is
	 * preferred over direct bitmask manipulation for cleaner code.
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * RxCapabilities rxCaps = descriptor.rxCapabilities();
	 * 
	 * if (rxCaps.hasHardwareTimestamp()) {
	 * 	long hwTimestamp = descriptor.timestamp();
	 * 	// High-precision timestamp from NIC
	 * }
	 * 
	 * if (rxCaps.hasRssHash()) {
	 * 	long hash = descriptor.hash();
	 * 	// Use for flow distribution
	 * }
	 * }</pre>
	 *
	 * @return the RX capabilities object providing type-safe capability queries
	 * @see RxCapabilities
	 * @see #rxCapabilitiesBitmask()
	 * @see #isRxSupported()
	 */
	RxCapabilities rxCapabilities();

	/**
	 * Gets the TX capabilities object.
	 * 
	 * <p>
	 * Returns a {@link TxCapabilities} object that provides a type-safe,
	 * object-oriented interface for querying transmit-side capabilities. This is
	 * preferred over direct bitmask manipulation for cleaner code.
	 * </p>
	 * 
	 * <h3>Example</h3>
	 * 
	 * <pre>{@code
	 * TxCapabilities txCaps = descriptor.txCapabilities();
	 * 
	 * if (txCaps.hasTsoSupport()) {
	 * 	// Configure TCP Segmentation Offload
	 * 	descriptor.setTsoSegmentSize(1460);
	 * }
	 * 
	 * if (txCaps.hasChecksumOffload()) {
	 * 	// Hardware will compute checksums
	 * 	descriptor.enableChecksumOffload();
	 * }
	 * }</pre>
	 *
	 * @return the TX capabilities object providing type-safe capability queries
	 * @see TxCapabilities
	 * @see #txCapabilitiesBitmask()
	 * @see #isTxSupported()
	 */
	TxCapabilities txCapabilities();
}