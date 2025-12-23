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
import java.util.Iterator;
import java.util.stream.Stream;

import com.slytechs.jnet.core.api.memory.BindableView;
import com.slytechs.jnet.core.api.memory.ByteBuf;
import com.slytechs.jnet.core.api.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.Header;
import com.slytechs.jnet.protocol.api.HeaderAccessor;
import com.slytechs.jnet.protocol.api.Protocol;
import com.slytechs.jnet.protocol.api.ProtocolId;
import com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor.BindingInfo;
import com.slytechs.jnet.protocol.api.spi.ProtocolProvider;

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
public interface PacketDescriptor extends Descriptor, Iterable<BindingInfo>, BindableView {

	/**
	 * Information about find entry in the descriptor. Used for toString not for
	 * hot-path protocol discovery.
	 */
	public record BindingInfo(int order, int id, long offset, long length) {
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

		public <T extends Header> T newBoundHeader(ByteBuf packet) {
			T header = newUnboundHeader();
			if (header == null)
				return null;

			header.bindHeader(packet, id, 0, offset, length);

			return header;
		}
	}

	/** The protocol not found return code from mapProtocol. */
	long PROTOCOL_NOT_FOUND = -1L;

	/** The default hash bit length. */
	int DEFAULT_HASH_BIT_LENGTH = 64;

	/**
	 * Decode length.
	 *
	 * @param encoded the encoded
	 * @return the int
	 */
	static int decodeLength(long encoded) {
		return (int) ((encoded >> 32) & 0xFFFFFFFF);
	}

	/**
	 * Decode offset.
	 *
	 * @param encoded the encoded
	 * @return the int
	 */
	static int decodeOffset(long encoded) {
		return (int) ((encoded >> 0) & 0xFFFFFFFF);
	}

	/**
	 * Encode length and offset.
	 * 
	 * @param length the length
	 * @param offset the offset
	 *
	 * @return the long
	 */
	static long encodeLengthAndOffset(int length, int offset) {
		return ((long) length) << 32 | offset;
	}

	/**
	 * Maps a given protocol ID to a offset and length of the protocol header. The
	 * length and offset are encoded into upper and lower 32-bits of the returned
	 * long.
	 * {@snippet lang = c:
	 * struct header_length_and_offset_s {
	 * 		u64		length:32,
	 * 				offset:32;
	 * }
	 * }
	 * 
	 * If header is not present, or supported, a -1 is returned.
	 *
	 * @param packet the source packet (a memory view) to bind to
	 * @param header the header (a memory view) to bind to the packet using the
	 *               Header's specific bind method
	 * @param id     the protocol pack specific numeric protocol id
	 * @param depth  depth of 0 means outer, depth of 1 means inner protocol and so
	 *               on
	 * @return true if protocol was found and bound
	 * @see Header#bindPacket(long, long, com.slytechs.jnet.protocol.api.Packet)
	 */
	boolean bindProtocol(ByteBuf packet, Header header, int protocolId, int depth);

	/**
	 * Returns the number of bytes captured for this packet.
	 * 
	 * <p>
	 * The capture length represents the actual number of bytes available for
	 * processing. This may be less than the wire length if the packet was truncated
	 * due to snapshot length (snaplen) settings during capture.
	 * 
	 * <h3>Capture Length Scenarios</h3>
	 * <ul>
	 * <li><strong>Full capture:</strong> captureLength == wireLength</li>
	 * <li><strong>Truncated:</strong> captureLength < wireLength (snaplen
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
	 * Gets the Layer 2 frame type as an integer value.
	 * 
	 * <p>
	 * Extracts the L2 frame type from the RX_INFO field (bits 0-4) and returns it
	 * as a primitive int. This method provides direct access to the raw frame type
	 * value without enum conversion overhead, useful for performance-critical code
	 * paths or when working with custom frame types not defined in the L2FrameType
	 * enum.
	 * </p>
	 * 
	 * <p>
	 * Standard frame type values:
	 * <ul>
	 * <li>1 - Ethernet II</li>
	 * <li>2 - IEEE 802.3</li>
	 * <li>3 - LLC</li>
	 * <li>4 - SNAP</li>
	 * </ul>
	 * </p>
	 * 
	 * @return the L2 frame type index (0-31)
	 * @see L2FrameType
	 * @see #l2FrameType()
	 */
	int l2FrameType();

	/**
	 * Maps a given protocol ID to a offset and length of the protocol header. The
	 * length and offset are encoded into upper and lower 32-bits of the returned
	 * long.
	 * {@snippet lang = c:
	 * struct header_length_and_offset_s {
	 * 		u64		length:32,
	 * 				offset:32;
	 * }
	 * }
	 * 
	 * If header is not present, or supported, a -1 is returned.
	 *
	 * @param id    the protocol id
	 * @param depth TODO
	 * @return the encoded length and offset or -1 if not present
	 */
	long mapProtocol(int protocolId, int depth);

	default ByteOrder order() {
		return ByteOrder.nativeOrder();
	}

	void setL2Type(int l2Type);

	/**
	 * Sets the capture length of the received packet.
	 *
	 * @param length the number of bytes captured
	 */
	void setCaptureLength(int length);

	/**
	 * Sets the receive timestamp.
	 *
	 * @param timestamp the timestamp value
	 */
	void setTimestamp(long timestamp);

	/**
	 * Sets the timestamp.
	 *
	 * @param timestamp the timestamp
	 * @param unit      the unit
	 */
	void setTimestamp(long timestamp, TimestampUnit unit);

	void setTimestampUnit(TimestampUnit unit);

	/**
	 * Sets the wire length of the received packet.
	 *
	 * @param length the original packet size on the wire
	 */
	void setWireLength(int length);

	/**
	 * Timestamp.
	 *
	 * @return the long
	 */
	long timestamp();

	default long timestamp(TimestampUnit unit) {
		return unit.convert(timestamp(), timestampUnit());
	}

	/**
	 * Timestamp unit.
	 *
	 * @return the timestamp unit
	 */
	TimestampUnit timestampUnit();

	/**
	 * Returns the original length of the packet on the wire.
	 * 
	 * <p>
	 * The wire length represents the packet's actual size as transmitted on the
	 * network, regardless of capture truncation. This value is essential for
	 * accurate statistics and bandwidth calculations.
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
	 * @see java.lang.Iterable#iterator()
	 */
	@Override
	default Iterator<BindingInfo> iterator() {
		var info = switch (l2FrameType()) {
		case L2FrameType.ETHER -> new BindingInfo(0, ProtocolId.ETHERNET, 0, 14);

		default -> throw new IllegalArgumentException("Unexpected value: " + l2FrameType());
		};

		return Stream.of(info).iterator();
	}

	/**
	 * @param port
	 * @return
	 */
	PacketDescriptor setTxPort(int port);

	/**
	 * @return
	 */
	int txPort();

	/**
	 * @return
	 */
	boolean isTxEnabled();

	/**
	 * @param enabled
	 * @return
	 */
	PacketDescriptor setTxEnabled(boolean enabled);

	/**
	 * @param immediate
	 * @return
	 */
	PacketDescriptor setTxImmediate(boolean immediate);

	/**
	 * @return
	 */
	boolean isTxImmediate();

	/**
	 * @return
	 */
	boolean isTxCrcRecalc();

	/**
	 * @return
	 */
	boolean isTxTimestampSync();

	/**
	 * @param sync
	 * @return
	 */
	NetPacketDescriptor setTxTimestampSync(boolean sync);

	/**
	 * @param recalc
	 * @return
	 */
	NetPacketDescriptor setTxCrcRecalc(boolean recalc);
}
