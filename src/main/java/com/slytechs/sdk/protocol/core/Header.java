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
package com.slytechs.sdk.protocol.core;

import java.lang.foreign.MemoryLayout;

import com.slytechs.sdk.common.memory.BindableView;
import com.slytechs.sdk.common.memory.BoundView;
import com.slytechs.sdk.common.memory.MemoryStructure;
import com.slytechs.sdk.common.util.Named;
import com.slytechs.sdk.protocol.core.pack.ProtocolPackManager;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public sealed abstract class Header
		extends BoundView
		implements MemoryStructure, Named
		permits FixedHeader, VariableHeader, ExtensibleHeader {

	private final int protocolId;
	private long headerOffset;
	private int depth;
	private Packet packet;
	private final MemoryLayout layout;
	private final String name;

	public Header(int id, MemoryLayout layout) {
		this.protocolId = id;
		this.layout = layout;
		this.name = getClass().getSimpleName();
	}

	@Override
	public String name() {
		return name;
	}

	public boolean bindHeader(
			BindableView packet,
			int protocolId,
			int innerDepth,
			long offset,
			long extendedLength) {

		assert this.protocolId == protocolId;

		this.packet = (Packet) packet;
		this.depth = innerDepth;
		this.headerOffset = offset;

		super.bind(packet, offset, extendedLength);

		onBindPacket();

		return true;
	}

	public Protocol getHeaderProtocol() {
		return ProtocolPackManager.lookupProtocol(getClass());
	}

	public final int getInnerDepth() {
		return depth;
	}

	public final Packet getPacket() {
		return packet;
	}

	public final int getProtocolId() {
		return protocolId;
	}

	/**
	 * Returns the extended length of this header including all additional
	 * components beyond the base structure in bytes.
	 * 
	 * <p>
	 * The extended length represents the full extent of the header including any
	 * additions that extend it beyond its base form. This encompasses integrated
	 * options (for VariableHeader types) or chained extension headers (for
	 * ExtensibleHeader types). This measurement spans from the start of this header
	 * to the beginning of the next independent protocol layer.
	 * 
	 * <h3>Header Type Behaviors:</h3>
	 * <ul>
	 * <li><strong>FixedHeader:</strong> Same as {@link #headerMinLength()} and
	 * {@link #headerLength()} - cannot be extended</li>
	 * <li><strong>VariableHeader:</strong> Same as {@link #headerLength()} -
	 * options are integrated within the header</li>
	 * <li><strong>ExtensibleHeader:</strong> Includes the base header plus all
	 * chained extension headers (e.g., IPv6 base + Hop-by-Hop + Routing + Fragment
	 * headers)</li>
	 * <li><strong>StructuredHeader:</strong> May include related sub-structures or
	 * dependent protocol elements</li>
	 * </ul>
	 * 
	 * <h3>Use Cases:</h3>
	 * <ul>
	 * <li>Calculating the offset to the next protocol layer</li>
	 * <li>Determining the complete protocol overhead</li>
	 * <li>Skipping all headers related to this protocol</li>
	 * <li>Memory buffer allocation for protocol processing</li>
	 * </ul>
	 * 
	 * <h3>IPv6 Extension Chain Example:</h3>
	 * 
	 * <pre>{@code
	 * Ip6 ipv6 = new Ip6();
	 * packet.getHeader(ipv6);
	 * 
	 * long base = ipv6.baseLength(); // 40 (just IPv6 header)
	 * long total = ipv6.totalLength(); // 40 (extensions not included)
	 * long extended = ipv6.extendedLength(); // 40 + all extension headers
	 * 
	 * // Skip to upper layer protocol
	 * long upperLayerOffset = ipv6.headerOffset() + ipv6.extendedLength();
	 * }</pre>
	 * 
	 * <h3>TCP with Options Example:</h3>
	 * 
	 * <pre>{@code
	 * Tcp tcp = new Tcp();
	 * packet.getHeader(tcp);
	 * 
	 * long base = tcp.baseLength(); // 20 (minimum TCP header)
	 * long total = tcp.totalLength(); // e.g., 32 (includes options)
	 * long extended = tcp.extendedLength(); // 32 (same as total for VariableHeader)
	 * }</pre>
	 * 
	 * <h3>Relationship Summary:</h3>
	 * 
	 * <pre>
	 * baseLength() ≤ totalLength() ≤ extendedLength()
	 * 
	 * For FixedHeader:      base == total == extended
	 * For VariableHeader:   base ≤ total == extended
	 * For ExtensibleHeader: base == total ≤ extended
	 * </pre>
	 * 
	 * <h3>Implementation Note:</h3>
	 * <p>
	 * The default implementation returns {@link #headerMinLength()} which is
	 * correct for FixedHeader types. VariableHeader overrides to return
	 * {@link #headerLength()}, and ExtensibleHeader overrides to calculate the sum
	 * of all extensions.
	 * 
	 * @return the extended length including all additional components in bytes,
	 *         always ≥ {@link #headerLength()}
	 * @see #headerMinLength()
	 * @see #headerLength()
	 * @see #extensionsLength() for ExtensibleHeader implementations
	 * @see #optionsLength() for VariableHeader implementations
	 * @since 1.0
	 */
	public long headerChainLength() {
		return headerMinLength();
	}

	/**
	 * Returns the total length of this header including any integrated
	 * variable-length components in bytes.
	 * 
	 * <p>
	 * The header length encompasses the complete header as defined by the protocol,
	 * including any variable-length fields that are considered part of the header
	 * structure itself. This typically includes options that are embedded within
	 * the header but excludes separate extension headers that follow.
	 * 
	 * <h3>Header Type Behaviors:</h3>
	 * <ul>
	 * <li><strong>FixedHeader:</strong> Same as {@link #headerMinLength()} - the
	 * header has no variable components</li>
	 * <li><strong>VariableHeader:</strong> Includes the base header plus all
	 * embedded options. This value is typically read from a length field within the
	 * header (e.g., IHL field in IPv4, Data Offset in TCP)</li>
	 * <li><strong>ExtensibleHeader:</strong> Returns only the base header size,
	 * excluding extension headers which are separate protocol entities</li>
	 * <li><strong>StructuredHeader:</strong> May include variable-length attributes
	 * or fields as defined by the application protocol</li>
	 * </ul>
	 * 
	 * <h3>Protocol Examples:</h3>
	 * <table border="1">
	 * <tr>
	 * <th>Protocol</th>
	 * <th>Base Length</th>
	 * <th>Total Length</th>
	 * <th>Calculation</th>
	 * </tr>
	 * <tr>
	 * <td>Ethernet</td>
	 * <td>14</td>
	 * <td>14</td>
	 * <td>Fixed size</td>
	 * </tr>
	 * <tr>
	 * <td>IPv4</td>
	 * <td>20</td>
	 * <td>20-60</td>
	 * <td>IHL × 4</td>
	 * </tr>
	 * <tr>
	 * <td>IPv6</td>
	 * <td>40</td>
	 * <td>40</td>
	 * <td>Fixed (extensions separate)</td>
	 * </tr>
	 * <tr>
	 * <td>TCP</td>
	 * <td>20</td>
	 * <td>20-60</td>
	 * <td>Data Offset × 4</td>
	 * </tr>
	 * <tr>
	 * <td>UDP</td>
	 * <td>8</td>
	 * <td>8</td>
	 * <td>Fixed size</td>
	 * </tr>
	 * </table>
	 * 
	 * <h3>Memory View:</h3>
	 * <p>
	 * The total length defines the boundary between the header and its payload:
	 * 
	 * <pre>
	 * [Start of Header]...[Start + totalLength] → [Payload begins here]
	 * </pre>
	 * 
	 * @return the total header length including integrated options in bytes, always
	 *         ≥ {@link #headerMinLength()}
	 * @see #headerMinLength()
	 * @see #headerChainLength()
	 * @see #optionsLength() for VariableHeader implementations
	 * @since 1.0
	 */
	public long headerLength() {
		return headerMinLength();
	}

	/**
	 * Returns the minimum (static) length of this header in bytes.
	 * 
	 * <p>
	 * The minimum length represents the fixed, minimum size of the protocol header
	 * structure as defined by its specification. This is the size of the mandatory
	 * fields that are always present, regardless of any variable-length components
	 * such as options or extensions.
	 * 
	 * <h3>Header Type Behaviors:</h3>
	 * <ul>
	 * <li><strong>FixedHeader:</strong> Returns the complete header size (same as
	 * {@link #headerLength()} and {@link #headerChainLength()})</li>
	 * <li><strong>VariableHeader:</strong> Returns only the fixed portion,
	 * excluding any options (e.g., 20 bytes for TCP, 20 bytes for IPv4)</li>
	 * <li><strong>ExtensibleHeader:</strong> Returns the base header size,
	 * excluding all extension headers (e.g., 40 bytes for IPv6)</li>
	 * <li><strong>StructuredHeader:</strong> Returns the minimum required header
	 * size for the protocol</li>
	 * </ul>
	 * 
	 * <h3>Implementation Note:</h3>
	 * <p>
	 * The default implementation returns the size of the memory layout associated
	 * with this header. Subclasses typically do not need to override this method
	 * unless they have dynamic base structures.
	 * 
	 * <h3>Example Usage:</h3>
	 * 
	 * <pre>{@code
	 * Tcp tcp = new Tcp();
	 * packet.getHeader(tcp);
	 * 
	 * long base = tcp.baseLength(); // Always 20 for TCP
	 * long total = tcp.totalLength(); // 20-60 depending on options
	 * 
	 * // Calculate options length
	 * long optionsLen = total - base;
	 * }</pre>
	 * 
	 * @return the base header length in bytes, always ≥ 0
	 * @see #headerLength()
	 * @see #headerChainLength()
	 * @since 1.0
	 */
	public long headerMinLength() {
		return layout.byteSize();
	}

	/**
	 * Returns the absolute offset of this header within the packet data in bytes.
	 * 
	 * <p>
	 * The header offset represents the starting position of this header relative to
	 * the beginning of the packet's memory segment. This is an absolute offset that
	 * can be used to directly access the header's data within the packet buffer.
	 * The offset remains constant for the lifetime of the header binding.
	 * 
	 * <h3>Offset Calculation:</h3>
	 * <p>
	 * The offset is determined during packet dissection and header binding:
	 * <ul>
	 * <li>Set when the header is bound to the packet via {@code bindPacket()}</li>
	 * <li>Calculated by the dissector based on preceding headers</li>
	 * <li>Accounts for all previous headers including their options/extensions</li>
	 * <li>Remains valid until the header is unbound</li>
	 * </ul>
	 * 
	 * <h3>Common Use Cases:</h3>
	 * <ul>
	 * <li>Direct memory access to header fields</li>
	 * <li>Calculating relative positions of header fields</li>
	 * <li>Determining payload offset: {@code headerOffset() + totalLength()}</li>
	 * <li>Locating options/extensions within the header</li>
	 * <li>Debugging packet structure and layout</li>
	 * </ul>
	 * 
	 * <h3>Example - Typical Packet Offsets:</h3>
	 * 
	 * <pre>{@code
	 * // Ethernet -> IPv4 -> TCP packet structure
	 * Ethernet eth = new Ethernet();
	 * Ip4 ip4 = new Ip4();
	 * Tcp tcp = new Tcp();
	 * 
	 * packet.getHeader(eth);
	 * packet.getHeader(ip4);
	 * packet.getHeader(tcp);
	 * 
	 * eth.headerOffset(); // 0 (always at packet start)
	 * ip4.headerOffset(); // 14 (after Ethernet)
	 * tcp.headerOffset(); // 34 (14 + 20, assuming no IP options)
	 * 
	 * // Calculate TCP payload offset
	 * long payloadOffset = tcp.headerOffset() + tcp.totalLength();
	 * }</pre>
	 * 
	 * <h3>Relationship to Memory Operations:</h3>
	 * 
	 * <pre>{@code
	 * // Reading a field at specific offset within header
	 * long fieldOffset = header.headerOffset() + 12; // 12 bytes into header
	 * int value = packet.getInt(fieldOffset);
	 * 
	 * // Accessing header memory directly
	 * MemorySegment segment = packet.segment();
	 * long absolutePos = packet.start() + header.headerOffset();
	 * byte firstByte = segment.get(ValueLayout.JAVA_BYTE, absolutePos);
	 * }</pre>
	 * 
	 * <h3>Tunneled Protocols:</h3>
	 * <p>
	 * For tunneled protocols, each header maintains its own offset regardless of
	 * encapsulation depth:
	 * 
	 * <pre>{@code
	 * // Outer IP -> GRE -> Inner IP -> TCP
	 * Ip4 outerIp = new Ip4();
	 * Ip4 innerIp = new Ip4();
	 * 
	 * packet.getHeader(outerIp, 0); // Depth 0 (outer)
	 * packet.getHeader(innerIp, 1); // Depth 1 (inner)
	 * 
	 * outerIp.headerOffset(); // e.g., 14 (after Ethernet)
	 * innerIp.headerOffset(); // e.g., 42 (after Outer IP + GRE)
	 * }</pre>
	 * 
	 * <h3>Implementation Notes:</h3>
	 * <ul>
	 * <li>The offset is relative to the packet's data region, not the memory
	 * segment</li>
	 * <li>For chained packets, offset is relative to the containing segment</li>
	 * <li>The value is undefined if the header is not bound to a packet</li>
	 * <li>Thread-safe once bound (immutable during binding lifetime)</li>
	 * </ul>
	 * 
	 * @return the absolute offset of this header within the packet in bytes, always
	 *         ≥ 0 when bound
	 * @throws IllegalStateException if the header is not currently bound to a
	 *                               packet
	 * @see #headerLength()
	 * @see #isHeaderTruncated()
	 * @see Packet#getHeader(int, int)
	 * @since 1.0
	 */
	public final long headerOffset() {
		return headerOffset;
	}

	public abstract boolean isFixedHeader();

	/**
	 * Convenience: offset where the next protocol layer begins.
	 */
	public long nextLayerOffset() {
		return headerOffset() + headerChainLength();
	}

	protected void onBindPacket() {}

	@Override
	public void onUnbind() {
		super.onUnbind();

		onUnbindPacket();
	}

	protected void onUnbindPacket() {}

	public final void unbindPacket() {
		onUnbindPacket();

		packet = null;
		headerOffset = 0; // Allows buffer bindings

		super.unbind();
	}

}
