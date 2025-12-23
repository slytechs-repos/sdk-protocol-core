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
package com.slytechs.jnet.protocol.api;

import java.lang.foreign.MemoryLayout;

import com.slytechs.jnet.core.api.memory.BindableView;
import com.slytechs.jnet.core.api.memory.ByteBuf;

/**
 * Base class for protocol headers with integrated variable-length options.
 * 
 * <p>
 * VariableHeader represents protocols that can contain optional fields
 * integrated within the header structure itself. The total header length varies
 * based on the presence of these options, but they remain part of the single
 * header rather than being separate chained headers.
 * </p>
 * 
 * <h2>Design Principles</h2>
 * <ul>
 * <li><strong>Zero-allocation:</strong> All structures are pre-allocated and
 * reused across packets</li>
 * <li><strong>Lazy decoding:</strong> Options are parsed only when first
 * accessed</li>
 * <li><strong>High performance:</strong> Designed for 100M+ pps processing
 * rates</li>
 * <li><strong>Memory efficiency:</strong> Direct memory binding without
 * copies</li>
 * </ul>
 * 
 * <h2>Options Model</h2>
 * <p>
 * Options are integrated components that:
 * </p>
 * <ul>
 * <li>Reside within the header's total length boundary</li>
 * <li>Are included in the protocol's length field (e.g., TCP Data Offset)</li>
 * <li>Follow the base header fields directly</li>
 * <li>May require padding to maintain alignment</li>
 * </ul>
 * 
 * <h2>Memory Layout</h2>
 * 
 * <pre>
 * ┌────────────────────┬─────────────────────┐
 * │   Base Header      │      Options        │ → Payload
 * │   (20B for TCP)    │     (0-40B)         │
 * └────────────────────┴─────────────────────┘
 *         ↑                     ↑
 *     baseLength()        optionsLength()
 * └─────────── totalLength() ───────────┘
 * </pre>
 * 
 * <h2>Usage Pattern</h2>
 * <p>
 * The recommended usage pattern pre-allocates header and option objects for
 * reuse:
 * </p>
 * 
 * <pre>{@code
 * // Pre-allocate objects outside the loop
 * Tcp tcp = new Tcp();
 * TcpMss mss = new TcpMss();
 * TcpWindowScale ws = new TcpWindowScale();
 * 
 * // Process packets with zero allocation
 * while (running) {
 * 	Packet packet = queue.take();
 * 
 * 	if (packet.hasHeader(tcp)) {
 * 		// Check and bind MSS option
 * 		if (tcp.hasOption(mss)) {
 * 			tcp.bindOption(mss);
 * 			System.out.println("MSS: " + mss.value());
 * 		}
 * 
 * 		// Or use convenience method
 * 		if (tcp.getOption(ws) != null) {
 * 			System.out.println("Window Scale: " + ws.shift());
 * 		}
 * 
 * 		// Iterate over all options
 * 		for (OptionInfo info : tcp.options()) {
 * 			System.out.println("Option " + info.getId() +
 * 					" at offset " + info.getOffset());
 * 		}
 * 	}
 * }
 * }</pre>
 * 
 * <h2>Common Examples</h2>
 * <ul>
 * <li><strong>TCP:</strong> 20-byte base + up to 40 bytes of options</li>
 * <li><strong>IPv4:</strong> 20-byte base + up to 40 bytes of options</li>
 * </ul>
 * 
 * <h2>Thread Safety</h2>
 * <p>
 * VariableHeader instances are not thread-safe. Each thread should maintain its
 * own set of pre-allocated header and option objects for packet processing.
 * </p>
 * 
 * @param <O> the base type for options within this header
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 * @see HeaderOption
 * @see Options
 * @see Tcp
 * @see Ip4
 */
public non-sealed abstract class VariableHeader<T extends HeaderOptions<?>> extends Header {

	/**
	 * Pre-allocated Options codec for efficient option handling. This instance is
	 * reused across all packet processing.
	 */
	private long extendedLength;

	/**
	 * Constructs a variable header with the specified protocol ID and layout.
	 * 
	 * <p>
	 * This constructor establishes the permanent association between the header and
	 * its options container. The options instance will be reused for all packets
	 * processed by this header.
	 * </p>
	 * 
	 * @param id             the protocol identifier
	 * @param layout         the memory layout for the base header
	 * @param optionsFactory the pre-allocated options container
	 * @throws NullPointerException if layout or options is null
	 */
	protected VariableHeader(int id, MemoryLayout layout) {
		super(id, layout);
	}

	/**
	 * Binds this header to a packet's memory region.
	 * 
	 * <p>
	 * This method is called during packet dissection to bind the header to its
	 * memory region within the packet. It prepares the options container for lazy
	 * decoding with the packet context.
	 * </p>
	 * 
	 * <p>
	 * The binding process:
	 * </p>
	 * <ol>
	 * <li>Prepares the options container with packet data and extended length</li>
	 * <li>Calls the superclass binding to establish memory mapping</li>
	 * <li>Options remain undecoded until first access (lazy decoding)</li>
	 * </ol>
	 * 
	 * @param packet         the packet memory buffer
	 * @param id     the protocol identifier (must match this header's ID)
	 * @param innerDepth     the depth level for tunneled protocols
	 * @param offset         the offset of this header within the packet
	 * @param extendedLength the total header length including options
	 * @return true if binding was successful
	 * @see Options#prepareForBinding(ByteBuf, long, long, long)
	 */
	@Override
	public final boolean bindHeader(
			BindableView packet,
			int protocolId,
			int innerDepth,
			long offset,
			long extendedLength) {

		this.extendedLength = extendedLength;

		return super.bindHeader(packet, protocolId, innerDepth, offset, extendedLength);
	}

	/**
	 * Returns the extended length of this header.
	 * 
	 * <p>
	 * For variable headers, the extended length equals the total length since
	 * options are integrated within the header structure rather than being separate
	 * extension headers.
	 * </p>
	 * 
	 * @return the total header length in bytes (same as totalLength())
	 * 
	 * @see #headerLength()
	 */
	@Override
	public final long headerChainLength() {
		return extendedLength;
	}

	/**
	 * Returns the total length of this header including options.
	 * 
	 * <p>
	 * For variable headers, this is the sum of the base header length and the
	 * options length. This value typically corresponds to a length field within the
	 * protocol header (e.g., IHL*4 for IPv4, Data Offset*4 for TCP).
	 * </p>
	 * 
	 * <h3>Calculation:</h3>
	 * 
	 * <pre>
	 * totalLength = baseLength + optionsLength
	 * 
	 * Examples:
	 * - TCP with no options: 20 bytes
	 * - TCP with MSS option: 24 bytes
	 * - TCP with full options: up to 60 bytes
	 * </pre>
	 * 
	 * @return the total header length including options in bytes
	 * 
	 * @see #headerMinLength()
	 * @see #optionsLength()
	 * @see #headerChainLength()
	 */
	@Override
	public long headerLength() {
		return extendedLength;
	}

	/**
	 * Indicates that this is not a fixed-length header.
	 * 
	 * @return always returns false for variable headers
	 */
	@Override
	public final boolean isFixedHeader() {
		return false;
	}

	/**
	 * Returns an iterator over all present options.
	 * 
	 * <p>
	 * This iterator provides access to option metadata for all options in the
	 * header. The iteration order follows the order of options in the packet.
	 * </p>
	 * 
	 * <h3>Usage Example:</h3>
	 * 
	 * <pre>{@code
	 * for (OptionInfo info : tcp.options()) {
	 * 	System.out.printf("Option ID=%d, Offset=%d, Length=%d%n",
	 * 			info.getId(), info.getOffset(), info.getLength());
	 * 
	 * 	// Process specific options
	 * 	switch (info.getId()) {
	 * 	case TCP_OPTION_MSS:
	 * 		// Process MSS option
	 * 		break;
	 * 	case TCP_OPTION_TIMESTAMP:
	 * 		// Process timestamp
	 * 		break;
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * <h3>Performance Note:</h3>
	 * <p>
	 * The iterator is efficient as it traverses a pre-built chain of options rather
	 * than scanning the entire options area. First call triggers lazy decoding.
	 * </p>
	 * 
	 * @return iterator of option information
	 * 
	 * @see OptionInfo
	 * @see #optionCount()
	 */
	public abstract T options();

	/**
	 * Returns the total length of the options section in bytes.
	 * 
	 * <p>
	 * This includes all options and any padding between them. The options length is
	 * calculated as: {@code totalLength() - baseLength()}
	 * </p>
	 * 
	 * <h3>Memory Layout:</h3>
	 * 
	 * <pre>
	 * [Base Header][←── Options Length ──→][Payload]
	 *              ↑                      ↑
	 *          baseLength()          totalLength()
	 * </pre>
	 * 
	 * @return options length in bytes, or 0 if no options
	 * 
	 * @see #headerMinLength()
	 * @see #headerLength()
	 */
	public long optionsLength() {
		return headerLength() - headerMinLength();
	}

	public abstract long optionsOffset();

	/**
	 * @return
	 */
	public abstract boolean hasOptions();
}