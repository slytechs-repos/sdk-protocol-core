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


/**
 * Base class for protocol headers that support chained extension headers.
 * 
 * <p>
 * ExtensibleHeader represents protocols that can be followed by a chain of
 * extension headers, where each extension is a separate protocol header that
 * extends the functionality of the base protocol. The primary example is IPv6,
 * which uses extension headers for routing, fragmentation, authentication, and
 * other features.
 * </p>
 * 
 * <h2>Design Principles</h2>
 * <ul>
 * <li><strong>Zero-allocation:</strong> All structures are pre-allocated and
 * reused across packets</li>
 * <li><strong>Lazy decoding:</strong> Extensions are parsed only when first
 * accessed</li>
 * <li><strong>Chain-based:</strong> Extensions form a linked chain following
 * the base header</li>
 * <li><strong>Independent headers:</strong> Each extension is a separate
 * protocol entity</li>
 * </ul>
 * 
 * <h2>Extension Model</h2>
 * <p>
 * Extensions are separate protocol headers that:
 * </p>
 * <ul>
 * <li>Follow the base header in a chained sequence</li>
 * <li>Have their own protocol IDs and structures</li>
 * <li>Are not included in the base header's length field</li>
 * <li>May themselves contain options or be extensible</li>
 * </ul>
 * 
 * <h2>Memory Layout</h2>
 * 
 * <pre>
 * ┌────────────┬────────────┬────────────┬────────────┐
 * │ Base Header│ Extension 1│ Extension 2│   Payload  │
 * │  (40B IPv6)│  (Variable)│  (Variable)│            │
 * └────────────┴────────────┴────────────┴────────────┘
 *       ↑            ↑                          ↑
 *  baseLength()  Extension Chain         Upper Protocol
 * └────────── extendedLength() ──────────┘
 * </pre>
 * 
 * <h2>Usage Pattern</h2>
 * <p>
 * The recommended usage pattern pre-allocates header and extension objects for
 * reuse:
 * </p>
 * 
 * <pre>{@code
 * // Pre-allocate objects outside the loop
 * Ip6 ipv6 = new Ip6();
 * Ip6HopByHop hopByHop = new Ip6HopByHop();
 * Ip6Fragment fragment = new Ip6Fragment();
 * Ip6Routing routing = new Ip6Routing();
 * 
 * // Process packets with zero allocation
 * while (running) {
 * 	Packet packet = queue.take();
 * 
 * 	if (packet.hasHeader(ipv6)) {
 * 		// Check for hop-by-hop extension
 * 		if (ipv6.hasExtension(hopByHop)) {
 * 			ipv6.getExtension(hopByHop);
 * 			System.out.println("Hop limit: " + hopByHop.hopLimit());
 * 		}
 * 
 * 		// Check for fragmentation
 * 		try {
 * 			ipv6.getExtension(fragment);
 * 			System.out.println("Fragment offset: " + fragment.offset());
 * 		} catch (HeaderNotFoundException e) {
 * 			// No fragment extension
 * 		}
 * 
 * 		// Iterate over all extensions
 * 		for (ExtensionInfo info : ipv6.extensions()) {
 * 			System.out.println("Extension " + info.getId() +
 * 					" at offset " + info.getOffset());
 * 		}
 * 	}
 * }
 * }</pre>
 * 
 * <h2>IPv6 Extension Headers</h2>
 * <p>
 * Common IPv6 extension headers include:
 * </p>
 * <ul>
 * <li><strong>Hop-by-Hop Options (0):</strong> Options for every hop</li>
 * <li><strong>Routing (43):</strong> Source routing information</li>
 * <li><strong>Fragment (44):</strong> Fragmentation and reassembly</li>
 * <li><strong>Authentication (51):</strong> IPsec authentication</li>
 * <li><strong>Encapsulating Security Payload (50):</strong> IPsec
 * encryption</li>
 * <li><strong>Destination Options (60):</strong> Options for destination
 * only</li>
 * </ul>
 * 
 * <h2>Extension Chain Processing</h2>
 * <p>
 * Extensions form a chain where each header's Next Header field points to the
 * following protocol. The chain terminates when reaching an upper-layer
 * protocol (TCP, UDP, etc.) or the No Next Header value (59).
 * </p>
 * 
 * <h2>Thread Safety</h2>
 * <p>
 * ExtensibleHeader instances are not thread-safe. Each thread should maintain
 * its own set of pre-allocated header and extension objects for packet
 * processing.
 * </p>
 * 
 * @param <E> the base type for extensions of this header
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 * @see HeaderExtension
 * @see Options
 * @see Ip6
 */
public non-sealed abstract class ExtensibleHeader<T extends HeaderExtensions<?>> extends Header {

	/**
	 * Pre-allocated Options codec for efficient extension handling. Reused to track
	 * extension headers as they share similar chain structure.
	 */
	private long extendedLength;

	/**
	 * Constructs an extensible header with the specified protocol ID and layout.
	 * 
	 * <p>
	 * This constructor establishes the base header structure and prepares the
	 * extensions container for tracking chained extension headers.
	 * </p>
	 * 
	 * @param id             the protocol identifier
	 * @param layout         the memory layout for the base header
	 * @param optionsFactory the pre-allocated extensions tracker
	 * @throws NullPointerException if layout or extensions is null
	 */
	protected ExtensibleHeader(int id, MemoryLayout layout) {
		super(id, layout);
	}

	/**
	 * Returns an iterator over all present extension headers.
	 * 
	 * <p>
	 * This iterator provides access to extension metadata for all extensions in the
	 * chain. The iteration order follows the chain order in the packet.
	 * </p>
	 * 
	 * <h3>Usage Example:</h3>
	 * 
	 * <pre>{@code
	 * for (ExtensionInfo info : ipv6.extensions()) {
	 * 	System.out.printf("Extension ID=%d, Offset=%d, Length=%d%n",
	 * 			info.getId(), info.getOffset(), info.getLength());
	 * 
	 * 	// Process specific extensions
	 * 	switch (info.getId()) {
	 * 	case IP6_HOPBYHOP:
	 * 		// Process hop-by-hop options
	 * 		break;
	 * 	case IP6_ROUTING:
	 * 		// Process routing header
	 * 		break;
	 * 	case IP6_FRAGMENT:
	 * 		// Process fragmentation
	 * 		break;
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * <h3>Performance Note:</h3>
	 * <p>
	 * The iterator is efficient as it traverses a pre-built chain of extensions
	 * rather than scanning the entire extension area. First call triggers lazy
	 * decoding.
	 * </p>
	 * 
	 * @return iterator of extension information
	 * 
	 * @see OptionInfo
	 * @see #extensionCount()
	 */
	public abstract T extensions();

	/**
	 * Returns the combined length of all extension headers in bytes.
	 * 
	 * <p>
	 * This includes all extension headers in the chain but excludes the base
	 * header. The extensions length is calculated as:
	 * {@code extendedLength() - baseLength()}
	 * </p>
	 * 
	 * <h3>Memory Layout:</h3>
	 * 
	 * <pre>
	 * [Base Header][←── Extensions Length ──→][Upper Protocol]
	 *       ↑                                        ↑
	 *  baseLength()                          extendedLength()
	 * </pre>
	 * 
	 * <h3>Performance Impact:</h3>
	 * <p>
	 * Large extension chains can impact packet processing performance. This method
	 * helps identify packets with significant extension overhead.
	 * </p>
	 * 
	 * @return total length of all extensions in bytes, or 0 if no extensions
	 * 
	 * @see #headerMinLength()
	 * @see #headerChainLength()
	 */
	public abstract long extensionsLength();
	
	public abstract long extensionsOffset();

	/**
	 * Checks if this header has any extension headers.
	 * 
	 * <p>
	 * This method triggers lazy decoding on first access and returns true if at
	 * least one extension header follows the base header.
	 * </p>
	 * 
	 * <h3>Common Use Cases:</h3>
	 * <ul>
	 * <li>Determining if IPv6 packet has extension headers</li>
	 * <li>Optimizing packet processing for simple vs. complex headers</li>
	 * <li>Calculating total protocol overhead</li>
	 * <li>Security analysis of extension header chains</li>
	 * </ul>
	 * 
	 * @return true if extension headers are present
	 * 
	 * @see #extensionCount()
	 * @see #extensionsLength()
	 */
	public boolean hasExtensions() {
		return extensionsLength() > 0;
	}

	/**
	 * Returns the extended length including all extension headers.
	 * 
	 * <p>
	 * The extended length represents the full extent from the start of the base
	 * header to the beginning of the upper-layer protocol. This spans the entire
	 * extension header chain.
	 * </p>
	 * 
	 * <h3>Calculation:</h3>
	 * 
	 * <pre>
	 * extendedLength = baseLength + extensionsLength
	 * 
	 * Example for IPv6 with extensions:
	 * - Base IPv6: 40 bytes
	 * - Hop-by-Hop: 8 bytes
	 * - Routing: 24 bytes
	 * - Fragment: 8 bytes
	 * = Extended: 80 bytes total
	 * </pre>
	 * 
	 * <h3>Use Cases:</h3>
	 * <ul>
	 * <li>Skipping to upper-layer protocol</li>
	 * <li>Calculating total protocol overhead</li>
	 * <li>Buffer allocation for header processing</li>
	 * </ul>
	 * 
	 * @return the base header plus all extensions in bytes
	 * 
	 * @see #headerMinLength()
	 * @see #headerLength()
	 * @see #extensionsLength()
	 */
	@Override
	public long headerChainLength() {
		return extendedLength;
	}

	/**
	 * Indicates that this is not a fixed-length header.
	 * 
	 * @return always returns false for extensible headers
	 */
	@Override
	public final boolean isFixedHeader() {
		return false;
	}

}