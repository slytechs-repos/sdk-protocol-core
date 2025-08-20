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

import com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor;

/**
 * Interface for accessing and binding protocol headers within packet data.
 * 
 * <p>
 * {@code HeaderAccessor} provides a uniform API for checking header presence
 * and retrieving header instances from packets or descriptors. This interface
 * supports both simple and complex packet structures including tunneled
 * protocols and multiple header instances at different depths.
 * 
 * <h2>Design Philosophy</h2>
 * 
 * <p>
 * The HeaderAccessor interface follows these key principles:
 * <ol>
 * <li><strong>Zero-allocation:</strong> Headers are reusable objects bound to
 * packet data</li>
 * <li><strong>Type safety:</strong> Generic methods preserve header types</li>
 * <li><strong>Fail-fast:</strong> Methods throw exceptions for missing
 * headers</li>
 * <li><strong>Depth support:</strong> Handles tunneled protocols elegantly</li>
 * </ol>
 * 
 * <h2>Header Access Patterns</h2>
 * 
 * <h3>Pattern 1: Check-then-Get (Recommended)</h3>
 * 
 * <pre>{@code
 * // Always check before accessing to avoid exceptions
 * if (packet.hasHeader(tcpHeader)) {
 * 	packet.getHeader(tcpHeader); // Binds header to packet data
 * 	int port = tcpHeader.sourcePort();
 * 	// Process TCP packet...
 * }
 * }</pre>
 * 
 * <h3>Pattern 2: Try-Catch</h3>
 * 
 * <pre>{@code
 * // Alternative approach using exception handling
 * try {
 * 	Tcp tcp = packet.getHeader(new Tcp());
 * 	processTcpPacket(tcp);
 * } catch (HeaderNotFoundException e) {
 * 	// Not a TCP packet
 * 	processNonTcp(packet);
 * }
 * }</pre>
 * 
 * <h3>Pattern 3: Protocol ID Based</h3>
 * 
 * <pre>{@code
 * // Fast protocol detection using IDs
 * if (packet.isPresent(CoreProtocol.IPv4)) {
 * 	Header ipv4 = packet.getHeader(CoreProtocol.IPv4);
 * 	// Process IPv4 header...
 * }
 * }</pre>
 * 
 * <h2>Depth Parameter</h2>
 * 
 * <p>
 * The depth parameter handles protocols that appear multiple times in a packet:
 * <ul>
 * <li><strong>Depth 0:</strong> First (outermost) occurrence</li>
 * <li><strong>Depth 1:</strong> Second occurrence</li>
 * <li><strong>Depth N:</strong> (N+1)th occurrence</li>
 * </ul>
 * 
 * <h3>Common Depth Scenarios</h3>
 * 
 * <pre>
 * Standard Packet:
 * [Ethernet] -> [IP] -> [TCP] -> [Payload]
 *                ↑        ↑
 *            depth=0   depth=0
 * 
 * IP-in-IP Tunnel:
 * [Ethernet] -> [Outer IP] -> [Inner IP] -> [TCP]
 *                    ↑            ↑
 *                depth=0      depth=1
 * 
 * Q-in-Q VLAN:
 * [Ethernet] -> [Outer VLAN] -> [Inner VLAN] -> [IP]
 *                     ↑              ↑
 *                 depth=0        depth=1
 * </pre>
 * 
 * <h2>Implementation Requirements</h2>
 * 
 * <p>
 * Implementations must ensure:
 * <ol>
 * <li>Thread-safety for read operations</li>
 * <li>Consistent state between has/is methods and get methods</li>
 * <li>Proper exception throwing for missing headers</li>
 * <li>Efficient header lookup (typically O(1) or O(log n))</li>
 * </ol>
 * 
 * <h2>Example Implementations</h2>
 * 
 * <h3>Custom Header Accessor</h3>
 * 
 * <pre>
 * {
 * 	&#64;code
 * 	public class PacketBuffer implements HeaderAccessor {
 * 		private final Map<Integer, HeaderInfo> headers = new HashMap<>();
 * 		private final ByteBuffer data;
 * 
 * 		&#64;Override
 * 		public boolean isPresent(int id, int depth) {
 * 			HeaderInfo info = headers.get(id);
 * 			return info != null && info.hasDepth(depth);
 * 		}
 * 
 * 		&#64;Override
 * 		public Header getHeader(int id, int depth) throws HeaderNotFoundException {
 * 			HeaderInfo info = headers.get(id);
 * 			if (info == null || !info.hasDepth(depth)) {
 * 				throw new HeaderNotFoundException(
 * 						"Header " + id + " at depth " + depth + " not found");
 * 			}
 * 
 * 			// Create and bind header
 * 			Header header = HeaderFactory.create(id);
 * 			header.bind(data, info.getOffset(depth), info.getLength(depth));
 * 			return header;
 * 		}
 * 
 * 		@Override
 * 		public <T extends Header> T getHeader(T header, int depth)
 * 				throws HeaderNotFoundException {
 * 			HeaderInfo info = headers.get(header.id());
 * 			if (info == null || !info.hasDepth(depth)) {
 * 				throw new HeaderNotFoundException();
 * 			}
 * 
 * 			// Bind provided header instance
 * 			header.bind(data, info.getOffset(depth), info.getLength(depth));
 * 			return header;
 * 		}
 * 	}
 * }
 * </pre>
 * 
 * <h3>Delegating Accessor</h3>
 * 
 * <pre>
 * {
 * 	&#64;code
 * 	public class FilteredAccessor implements HeaderAccessor {
 * 		private final HeaderAccessor delegate;
 * 		private final Set<Integer> allowedProtocols;
 * 
 * 		&#64;Override
 * 		public boolean isPresent(int id, int depth) {
 * 			return allowedProtocols.contains(id) &&
 * 					delegate.isPresent(id, depth);
 * 		}
 * 
 * 		@Override
 * 		public Header getHeader(int id, int depth)
 * 				throws HeaderNotFoundException {
 * 			if (!allowedProtocols.contains(id)) {
 * 				throw new HeaderNotFoundException("Protocol filtered: " + id);
 * 			}
 * 			return delegate.getHeader(id, depth);
 * 		}
 * 	}
 * }
 * </pre>
 * 
 * @see Header
 * @see HeaderNotFoundException
 * @see PacketDescriptor
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public interface HeaderAccessor {

	/**
	 * Empty header accessor that never contains any headers.
	 * 
	 * <p>
	 * This singleton instance is useful as a null object pattern implementation for
	 * cases where no headers are available but a HeaderAccessor is required. All
	 * presence checks return {@code false} and all get methods throw
	 * {@code HeaderNotFoundException}.
	 * 
	 * <h3>Usage Example</h3>
	 * 
	 * <pre>{@code
	 * public class PacketProcessor {
	 * 	private HeaderAccessor accessor = HeaderAccessor.EMPTY;
	 * 
	 * 	public void setPacket(Packet packet) {
	 * 		this.accessor = packet != null ? packet : HeaderAccessor.EMPTY;
	 * 	}
	 * 
	 * 	public void process() {
	 * 		// Safe to use without null checks
	 * 		if (accessor.isPresent(CoreProtocol.TCP)) {
	 * 			// Will never execute for EMPTY
	 * 		}
	 * 	}
	 * }
	 * }</pre>
	 */
	HeaderAccessor EMPTY = new HeaderAccessor() {};

	/**
	 * Retrieves a header by its protocol ID at depth 0.
	 * 
	 * <p>
	 * This convenience method is equivalent to calling {@code getHeader(id, 0)} and
	 * retrieves the first (outermost) occurrence of the specified protocol.
	 * 
	 * <h3>Common Protocol IDs</h3>
	 * 
	 * <pre>{@code
	 * // Core protocol constants
	 * Header eth = accessor.getHeader(CoreProtocol.ETHERNET);
	 * Header ip4 = accessor.getHeader(CoreProtocol.IPv4);
	 * Header tcp = accessor.getHeader(CoreProtocol.TCP);
	 * Header udp = accessor.getHeader(CoreProtocol.UDP);
	 * }</pre>
	 * 
	 * @param id the protocol identifier
	 * @return the header instance bound to packet data
	 * @throws HeaderNotFoundException if the header is not present
	 * @see #getHeader(int, int)
	 * @see #isPresent(int)
	 */
	default Header getHeader(int id) throws HeaderNotFoundException {
		return getHeader(id, 0);
	}

	/**
	 * Retrieves a header by its protocol ID at the specified depth.
	 * 
	 * <p>
	 * This method creates or retrieves a header instance and binds it to the
	 * appropriate location in the packet data. The returned header can be used to
	 * access protocol-specific fields and methods.
	 * 
	 * <h3>Implementation Note</h3>
	 * <p>
	 * Implementations should create lightweight header objects that share the
	 * underlying packet data rather than copying it. Headers should be reusable
	 * across multiple packets by rebinding.
	 * 
	 * <h3>Example: Accessing Tunneled Headers</h3>
	 * 
	 * <pre>{@code
	 * // Access both outer and inner IP headers in tunnel
	 * try {
	 * 	Header outerIp = packet.getHeader(CoreProtocol.IPv4, 0);
	 * 	Header innerIp = packet.getHeader(CoreProtocol.IPv4, 1);
	 * 
	 * 	log.info("Tunnel: {} -> {}",
	 * 			outerIp.getAddress(12), // Source IP at offset 12
	 * 			outerIp.getAddress(16)); // Dest IP at offset 16
	 * } catch (HeaderNotFoundException e) {
	 * 	// Not a tunneled packet
	 * }
	 * }</pre>
	 * 
	 * @param id    the protocol identifier
	 * @param depth the occurrence depth (0 for first, 1 for second, etc.)
	 * @return the header instance bound to packet data
	 * @throws HeaderNotFoundException if the header is not present at the specified
	 *                                 depth
	 * @see #isPresent(int, int)
	 */
	default Header getHeader(int id, int depth) throws HeaderNotFoundException {
		throw new HeaderNotFoundException();
	}

	/**
	 * Binds the provided header instance to packet data at depth 0.
	 * 
	 * <p>
	 * This convenience method is equivalent to calling
	 * {@code getHeader(header, 0)}. It allows reuse of header objects across
	 * multiple packets, reducing allocation.
	 * 
	 * <h3>Header Reuse Pattern</h3>
	 * 
	 * <pre>{@code
	 * public class TcpAnalyzer {
	 * 	// Reusable header instances (allocated once)
	 * 	private final Ethernet eth = new Ethernet();
	 * 	private final Ip4 ip4 = new Ip4();
	 * 	private final Tcp tcp = new Tcp();
	 * 
	 * 	public void analyze(HeaderAccessor packet) {
	 * 		// Bind headers to current packet (no allocation)
	 * 		if (packet.hasHeader(tcp)) {
	 * 			packet.getHeader(eth);
	 * 			packet.getHeader(ip4);
	 * 			packet.getHeader(tcp);
	 * 
	 * 			// Use bound headers
	 * 			analyzeTcpFlow(eth, ip4, tcp);
	 * 		}
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * @param <T>    the specific header type
	 * @param header the header instance to bind
	 * @return the same header instance, now bound to packet data
	 * @throws HeaderNotFoundException if the header type is not present
	 * @see #getHeader(Header, int)
	 * @see #hasHeader(Header)
	 */
	default <T extends Header> T getHeader(T header) throws HeaderNotFoundException {
		return getHeader(header, 0);
	}

	/**
	 * Binds the provided header instance to packet data at the specified depth.
	 * 
	 * <p>
	 * This method enables zero-allocation header access by reusing header objects.
	 * The provided header is bound to the packet data at the location corresponding
	 * to its protocol type and the specified depth.
	 * 
	 * <h3>Type Safety</h3>
	 * <p>
	 * The generic return type ensures type safety without casting:
	 * 
	 * <pre>{@code
	 * Tcp tcp = packet.getHeader(new Tcp(), 0); // No cast needed
	 * int srcPort = tcp.sourcePort(); // Type-specific methods available
	 * }</pre>
	 * 
	 * <h3>Example: Processing VLAN Stack</h3>
	 * 
	 * <pre>{@code
	 * public class VlanProcessor {
	 * 	private final Vlan vlan = new Vlan();
	 * 
	 * 	public void processVlanStack(HeaderAccessor packet) {
	 * 		int depth = 0;
	 * 
	 * 		// Process all VLAN tags
	 * 		while (packet.hasHeader(vlan, depth)) {
	 * 			packet.getHeader(vlan, depth);
	 * 
	 * 			int vlanId = vlan.id();
	 * 			int priority = vlan.priority();
	 * 
	 * 			log.info("VLAN[{}]: ID={}, Priority={}",
	 * 					depth, vlanId, priority);
	 * 
	 * 			depth++;
	 * 		}
	 * 
	 * 		log.info("Total VLAN tags: {}", depth);
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * @param <T>    the specific header type
	 * @param header the header instance to bind
	 * @param depth  the occurrence depth (0 for first, 1 for second, etc.)
	 * @return the same header instance, now bound to packet data
	 * @throws HeaderNotFoundException if the header is not present at the specified
	 *                                 depth
	 * @see #hasHeader(Header, int)
	 */
	default <T extends Header> T getHeader(T header, int depth) throws HeaderNotFoundException {
		throw new HeaderNotFoundException();
	}

	/**
	 * Checks if the specified header type is present at depth 0.
	 * 
	 * <p>
	 * This convenience method is equivalent to calling
	 * {@code hasHeader(header, 0)}. Use this method to check header presence before
	 * calling {@code getHeader} to avoid exceptions.
	 * 
	 * <h3>Conditional Processing</h3>
	 * 
	 * <pre>{@code
	 * public void routePacket(HeaderAccessor packet) {
	 * 	Ip4 ip4 = new Ip4();
	 * 	Ip6 ip6 = new Ip6();
	 * 
	 * 	if (packet.hasHeader(ip4)) {
	 * 		routeIPv4(packet);
	 * 	} else if (packet.hasHeader(ip6)) {
	 * 		routeIPv6(packet);
	 * 	} else {
	 * 		// Non-IP packet (maybe ARP, etc.)
	 * 		handleNonIP(packet);
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * @param header the header instance to check
	 * @return {@code true} if the header type is present, {@code false} otherwise
	 * @see #hasHeader(Header, int)
	 * @see #getHeader(Header)
	 */
	default boolean hasHeader(Header header) {
		return hasHeader(header, 0);
	}

	/**
	 * Checks if the specified header type is present at the given depth.
	 * 
	 * <p>
	 * This method provides a non-throwing way to check for header presence before
	 * attempting to retrieve it. Always returns {@code false} for negative depths
	 * or depths beyond the packet structure.
	 * 
	 * <h3>Example: Tunnel Detection</h3>
	 * 
	 * <pre>{@code
	 * public class TunnelDetector {
	 * 	private final Ip4 ip4 = new Ip4();
	 * 	private final Ip6 ip6 = new Ip6();
	 * 
	 * 	public TunnelType detectTunnel(HeaderAccessor packet) {
	 * 		boolean hasOuterV4 = packet.hasHeader(ip4, 0);
	 * 		boolean hasInnerV4 = packet.hasHeader(ip4, 1);
	 * 		boolean hasOuterV6 = packet.hasHeader(ip6, 0);
	 * 		boolean hasInnerV6 = packet.hasHeader(ip6, 1);
	 * 
	 * 		if (hasOuterV4 && hasInnerV4) {
	 * 			return TunnelType.IPv4_IN_IPv4;
	 * 		} else if (hasOuterV6 && hasInnerV4) {
	 * 			return TunnelType.IPv4_IN_IPv6;
	 * 		} else if (hasOuterV4 && hasInnerV6) {
	 * 			return TunnelType.IPv6_IN_IPv4;
	 * 		} else if (hasOuterV6 && hasInnerV6) {
	 * 			return TunnelType.IPv6_IN_IPv6;
	 * 		} else {
	 * 			return TunnelType.NONE;
	 * 		}
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * @param header the header instance to check
	 * @param depth  the occurrence depth to check
	 * @return {@code true} if the header type is present at the specified depth
	 * @see #getHeader(Header, int)
	 */
	default boolean hasHeader(Header header, int depth) {
		return false;
	}

	/**
	 * Checks if a protocol is present by its ID at depth 0.
	 * 
	 * <p>
	 * This convenience method is equivalent to calling {@code isPresent(id, 0)}. It
	 * provides the fastest way to check protocol presence when you don't need a
	 * header instance.
	 * 
	 * <h3>Fast Protocol Detection</h3>
	 * 
	 * <pre>{@code
	 * public PacketType classifyPacket(HeaderAccessor packet) {
	 * 	// Fast protocol detection using IDs
	 * 	if (packet.isPresent(CoreProtocol.TCP)) {
	 * 		return PacketType.TCP;
	 * 	} else if (packet.isPresent(CoreProtocol.UDP)) {
	 * 		return PacketType.UDP;
	 * 	} else if (packet.isPresent(CoreProtocol.ICMP)) {
	 * 		return PacketType.ICMP;
	 * 	} else if (packet.isPresent(CoreProtocol.ARP)) {
	 * 		return PacketType.ARP;
	 * 	} else {
	 * 		return PacketType.OTHER;
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * @param id the protocol identifier to check
	 * @return {@code true} if the protocol is present, {@code false} otherwise
	 * @see #isPresent(int, int)
	 * @see #getHeader(int)
	 */
	default boolean isPresent(int id) {
		return isPresent(id, 0);
	}

	/**
	 * Checks if a protocol is present by its ID at the specified depth.
	 * 
	 * <p>
	 * This method provides the most efficient way to check for protocol presence
	 * when working with protocol IDs directly. It's particularly useful for
	 * filtering and routing decisions where header instances are not needed.
	 * 
	 * <h3>Performance Advantage</h3>
	 * <p>
	 * Using protocol IDs is typically faster than header-based checks:
	 * <ul>
	 * <li>No object instantiation required</li>
	 * <li>Direct bitmask or lookup table access</li>
	 * <li>Suitable for high-frequency operations</li>
	 * </ul>
	 * 
	 * <h3>Example: Multi-Protocol Statistics</h3>
	 * 
	 * <pre>{@code
	 * public class ProtocolStatistics {
	 * 	private final Map<Integer, AtomicLong> counters = new HashMap<>();
	 * 
	 * 	public void updateStatistics(HeaderAccessor packet) {
	 * 		// Check all protocols efficiently
	 * 		for (int protocolId : MONITORED_PROTOCOLS) {
	 * 			if (packet.isPresent(protocolId)) {
	 * 				counters.computeIfAbsent(protocolId,
	 * 						k -> new AtomicLong()).incrementAndGet();
	 * 			}
	 * 		}
	 * 
	 * 		// Check for tunneling
	 * 		if (packet.isPresent(CoreProtocol.IPv4, 0) &&
	 * 				packet.isPresent(CoreProtocol.IPv4, 1)) {
	 * 			tunnelCounter.incrementAndGet();
	 * 		}
	 * 	}
	 * 
	 * 	public void printStatistics() {
	 * 		counters.forEach((id, count) -> {
	 * 			String name = ProtocolRegistry.getName(id);
	 * 			System.out.printf("%s: %d packets%n", name, count.get());
	 * 		});
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * <h3>Example: Protocol Filtering</h3>
	 * 
	 * <pre>{@code
	 * public class PacketFilter {
	 * 	private final Set<Integer> allowedProtocols;
	 * 	private final int maxDepth;
	 * 
	 * 	public boolean accept(HeaderAccessor packet) {
	 * 		// Check if packet contains any allowed protocol
	 * 		for (int protocol : allowedProtocols) {
	 * 			for (int depth = 0; depth <= maxDepth; depth++) {
	 * 				if (packet.isPresent(protocol, depth)) {
	 * 					return true;
	 * 				}
	 * 			}
	 * 		}
	 * 		return false;
	 * 	}
	 * 
	 * 	public boolean acceptStrict(HeaderAccessor packet) {
	 * 		// Check if packet contains ALL required protocols
	 * 		for (int protocol : allowedProtocols) {
	 * 			if (!packet.isPresent(protocol, 0)) {
	 * 				return false;
	 * 			}
	 * 		}
	 * 		return true;
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * <h3>Implementation Guidelines</h3>
	 * <p>
	 * Implementations should optimize this method for performance:
	 * <ul>
	 * <li>Use bitmasks for common protocols (O(1) lookup)</li>
	 * <li>Implement sparse arrays for extended protocols</li>
	 * <li>Cache negative results to avoid repeated searches</li>
	 * <li>Return {@code false} immediately for invalid depths</li>
	 * </ul>
	 * 
	 * @param id    the protocol identifier to check
	 * @param depth the occurrence depth to check
	 * @return {@code true} if the protocol is present at the specified depth
	 * @see #getHeader(int, int)
	 * @see #hasHeader(Header, int)
	 */
	default boolean isPresent(int id, int depth) {
		return false;
	}
}