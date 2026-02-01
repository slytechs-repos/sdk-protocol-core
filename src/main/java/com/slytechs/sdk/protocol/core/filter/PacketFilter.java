/*
 * Copyright 2005-2026 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.protocol.core.filter;

import com.slytechs.sdk.protocol.core.filter.EthernetFilter.EthernetDsl;
import com.slytechs.sdk.protocol.core.filter.Ip4Filter.Ip4Dsl;
import com.slytechs.sdk.protocol.core.filter.Ip6Filter.Ip6Dsl;
import com.slytechs.sdk.protocol.core.filter.IpSecFilter.IpSecDsl;
import com.slytechs.sdk.protocol.core.filter.MplsFilter.MplsDsl;
import com.slytechs.sdk.protocol.core.filter.TcpFilter.TcpDsl;
import com.slytechs.sdk.protocol.core.filter.UdpFilter.UdpDsl;
import com.slytechs.sdk.protocol.core.filter.VlanFilter.VlanDsl;

/**
 * Entry-point static factory for creating type-safe, backend-agnostic packet
 * filter expressions.
 * <p>
 * {@code PacketFilter} provides convenience static methods that start a new
 * filter chain by returning an empty or pre-scoped {@link PacketDsl}. All
 * subsequent method calls on the returned {@code PacketDsl} are combined
 * with logical AND.
 * </p>
 * <p>
 * The resulting {@code PacketDsl} is completely independent of any
 * capture/forwarding backend and can be compiled to multiple targets (BPF,
 * rte_flow, NTPL, eBPF, etc.) using the appropriate {@link Emitter}
 * implementation.
 * </p>
 * <p>
 * All methods that accept numeric values (ports, ranges, lengths) perform eager
 * validation and throw {@link FilterException} on invalid input to catch
 * configuration errors early.
 * </p>
 *
 * <h2>Usage Examples</h2>
 *
 * {@snippet lang = java :
 * // Start with IPv4 + TCP port 443 (HTTPS)
 * PacketDsl https = PacketFilter
 * 		.ip4()
 * 		.tcp(t -> t.dstPort(443));
 *
 * // VLAN 100 + source subnet + UDP port range
 * PacketDsl internalMonitoring = PacketFilter
 * 		.vlan(v -> v.vid(100))
 * 		.srcNet("192.168.100.0/24")
 * 		.udp()
 * 		.portRange(40000, 50000);
 *
 * // Logical OR across protocols
 * PacketDsl dnsTraffic = PacketFilter
 * 		.anyOf(
 * 				PacketFilter.udp().port(53),
 * 				PacketFilter.tcp().port(53));
 *
 * // Compile to backend (example)
 * // String bpf = new BpfFilterBuilder().build(dnsTraffic).toExpression();
 * 
 * * // Capture all packets (required for NTPL backends)
 * PacketDsl captureAll = PacketFilter.all();
 *
 * // Check if compiled filter is catch-all
 * PacketFilter filter = new BpfFilterBuilder().build(captureAll);
 * filter.isCatchAll(); // true
 * }
 * 
 *
 * @see PacketDsl the chainable filter interface
 * @see Emitter common contract for backend-specific compilation
 * @see FilterException thrown on invalid filter parameters
 */
public interface PacketFilter {

	/**
	 * The protocol keyword used internally to represent an unconditional match-all
	 * filter.
	 * <p>
	 * This constant is emitted by the {@link #ALL} filter and recognized by backend
	 * builders to determine catch-all semantics. It is also used by
	 * {@link #isCatchAll()} for expression comparison.
	 * </p>
	 *
	 * @see #ALL
	 * @see #isCatchAll()
	 */
	String KEYWORD_ALL = "all";

	/**
	 * Predefined filter that matches all packets without any conditions.
	 * <p>
	 * This constant is recognized by backend builders during compilation. Backends
	 * that require an explicit "accept all" directive (e.g. Napatech NTPL) emit the
	 * appropriate native command. Backends where no filter means capture-all (e.g.
	 * libpcap, DPDK) return {@code null} from their binary compilation methods.
	 * </p>
	 * <p>
	 * <b>Important:</b> {@code ALL} must not be combined with other filters.
	 * Passing it inside {@link PacketDsl#anyOf(PacketDsl...)} or chaining
	 * additional conditions after it will throw {@link FilterException}.
	 * </p>
	 *
	 * @see #all()
	 * @see #isCatchAll()
	 */
	PacketDsl ALL = _ -> new CatchAllBuilder();

	/**
	 * Starts a filter chain that matches packets containing an AH (Authentication
	 * Header) header.
	 *
	 * @return a {@link PacketDsl} scoped to AH presence
	 * @see #ah(HeaderOperator)
	 */
	static PacketDsl ah() {
		return of().ah();
	}

	/**
	 * Starts a filter chain that matches AH packets and applies additional
	 * AH-specific conditions.
	 *
	 * @param header lambda/operator that configures AH fields (SPI, sequence
	 *               number)
	 * @return a {@link PacketDsl} combining AH scope with the given conditions
	 */
	static PacketDsl ah(HeaderOperator<IpSecDsl> header) {
		return of().ah(header);
	}

	/**
	 * Returns a filter that matches all packets.
	 * <p>
	 * Equivalent to referencing {@link #ALL} directly. Provided as a method for
	 * consistency with other static factories on this interface.
	 * </p>
	 *
	 * {@snippet :
	 * // Explicit capture-all (required for NTPL backends)
	 * net.capture("main", port)
	 * 		.filter(PacketFilter.all())
	 * 		.apply();
	 * }
	 *
	 * @return the {@link #ALL} catch-all filter
	 * @see #ALL
	 * @see #isCatchAll()
	 */
	static PacketDsl all() {
		return ALL;
	}

	// ──────────────────────────────────────────────────────────────────────────
	// Logical OR combinators (convenience entry points)
	// ──────────────────────────────────────────────────────────────────────────

	/**
	 * Creates a filter that matches if <strong>any</strong> of the provided header
	 * filters match.
	 *
	 * @param alternatives one or more header-specific filters (logical OR)
	 * @return a new {@link PacketDsl} representing the OR group
	 * @throws FilterException thrown if PacketFilter.ALL is used inside
	 */
	static PacketDsl anyOf(HeaderDsl... alternatives) {
		return of().anyOf(alternatives);
	}

	/**
	 * Creates a filter that matches if <strong>any</strong> of the provided
	 * protocol filters match.
	 *
	 * @param alternatives one or more protocol-level filters (logical OR)
	 * @return a new {@link PacketDsl} representing the OR group
	 * @throws FilterException if any alternative is {@link PacketFilter#ALL}, which
	 *                         cannot be combined with other filters
	 */
	static PacketDsl anyOf(PacketDsl... alternatives) throws FilterException {
		for (var alt : alternatives)
			if (alt == PacketFilter.ALL)
				throw new FilterException("PacketFilter.ALL cannot be used inside anyOf()");

		return of().anyOf(alternatives);
	}

	// ──────────────────────────────────────────────────────────────────────────
	// Protocol entry points (start chain with a specific protocol)
	// ──────────────────────────────────────────────────────────────────────────

	/**
	 * Starts a filter that matches broadcast packets.
	 *
	 * @return a {@link PacketDsl} with broadcast match
	 */
	static PacketDsl broadcast() {
		return of().broadcast();
	}

	/**
	 * Starts a filter that matches packets where the destination IP equals the
	 * given address.
	 *
	 * @param ip IPv4 or IPv6 address string
	 * @return a {@link PacketDsl} with destination host match
	 * @throws FilterException if the IP string is malformed
	 */
	static PacketDsl dstHost(String ip) {
		return of().dstHost(ip);
	}

	/**
	 * Starts a filter that matches packets where the destination IP is within the
	 * given subnet.
	 *
	 * @param cidr CIDR notation
	 * @return a {@link PacketDsl} with destination network match
	 * @throws FilterException if cidr is malformed or invalid
	 */
	static PacketDsl dstNet(String cidr) {
		return of().dstNet(cidr);
	}

	/**
	 * Starts a filter chain that matches packets containing an ESP (Encapsulating
	 * Security Payload) header.
	 *
	 * @return a {@link PacketDsl} scoped to ESP presence
	 * @see #esp(HeaderOperator)
	 */
	static PacketDsl esp() {
		return of().esp();
	}

	/**
	 * Starts a filter chain that matches ESP packets and applies additional
	 * ESP-specific conditions.
	 *
	 * @param header lambda/operator that configures ESP fields (SPI, sequence
	 *               number)
	 * @return a {@link PacketDsl} combining ESP scope with the given
	 *         conditions
	 */
	static PacketDsl esp(HeaderOperator<IpSecDsl> header) {
		return of().esp(header);
	}

	/**
	 * Starts a filter chain scoped to the Ethernet header (base layer).
	 *
	 * @return a {@link PacketDsl} ready for Ethernet-specific conditions
	 * @see #ethernet(HeaderOperator)
	 */
	static PacketDsl ethernet() {
		return of().ethernet();
	}

	/**
	 * Starts a filter chain that matches Ethernet frames and applies additional
	 * Ethernet conditions.
	 *
	 * @param header lambda/operator that configures Ethernet fields (MAC addresses,
	 *               EtherType)
	 * @return a {@link PacketDsl} combining Ethernet scope with the given
	 *         conditions
	 */
	static PacketDsl ethernet(HeaderOperator<EthernetDsl> header) {
		return of().ethernet(header);
	}

	/**
	 * Starts a filter that matches packets where source or destination IP equals
	 * the given address.
	 *
	 * @param ip IPv4 or IPv6 address string (e.g. "192.168.1.1", "2001:db8::1")
	 * @return a {@link PacketDsl} with host match
	 * @throws FilterException if the IP string is malformed
	 */
	static PacketDsl host(String ip) {
		return of().host(ip);
	}

	/**
	 * Starts a filter chain that matches IPv4 packets.
	 *
	 * @return a {@link PacketDsl} scoped to IPv4
	 * @see #ip4(HeaderOperator)
	 */
	static PacketDsl ip4() {
		return of().ip4();
	}

	/**
	 * Starts a filter chain that matches IPv4 packets and applies additional IPv4
	 * header conditions.
	 *
	 * @param header lambda/operator that configures IPv4 fields (addresses,
	 *               protocol, TTL, etc.)
	 * @return a {@link PacketDsl} combining IPv4 scope with the given
	 *         conditions
	 */
	static PacketDsl ip4(HeaderOperator<Ip4Dsl> header) {
		return of().ip4(header);
	}

	/**
	 * Starts a filter chain that matches IPv6 packets.
	 *
	 * @return a {@link PacketDsl} scoped to IPv6
	 * @see #ip6(HeaderOperator)
	 */
	static PacketDsl ip6() {
		return of().ip6();
	}

	/**
	 * Starts a filter chain that matches IPv6 packets and applies additional IPv6
	 * header conditions.
	 *
	 * @param header lambda/operator that configures IPv6 fields (addresses, Next
	 *               Header, Hop Limit, etc.)
	 * @return a {@link PacketDsl} combining IPv6 scope with the given
	 *         conditions
	 */
	static PacketDsl ip6(HeaderOperator<Ip6Dsl> header) {
		return of().ip6(header);
	}

	/**
	 * Starts a filter that matches packets whose length is greater than the given
	 * value.
	 *
	 * @param len minimum length (exclusive)
	 * @return a {@link PacketDsl} with length > condition
	 */
	static PacketDsl lengthGreater(int len) {
		return of().lengthGreater(len);
	}

	/**
	 * Starts a filter that matches packets whose length is less than the given
	 * value.
	 *
	 * @param len maximum length (exclusive)
	 * @return a {@link PacketDsl} with length < condition
	 */
	static PacketDsl lengthLess(int len) {
		return of().lengthLess(len);
	}

	/**
	 * Starts a filter chain that matches packets with an MPLS label stack.
	 *
	 * @return a {@link PacketDsl} scoped to MPLS
	 * @see #mpls(HeaderOperator)
	 */
	static PacketDsl mpls() {
		return of().mpls();
	}

	/**
	 * Starts a filter chain that matches MPLS packets and applies additional MPLS
	 * label entry conditions.
	 *
	 * @param header lambda/operator that configures MPLS fields (label, TC, BOS,
	 *               TTL)
	 * @return a {@link PacketDsl} combining MPLS scope with the given
	 *         conditions
	 */
	static PacketDsl mpls(HeaderOperator<MplsDsl> header) {
		return of().mpls(header);
	}

	/**
	 * Starts a filter that matches multicast packets.
	 *
	 * @return a {@link PacketDsl} with multicast match
	 */
	static PacketDsl multicast() {
		return of().multicast();
	}

	/**
	 * Starts a filter that matches packets where source or destination IP is within
	 * the given subnet.
	 *
	 * @param cidr CIDR notation (e.g. "192.168.1.0/24", "2001:db8::/64")
	 * @return a {@link PacketDsl} with network match
	 * @throws FilterException if cidr is malformed or invalid
	 */
	static PacketDsl net(String cidr) {
		return of().net(cidr);
	}

	// ──────────────────────────────────────────────────────────────────────────
	// Network primitives (host, subnet, port) — convenience entry points
	// ──────────────────────────────────────────────────────────────────────────

	/**
	 * Returns an empty (identity) filter that matches all packets.
	 * <p>
	 * This is the starting point for building complex filters via chaining.
	 * </p>
	 *
	 * @return an empty {@link PacketDsl} ready for chaining
	 */
	static PacketDsl of() {
		return b -> b;
	}

	/**
	 * Starts a filter that matches packets where source or destination transport
	 * port equals the given value.
	 *
	 * @param port port number (must be 0–65535)
	 * @return a {@link PacketDsl} with port match (src OR dst)
	 * @throws FilterException if port is not in the range 0–65535
	 */
	static PacketDsl port(int port) throws FilterException {
		if (port < 0 || port > 65535) {
			throw new FilterException("Port must be 0-65535, got: " + port);
		}
		return of().port(port);
	}

	/**
	 * Starts a filter that matches packets where either source or destination port
	 * is within the given range.
	 *
	 * @param start inclusive lower bound (0–65535)
	 * @param end   inclusive upper bound (0–65535)
	 * @return a {@link PacketDsl} with port range match (src OR dst)
	 * @throws FilterException if start or end is out of range or start > end
	 */
	static PacketDsl portRange(int start, int end) throws FilterException {
		if (start < 0 || start > 65535) {
			throw new FilterException("Port range start must be 0-65535, got: " + start);
		}
		if (end < 0 || end > 65535) {
			throw new FilterException("Port range end must be 0-65535, got: " + end);
		}
		if (start > end) {
			throw new FilterException("Port range start (" + start + ") must not exceed end (" + end + ")");
		}
		return of().portRange(start, end);
	}

	/**
	 * Starts a filter that matches packets where the source IP equals the given
	 * address.
	 *
	 * @param ip IPv4 or IPv6 address string
	 * @return a {@link PacketDsl} with source host match
	 * @throws FilterException if the IP string is malformed
	 */
	static PacketDsl srcHost(String ip) {
		return of().srcHost(ip);
	}

	/**
	 * Starts a filter that matches packets where the source IP is within the given
	 * subnet.
	 *
	 * @param cidr CIDR notation
	 * @return a {@link PacketDsl} with source network match
	 * @throws FilterException if cidr is malformed or invalid
	 */
	static PacketDsl srcNet(String cidr) {
		return of().srcNet(cidr);
	}

	/**
	 * Starts a filter chain that matches TCP packets.
	 *
	 * @return a {@link PacketDsl} scoped to TCP
	 * @see #tcp(HeaderOperator)
	 */
	static PacketDsl tcp() {
		return of().tcp();
	}

	/**
	 * Starts a filter chain that matches TCP packets and applies additional TCP
	 * header conditions.
	 *
	 * @param header lambda/operator that configures TCP fields (ports, flags, etc.)
	 * @return a {@link PacketDsl} combining TCP scope with the given
	 *         conditions
	 */
	static PacketDsl tcp(HeaderOperator<TcpDsl> header) {
		return of().tcp(header);
	}

	/**
	 * Starts a filter chain that matches UDP packets.
	 *
	 * @return a {@link PacketDsl} scoped to UDP
	 * @see #udp(HeaderOperator)
	 */
	static PacketDsl udp() {
		return of().udp();
	}

	// ──────────────────────────────────────────────────────────────────────────
	// Packet metadata entry points
	// ──────────────────────────────────────────────────────────────────────────

	/**
	 * Starts a filter chain that matches UDP packets and applies additional UDP
	 * header conditions.
	 *
	 * @param header lambda/operator that configures UDP fields (ports)
	 * @return a {@link PacketDsl} combining UDP scope with the given
	 *         conditions
	 */
	static PacketDsl udp(HeaderOperator<UdpDsl> header) {
		return of().udp(header);
	}

	/**
	 * Starts a filter chain that matches packets with a VLAN tag (802.1Q).
	 *
	 * @return a {@link PacketDsl} scoped to VLAN
	 * @see #vlan(HeaderOperator)
	 */
	static PacketDsl vlan() {
		return of().vlan();
	}

	/**
	 * Starts a filter chain that matches VLAN-tagged packets and applies additional
	 * VLAN conditions.
	 *
	 * @param header lambda/operator that configures VLAN fields (VID, PCP, DEI,
	 *               TPID)
	 * @return a {@link PacketDsl} combining VLAN scope with the given
	 *         conditions
	 */
	static PacketDsl vlan(HeaderOperator<VlanDsl> header) {
		return of().vlan(header);
	}

	/**
	 * Returns {@code true} if this compiled filter represents an unconditional
	 * match-all filter.
	 * <p>
	 * Backend-specific compiled filters and capture pipelines can use this method
	 * to skip native filter installation when no filtering is needed. The check is
	 * based on the compiled expression content, not reference identity, so it works
	 * correctly regardless of which builder produced the filter.
	 * </p>
	 *
	 * {@snippet :
	 * PacketFilter filter = builder.build(dsl);
	 *
	 * if (!filter.isCatchAll()) {
	 * 	BpFilter bpf = ((PcapPacketFilter) filter).toBpfProgram();
	 * 	pcap.setFilter(bpf);
	 * }
	 * // else: no native filter needed, capture everything
	 * }
	 *
	 * @return {@code true} if this filter matches all packets unconditionally
	 * @see #ALL
	 */
	default boolean isCatchAll() {
		return KEYWORD_ALL.equalsIgnoreCase(toExpression().trim());
	}

	/**
	 * Converts the filter expression to a human-readable string (for debugging or
	 * logging).
	 * <p>
	 * The exact format depends on the backend that compiled the filter.
	 * </p>
	 *
	 * @return string representation of the filter (backend-dependent)
	 */
	String toExpression();
}