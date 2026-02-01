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

import com.slytechs.sdk.protocol.core.filter.EthernetFilter.EthernetBuilder;
import com.slytechs.sdk.protocol.core.filter.Ip4Filter.Ip4Builder;
import com.slytechs.sdk.protocol.core.filter.Ip6Filter.Ip6Builder;
import com.slytechs.sdk.protocol.core.filter.IpSecFilter.IpSecBuilder;
import com.slytechs.sdk.protocol.core.filter.MplsFilter.MplsBuilder;
import com.slytechs.sdk.protocol.core.filter.TcpFilter.TcpBuilder;
import com.slytechs.sdk.protocol.core.filter.UdpFilter.UdpBuilder;
import com.slytechs.sdk.protocol.core.filter.VlanFilter.VlanBuilder;

/**
 * Entry-point static factory for creating type-safe, backend-agnostic packet
 * filter expressions.
 * <p>
 * {@code PacketFilter} provides convenience static methods that start a new
 * filter chain by returning an empty or pre-scoped {@link ProtocolFilter}. All
 * subsequent method calls on the returned {@code ProtocolFilter} are combined
 * with logical AND.
 * </p>
 * <p>
 * The resulting {@code ProtocolFilter} is completely independent of any
 * capture/forwarding backend and can be compiled to multiple targets (BPF,
 * rte_flow, NTPL, eBPF, etc.) using the appropriate {@link FilterBuilder}
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
 * ProtocolFilter https = PacketFilter
 * 		.ip4()
 * 		.tcp(t -> t.dstPort(443));
 *
 * // VLAN 100 + source subnet + UDP port range
 * ProtocolFilter internalMonitoring = PacketFilter
 * 		.vlan(v -> v.vid(100))
 * 		.srcNet("192.168.100.0/24")
 * 		.udp()
 * 		.portRange(40000, 50000);
 *
 * // Logical OR across protocols
 * ProtocolFilter dnsTraffic = PacketFilter
 * 		.anyOf(
 * 				PacketFilter.udp().port(53),
 * 				PacketFilter.tcp().port(53));
 *
 * // Compile to backend (example)
 * // String bpf = new BpfFilterBuilder().build(dnsTraffic).toExpression();
 * }
 *
 * @see ProtocolFilter the chainable filter interface
 * @see FilterBuilder common contract for backend-specific compilation
 * @see FilterException thrown on invalid filter parameters
 */
public interface PacketFilter {

	/**
	 * Returns an empty (identity) filter that matches all packets.
	 * <p>
	 * This is the starting point for building complex filters via chaining.
	 * </p>
	 *
	 * @return an empty {@link ProtocolFilter} ready for chaining
	 */
	static ProtocolFilter of() {
		return b -> b;
	}

	// ──────────────────────────────────────────────────────────────────────────
	// Logical OR combinators (convenience entry points)
	// ──────────────────────────────────────────────────────────────────────────

	/**
	 * Creates a filter that matches if <strong>any</strong> of the provided header
	 * filters match.
	 *
	 * @param alternatives one or more header-specific filters (logical OR)
	 * @return a new {@link ProtocolFilter} representing the OR group
	 */
	static ProtocolFilter anyOf(HeaderFilter... alternatives) {
		return of().anyOf(alternatives);
	}

	/**
	 * Creates a filter that matches if <strong>any</strong> of the provided
	 * protocol filters match.
	 *
	 * @param alternatives one or more protocol-level filters (logical OR)
	 * @return a new {@link ProtocolFilter} representing the OR group
	 */
	static ProtocolFilter anyOf(ProtocolFilter... alternatives) {
		return of().anyOf(alternatives);
	}

	// ──────────────────────────────────────────────────────────────────────────
	// Protocol entry points (start chain with a specific protocol)
	// ──────────────────────────────────────────────────────────────────────────

	/**
	 * Starts a filter chain that matches packets containing an AH (Authentication
	 * Header) header.
	 *
	 * @return a {@link ProtocolFilter} scoped to AH presence
	 * @see #ah(HeaderOperator)
	 */
	static ProtocolFilter ah() {
		return of().ah();
	}

	/**
	 * Starts a filter chain that matches AH packets and applies additional
	 * AH-specific conditions.
	 *
	 * @param header lambda/operator that configures AH fields (SPI, sequence
	 *               number)
	 * @return a {@link ProtocolFilter} combining AH scope with the given conditions
	 */
	static ProtocolFilter ah(HeaderOperator<IpSecBuilder> header) {
		return of().ah(header);
	}

	/**
	 * Starts a filter chain that matches packets containing an ESP (Encapsulating
	 * Security Payload) header.
	 *
	 * @return a {@link ProtocolFilter} scoped to ESP presence
	 * @see #esp(HeaderOperator)
	 */
	static ProtocolFilter esp() {
		return of().esp();
	}

	/**
	 * Starts a filter chain that matches ESP packets and applies additional
	 * ESP-specific conditions.
	 *
	 * @param header lambda/operator that configures ESP fields (SPI, sequence
	 *               number)
	 * @return a {@link ProtocolFilter} combining ESP scope with the given
	 *         conditions
	 */
	static ProtocolFilter esp(HeaderOperator<IpSecBuilder> header) {
		return of().esp(header);
	}

	/**
	 * Starts a filter chain scoped to the Ethernet header (base layer).
	 *
	 * @return a {@link ProtocolFilter} ready for Ethernet-specific conditions
	 * @see #ethernet(HeaderOperator)
	 */
	static ProtocolFilter ethernet() {
		return of().ethernet();
	}

	/**
	 * Starts a filter chain that matches Ethernet frames and applies additional
	 * Ethernet conditions.
	 *
	 * @param header lambda/operator that configures Ethernet fields (MAC addresses,
	 *               EtherType)
	 * @return a {@link ProtocolFilter} combining Ethernet scope with the given
	 *         conditions
	 */
	static ProtocolFilter ethernet(HeaderOperator<EthernetBuilder> header) {
		return of().ethernet(header);
	}

	/**
	 * Starts a filter chain that matches IPv4 packets.
	 *
	 * @return a {@link ProtocolFilter} scoped to IPv4
	 * @see #ip4(HeaderOperator)
	 */
	static ProtocolFilter ip4() {
		return of().ip4();
	}

	/**
	 * Starts a filter chain that matches IPv4 packets and applies additional IPv4
	 * header conditions.
	 *
	 * @param header lambda/operator that configures IPv4 fields (addresses,
	 *               protocol, TTL, etc.)
	 * @return a {@link ProtocolFilter} combining IPv4 scope with the given
	 *         conditions
	 */
	static ProtocolFilter ip4(HeaderOperator<Ip4Builder> header) {
		return of().ip4(header);
	}

	/**
	 * Starts a filter chain that matches IPv6 packets.
	 *
	 * @return a {@link ProtocolFilter} scoped to IPv6
	 * @see #ip6(HeaderOperator)
	 */
	static ProtocolFilter ip6() {
		return of().ip6();
	}

	/**
	 * Starts a filter chain that matches IPv6 packets and applies additional IPv6
	 * header conditions.
	 *
	 * @param header lambda/operator that configures IPv6 fields (addresses, Next
	 *               Header, Hop Limit, etc.)
	 * @return a {@link ProtocolFilter} combining IPv6 scope with the given
	 *         conditions
	 */
	static ProtocolFilter ip6(HeaderOperator<Ip6Builder> header) {
		return of().ip6(header);
	}

	/**
	 * Starts a filter chain that matches packets with an MPLS label stack.
	 *
	 * @return a {@link ProtocolFilter} scoped to MPLS
	 * @see #mpls(HeaderOperator)
	 */
	static ProtocolFilter mpls() {
		return of().mpls();
	}

	/**
	 * Starts a filter chain that matches MPLS packets and applies additional MPLS
	 * label entry conditions.
	 *
	 * @param header lambda/operator that configures MPLS fields (label, TC, BOS,
	 *               TTL)
	 * @return a {@link ProtocolFilter} combining MPLS scope with the given
	 *         conditions
	 */
	static ProtocolFilter mpls(HeaderOperator<MplsBuilder> header) {
		return of().mpls(header);
	}

	/**
	 * Starts a filter chain that matches TCP packets.
	 *
	 * @return a {@link ProtocolFilter} scoped to TCP
	 * @see #tcp(HeaderOperator)
	 */
	static ProtocolFilter tcp() {
		return of().tcp();
	}

	/**
	 * Starts a filter chain that matches TCP packets and applies additional TCP
	 * header conditions.
	 *
	 * @param header lambda/operator that configures TCP fields (ports, flags, etc.)
	 * @return a {@link ProtocolFilter} combining TCP scope with the given
	 *         conditions
	 */
	static ProtocolFilter tcp(HeaderOperator<TcpBuilder> header) {
		return of().tcp(header);
	}

	/**
	 * Starts a filter chain that matches UDP packets.
	 *
	 * @return a {@link ProtocolFilter} scoped to UDP
	 * @see #udp(HeaderOperator)
	 */
	static ProtocolFilter udp() {
		return of().udp();
	}

	/**
	 * Starts a filter chain that matches UDP packets and applies additional UDP
	 * header conditions.
	 *
	 * @param header lambda/operator that configures UDP fields (ports)
	 * @return a {@link ProtocolFilter} combining UDP scope with the given
	 *         conditions
	 */
	static ProtocolFilter udp(HeaderOperator<UdpBuilder> header) {
		return of().udp(header);
	}

	/**
	 * Starts a filter chain that matches packets with a VLAN tag (802.1Q).
	 *
	 * @return a {@link ProtocolFilter} scoped to VLAN
	 * @see #vlan(HeaderOperator)
	 */
	static ProtocolFilter vlan() {
		return of().vlan();
	}

	/**
	 * Starts a filter chain that matches VLAN-tagged packets and applies additional
	 * VLAN conditions.
	 *
	 * @param header lambda/operator that configures VLAN fields (VID, PCP, DEI,
	 *               TPID)
	 * @return a {@link ProtocolFilter} combining VLAN scope with the given
	 *         conditions
	 */
	static ProtocolFilter vlan(HeaderOperator<VlanBuilder> header) {
		return of().vlan(header);
	}

	// ──────────────────────────────────────────────────────────────────────────
	// Network primitives (host, subnet, port) — convenience entry points
	// ──────────────────────────────────────────────────────────────────────────

	/**
	 * Starts a filter that matches packets where source or destination IP equals
	 * the given address.
	 *
	 * @param ip IPv4 or IPv6 address string (e.g. "192.168.1.1", "2001:db8::1")
	 * @return a {@link ProtocolFilter} with host match
	 * @throws FilterException if the IP string is malformed
	 */
	static ProtocolFilter host(String ip) {
		return of().host(ip);
	}

	/**
	 * Starts a filter that matches packets where the source IP equals the given
	 * address.
	 *
	 * @param ip IPv4 or IPv6 address string
	 * @return a {@link ProtocolFilter} with source host match
	 * @throws FilterException if the IP string is malformed
	 */
	static ProtocolFilter srcHost(String ip) {
		return of().srcHost(ip);
	}

	/**
	 * Starts a filter that matches packets where the destination IP equals the
	 * given address.
	 *
	 * @param ip IPv4 or IPv6 address string
	 * @return a {@link ProtocolFilter} with destination host match
	 * @throws FilterException if the IP string is malformed
	 */
	static ProtocolFilter dstHost(String ip) {
		return of().dstHost(ip);
	}

	/**
	 * Starts a filter that matches packets where source or destination IP is within
	 * the given subnet.
	 *
	 * @param cidr CIDR notation (e.g. "192.168.1.0/24", "2001:db8::/64")
	 * @return a {@link ProtocolFilter} with network match
	 * @throws FilterException if cidr is malformed or invalid
	 */
	static ProtocolFilter net(String cidr) {
		return of().net(cidr);
	}

	/**
	 * Starts a filter that matches packets where the source IP is within the given
	 * subnet.
	 *
	 * @param cidr CIDR notation
	 * @return a {@link ProtocolFilter} with source network match
	 * @throws FilterException if cidr is malformed or invalid
	 */
	static ProtocolFilter srcNet(String cidr) {
		return of().srcNet(cidr);
	}

	/**
	 * Starts a filter that matches packets where the destination IP is within the
	 * given subnet.
	 *
	 * @param cidr CIDR notation
	 * @return a {@link ProtocolFilter} with destination network match
	 * @throws FilterException if cidr is malformed or invalid
	 */
	static ProtocolFilter dstNet(String cidr) {
		return of().dstNet(cidr);
	}

	/**
	 * Starts a filter that matches packets where source or destination transport
	 * port equals the given value.
	 *
	 * @param port port number (must be 0–65535)
	 * @return a {@link ProtocolFilter} with port match (src OR dst)
	 * @throws FilterException if port is not in the range 0–65535
	 */
	static ProtocolFilter port(int port) throws FilterException {
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
	 * @return a {@link ProtocolFilter} with port range match (src OR dst)
	 * @throws FilterException if start or end is out of range or start > end
	 */
	static ProtocolFilter portRange(int start, int end) throws FilterException {
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

	// ──────────────────────────────────────────────────────────────────────────
	// Packet metadata entry points
	// ──────────────────────────────────────────────────────────────────────────

	/**
	 * Starts a filter that matches packets whose length is greater than the given
	 * value.
	 *
	 * @param len minimum length (exclusive)
	 * @return a {@link ProtocolFilter} with length > condition
	 */
	static ProtocolFilter lengthGreater(int len) {
		return of().lengthGreater(len);
	}

	/**
	 * Starts a filter that matches packets whose length is less than the given
	 * value.
	 *
	 * @param len maximum length (exclusive)
	 * @return a {@link ProtocolFilter} with length < condition
	 */
	static ProtocolFilter lengthLess(int len) {
		return of().lengthLess(len);
	}

	/**
	 * Starts a filter that matches broadcast packets.
	 *
	 * @return a {@link ProtocolFilter} with broadcast match
	 */
	static ProtocolFilter broadcast() {
		return of().broadcast();
	}

	/**
	 * Starts a filter that matches multicast packets.
	 *
	 * @return a {@link ProtocolFilter} with multicast match
	 */
	static ProtocolFilter multicast() {
		return of().multicast();
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