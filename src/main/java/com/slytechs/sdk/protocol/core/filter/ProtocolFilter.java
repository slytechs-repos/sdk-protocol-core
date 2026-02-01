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

import java.util.function.Consumer;
import java.util.function.Function;

import com.slytechs.sdk.common.util.Registration;
import com.slytechs.sdk.protocol.core.filter.VlanFilter.VlanBuilder;

/**
 * Fluent, type-safe DSL for composing backend-agnostic packet filter
 * expressions.
 * <p>
 * {@code ProtocolFilter} is the primary chainable interface returned by static
 * factory methods on {@link PacketFilter}. It allows declarative construction
 * of filters that span multiple protocol layers (Ethernet, VLAN, IPv4/IPv6,
 * TCP, UDP, MPLS, IPsec/AH/ESP) as well as common network matching primitives
 * (host, subnet/CIDR, port, port range) and packet metadata (length, broadcast,
 * multicast).
 * </p>
 * <p>
 * The DSL is deliberately independent of any specific capture or forwarding
 * engine. The same {@code ProtocolFilter} expression can be compiled to
 * different target formats by using the appropriate backend-specific builder:
 * <ul>
 * <li>libpcap / WinPcap / Npcap BPF syntax ({@code BpfFilterBuilder})</li>
 * <li>DPDK rte_flow rules or eBPF bytecode ({@code RteFlowBuilder}, eBPF
 * builder)</li>
 * <li>Napatech NTPL filter language ({@code NtplFilterBuilder})</li>
 * <li>potentially others (SmartNIC P4, XDP, etc.)</li>
 * </ul>
 * </p>
 * <p>
 * Successive method calls on the chain are combined with logical
 * <strong>AND</strong>. Logical <strong>OR</strong> is explicitly constructed
 * using {@link #anyOf(HeaderFilter...)} or {@link #anyOf(ProtocolFilter...)}.
 * </p>
 * <p>
 * Input validation is performed eagerly during construction:
 * <ul>
 * <li>ports and port ranges must be 0–65535</li>
 * <li>IP addresses and CIDR notations are validated for format and
 * semantics</li>
 * <li>out-of-range or semantically invalid values throw {@link FilterException}
 * immediately (fail-fast behavior)</li>
 * </ul>
 * This helps catch configuration errors at development / initialization time
 * rather than at runtime or during filter compilation.
 * </p>
 * 
 * <h2>Catch-All Filter</h2>
 * <p>
 * Use {@link PacketFilter#all()} to create a filter that matches all packets
 * unconditionally. The catch-all filter must not be combined with other filters
 * or used inside {@link #anyOf(ProtocolFilter...)}; doing so throws
 * {@link FilterException}.
 * </p>
 * 
 * <h2>Usage Examples</h2>
 *
 * {@snippet lang = java :
 * // Basic protocol + port filter
 * ProtocolFilter https = PacketFilter
 * 		.ip4()
 * 		.tcp(t -> t.dstPort(443));
 *
 * // VLAN + IP subnet + TCP flags
 * ProtocolFilter internalWeb = PacketFilter
 * 		.vlan(v -> v.vid(100).pcp(5))
 * 		.ip4(ip -> ip.srcNet("10.10.0.0/16"))
 * 		.tcp(t -> t.dstPort(443).flagSyn());
 *
 * // Logical OR across VLAN IDs
 * ProtocolFilter financeVlans = PacketFilter
 * 		.anyOf(
 * 				VlanFilter.vid(200),
 * 				VlanFilter.vid(300))
 * 		.ip4();
 *
 * // Protocol family agnostic + port range
 * ProtocolFilter monitoring = PacketFilter
 * 		.anyOf(PacketFilter.ip4(), PacketFilter.ip6())
 * 		.udp()
 * 		.portRange(30000, 31000);
 *
 * // Compile to different backends
 * String bpfExpr = new BpfFilterBuilder().build(monitoring).toExpression();
 * // RteFlowRule rteRule = new RteFlowBuilder().build(monitoring);
 * // String ntpl = new NtplFilterBuilder().build(monitoring).toString();
 * }
 *
 * @see PacketFilter static factory entry point
 * @see FilterBuilder common builder contract used by backends
 * @see FilterException thrown on invalid filter construction
 * @see HeaderOperator functional interface for header-specific lambdas
 * @see VlanFilter
 * @see EthernetFilter
 * @see Ip4Filter
 * @see Ip6Filter
 * @see TcpFilter
 * @see UdpFilter
 * @see MplsFilter
 * @see IpSecFilter
 */
public interface ProtocolFilter {

	/**
	 * Emits the current filter expression into the provided {@link FilterBuilder}.
	 * <p>
	 * This is the terminal method called internally to build the final filter
	 * string or structure. Implementations append their conditions and return the
	 * modified builder.
	 * </p>
	 *
	 * @param b the builder to emit into
	 * @return the modified builder (for chaining)
	 * @throws FilterException if the emitted expression is invalid
	 */
	FilterBuilder emit(FilterBuilder b) throws FilterException;

	// -------------------------------------------------------------------------
	// Protocol selectors (simple presence)
	// -------------------------------------------------------------------------

	/**
	 * Matches packets containing an AH (Authentication Header) header (IP protocol
	 * 51).
	 *
	 * @return a new filter that adds an AH protocol condition
	 */
	default ProtocolFilter ah() {
		return b -> this.emit(b).and().protocol("ah");
	}

	/**
	 * Matches packets containing an AH header and applies additional AH-specific
	 * conditions.
	 *
	 * @param header operator that configures AH fields (SPI, sequence number, etc.)
	 * @return a new filter combining AH presence with the specified header
	 *         conditions
	 */
	default ProtocolFilter ah(HeaderOperator<IpSecFilter.IpSecBuilder> header) {
		return b -> header.apply(IpSecFilter.of()).emit(this.emit(b).and().protocol("ah"));
	}

	/**
	 * Matches packets containing an ESP (Encapsulating Security Payload) header (IP
	 * protocol 50).
	 *
	 * @return a new filter that adds an ESP protocol condition
	 */
	default ProtocolFilter esp() {
		return b -> this.emit(b).and().protocol("esp");
	}

	/**
	 * Matches packets containing an ESP header and applies additional ESP-specific
	 * conditions.
	 *
	 * @param header operator that configures ESP fields (SPI, sequence number)
	 * @return a new filter combining ESP presence with the specified header
	 *         conditions
	 */
	default ProtocolFilter esp(HeaderOperator<IpSecFilter.IpSecBuilder> header) {
		return b -> header.apply(IpSecFilter.of()).emit(this.emit(b).and().protocol("esp"));
	}

	/**
	 * Matches Ethernet frames (base layer).
	 *
	 * @return a new filter that scopes to Ethernet header conditions
	 */
	default ProtocolFilter ethernet() {
		return b -> this.emit(b).and().protocol("eth");
	}

	/**
	 * Matches Ethernet frames and applies additional Ethernet header conditions
	 * (MAC, EtherType).
	 *
	 * @param header operator that configures Ethernet fields
	 * @return a new filter combining Ethernet scope with the specified conditions
	 */
	default ProtocolFilter ethernet(HeaderOperator<EthernetFilter.EthernetBuilder> header) {
		return b -> header.apply(EthernetFilter.of()).emit(this.emit(b).and().protocol("eth"));
	}

	/**
	 * Matches IPv4 packets.
	 *
	 * @return a new filter that adds an IPv4 protocol condition
	 */
	default ProtocolFilter ip4() {
		return b -> this.emit(b).and().protocol("ip4");
	}

	/**
	 * Matches IPv4 packets and applies additional IPv4 header conditions
	 * (addresses, protocol, TTL).
	 *
	 * @param header operator that configures IPv4 fields
	 * @return a new filter combining IPv4 scope with the specified conditions
	 */
	default ProtocolFilter ip4(HeaderOperator<Ip4Filter.Ip4Builder> header) {
		return b -> header.apply(Ip4Filter.of()).emit(this.emit(b).and().protocol("ip4"));
	}

	/**
	 * Matches IPv6 packets.
	 *
	 * @return a new filter that adds an IPv6 protocol condition
	 */
	default ProtocolFilter ip6() {
		return b -> this.emit(b).and().protocol("ip6");
	}

	/**
	 * Matches IPv6 packets and applies additional IPv6 header conditions
	 * (addresses, Next Header, Hop Limit).
	 *
	 * @param header operator that configures IPv6 fields
	 * @return a new filter combining IPv6 scope with the specified conditions
	 */
	default ProtocolFilter ip6(HeaderOperator<Ip6Filter.Ip6Builder> header) {
		return b -> header.apply(Ip6Filter.of()).emit(this.emit(b).and().protocol("ip6"));
	}

	/**
	 * Matches TCP packets.
	 *
	 * @return a new filter that adds a TCP protocol condition
	 */
	default ProtocolFilter tcp() {
		return b -> this.emit(b).and().protocol("tcp");
	}

	/**
	 * Matches TCP packets and applies additional TCP header conditions (ports,
	 * flags).
	 *
	 * @param header operator that configures TCP fields
	 * @return a new filter combining TCP scope with the specified conditions
	 */
	default ProtocolFilter tcp(HeaderOperator<TcpFilter.TcpBuilder> header) {
		return b -> header.apply(TcpFilter.of()).emit(this.emit(b).and().protocol("tcp"));
	}

	/**
	 * Matches UDP packets.
	 *
	 * @return a new filter that adds a UDP protocol condition
	 */
	default ProtocolFilter udp() {
		return b -> this.emit(b).and().protocol("udp");
	}

	/**
	 * Matches UDP packets and applies additional UDP header conditions (ports).
	 *
	 * @param header operator that configures UDP fields
	 * @return a new filter combining UDP scope with the specified conditions
	 */
	default ProtocolFilter udp(HeaderOperator<UdpFilter.UdpBuilder> header) {
		return b -> header.apply(UdpFilter.of()).emit(this.emit(b).and().protocol("udp"));
	}

	/**
	 * Matches packets with a VLAN tag (802.1Q).
	 *
	 * @return a new filter that adds a VLAN protocol condition
	 */
	default ProtocolFilter vlan() {
		return b -> this.emit(b).and().protocol("vlan");
	}

	/**
	 * Matches VLAN-tagged packets and applies additional VLAN header conditions
	 * (VID, PCP, DEI, TPID).
	 *
	 * @param header operator that configures VLAN fields
	 * @return a new filter combining VLAN scope with the specified conditions
	 */
	default ProtocolFilter vlan(HeaderOperator<VlanBuilder> header) {
		return b -> header.apply(VlanFilter.of()).emit(this.emit(b).and().protocol("vlan"));
	}

	/**
	 * Directly embeds a pre-configured {@link VlanBuilder} into the filter.
	 *
	 * @param header a configured VLAN builder
	 * @return a new filter that includes the VLAN conditions
	 */
	default ProtocolFilter vlanFilter(VlanBuilder header) {
		return b -> header.emit(this.emit(b));
	}

	/**
	 * Matches packets with an MPLS label stack entry.
	 *
	 * @return a new filter that adds an MPLS protocol condition
	 */
	default ProtocolFilter mpls() {
		return b -> this.emit(b).and().protocol("mpls");
	}

	/**
	 * Matches MPLS packets and applies additional MPLS label entry conditions
	 * (label, TC, BOS, TTL).
	 *
	 * @param header operator that configures MPLS fields
	 * @return a new filter combining MPLS scope with the specified conditions
	 */
	default ProtocolFilter mpls(HeaderOperator<MplsFilter.MplsBuilder> header) {
		return b -> header.apply(MplsFilter.of()).emit(this.emit(b).and().protocol("mpls"));
	}

	// -------------------------------------------------------------------------
	// Logical combinators
	// -------------------------------------------------------------------------

	/**
	 * Matches if <strong>any</strong> of the provided header filters match (logical
	 * OR).
	 *
	 * @param alternatives one or more header-specific filters
	 * @return a new filter that groups the alternatives with OR
	 */
	default ProtocolFilter anyOf(HeaderFilter... alternatives) {
		return b -> {
			this.emit(b).and().group();
			for (int i = 0; i < alternatives.length; i++) {
				if (i > 0)
					b.or();
				alternatives[i].emit(b);
			}
			return b.endGroup();
		};
	}

	/**
	 * Matches if <strong>any</strong> of the provided protocol filters match
	 * (logical OR).
	 *
	 * @param alternatives one or more protocol-level filters
	 * @return a new filter that groups the alternatives with OR
	 */
	default ProtocolFilter anyOf(ProtocolFilter... alternatives) {
		return b -> {
			this.emit(b).and().group();
			for (int i = 0; i < alternatives.length; i++) {
				if (i > 0)
					b.or();
				alternatives[i].emit(b);
			}
			return b.endGroup();
		};
	}

	// -------------------------------------------------------------------------
	// Address / Host matching
	// -------------------------------------------------------------------------

	/**
	 * Matches packets where the source or destination IP address equals the given
	 * host.
	 *
	 * @param ip IPv4 or IPv6 address as string (e.g. "192.168.1.1", "2001:db8::1")
	 * @return a new filter adding host match condition
	 * @throws FilterException if the IP string is malformed
	 */
	default ProtocolFilter host(String ip) {
		return b -> this.emit(b).and().host(ip);
	}

	/**
	 * Matches packets where the source or destination IP address equals the given
	 * binary address.
	 *
	 * @param ip 4-byte (IPv4) or 16-byte (IPv6) address
	 * @return a new filter adding binary host match condition
	 * @throws FilterException if ip is null or wrong length
	 */
	default ProtocolFilter host(byte[] ip) {
		return b -> this.emit(b).and().host(ip);
	}

	/**
	 * Matches packets where the destination IP address equals the given host.
	 *
	 * @param ip IPv4 or IPv6 address as string
	 * @return a new filter adding destination host match
	 * @throws FilterException if the IP string is malformed
	 */
	default ProtocolFilter dstHost(String ip) {
		return b -> this.emit(b).and().dstHost(ip);
	}

	/**
	 * Matches packets where the source IP address equals the given host.
	 *
	 * @param ip IPv4 or IPv6 address as string
	 * @return a new filter adding source host match
	 * @throws FilterException if the IP string is malformed
	 */
	default ProtocolFilter srcHost(String ip) {
		return b -> this.emit(b).and().srcHost(ip);
	}

	/**
	 * Matches packets where the source or destination IP is within the given CIDR
	 * network.
	 *
	 * @param cidr CIDR notation (e.g. "192.168.1.0/24", "2001:db8::/32")
	 * @return a new filter adding network match
	 * @throws FilterException if cidr is malformed or invalid
	 */
	default ProtocolFilter net(String cidr) {
		return b -> this.emit(b).and().net(cidr);
	}

	/**
	 * Matches packets where the destination IP is within the given CIDR network.
	 *
	 * @param cidr CIDR notation
	 * @return a new filter adding destination network match
	 * @throws FilterException if cidr is malformed or invalid
	 */
	default ProtocolFilter dstNet(String cidr) {
		return b -> this.emit(b).and().dstNet(cidr);
	}

	/**
	 * Matches packets where the source IP is within the given CIDR network.
	 *
	 * @param cidr CIDR notation
	 * @return a new filter adding source network match
	 * @throws FilterException if cidr is malformed or invalid
	 */
	default ProtocolFilter srcNet(String cidr) {
		return b -> this.emit(b).and().srcNet(cidr);
	}

	// -------------------------------------------------------------------------
	// Port matching
	// -------------------------------------------------------------------------

	/**
	 * Matches packets where the source or destination transport port equals the
	 * given value.
	 *
	 * @param port port number (0–65535)
	 * @return a new filter adding port match (src OR dst)
	 * @throws FilterException if port is not in 0–65535
	 */
	default ProtocolFilter port(int port) throws FilterException {
		if (port < 0 || port > 65535) {
			throw new FilterException("Port must be 0-65535, got: " + port);
		}
		return b -> this.emit(b).and().port(port);
	}

	/**
	 * Matches packets where the source transport port equals the given value.
	 *
	 * @param port source port number (0–65535)
	 * @return a new filter adding source port match
	 * @throws FilterException if port is not in 0–65535
	 */
	default ProtocolFilter srcPort(int port) throws FilterException {
		if (port < 0 || port > 65535) {
			throw new FilterException("Source port must be 0-65535, got: " + port);
		}
		return b -> this.emit(b).and().srcPort(port);
	}

	/**
	 * Matches packets where the destination transport port equals the given value.
	 *
	 * @param port destination port number (0–65535)
	 * @return a new filter adding destination port match
	 * @throws FilterException if port is not in 0–65535
	 */
	default ProtocolFilter dstPort(int port) throws FilterException {
		if (port < 0 || port > 65535) {
			throw new FilterException("Destination port must be 0-65535, got: " + port);
		}
		return b -> this.emit(b).and().dstPort(port);
	}

	/**
	 * Matches packets where either the source or destination port is within the
	 * inclusive range [start, end].
	 *
	 * @param start lower bound of port range (inclusive, 0–65535)
	 * @param end   upper bound of port range (inclusive, 0–65535)
	 * @return a new filter adding port range match (src OR dst)
	 * @throws FilterException if start or end is out of range or start > end
	 */
	default ProtocolFilter portRange(int start, int end) throws FilterException {
		if (start < 0 || start > 65535) {
			throw new FilterException("Port range start must be 0-65535, got: " + start);
		}
		if (end < 0 || end > 65535) {
			throw new FilterException("Port range end must be 0-65535, got: " + end);
		}
		if (start > end) {
			throw new FilterException("Port range start (" + start + ") must not exceed end (" + end + ")");
		}
		return b -> this.emit(b).and().portRange(start, end);
	}

	// -------------------------------------------------------------------------
	// Packet metadata / special matches
	// -------------------------------------------------------------------------

	/**
	 * Matches broadcast packets (destination MAC is broadcast or destination IP is
	 * broadcast address).
	 *
	 * @return a new filter adding broadcast match
	 */
	default ProtocolFilter broadcast() {
		return b -> this.emit(b).and().broadcast();
	}

	/**
	 * Matches multicast packets (destination MAC is multicast or destination IP is
	 * multicast address).
	 *
	 * @return a new filter adding multicast match
	 */
	default ProtocolFilter multicast() {
		return b -> this.emit(b).and().multicast();
	}

	/**
	 * Matches packets whose total captured length equals the given value.
	 *
	 * @param len exact packet length in bytes
	 * @return a new filter adding exact length match
	 */
	default ProtocolFilter length(int len) {
		return b -> this.emit(b).and().length(FilterBuilder.Op.EQ, len);
	}

	/**
	 * Matches packets whose total captured length is greater than the given value.
	 *
	 * @param len minimum packet length (exclusive)
	 * @return a new filter adding length > condition
	 */
	default ProtocolFilter lengthGreater(int len) {
		return b -> this.emit(b).and().length(FilterBuilder.Op.GT, len);
	}

	/**
	 * Matches packets whose total captured length is less than the given value.
	 *
	 * @param len maximum packet length (exclusive)
	 * @return a new filter adding length < condition
	 */
	default ProtocolFilter lengthLess(int len) {
		return b -> this.emit(b).and().length(FilterBuilder.Op.LT, len);
	}

	// -------------------------------------------------------------------------
	// Debugging / expression hooks
	// -------------------------------------------------------------------------

	/**
	 * Registers a callback that receives the final generated filter expression
	 * string and allows assertion-style validation during development.
	 *
	 * @param debugAction consumer that receives the expression and may throw if
	 *                    invalid
	 * @return a new filter with the debug hook attached
	 */
	default ProtocolFilter onExpressionAssert(Function<String, Boolean> debugAction) {
		return onExpression(value -> {
			if (!debugAction.apply(value))
				throw new IllegalStateException("expression output error :" + value);
		});
	}

	/**
	 * Registers a simple callback that receives the final generated filter
	 * expression string.
	 *
	 * @param debugAction consumer that receives the expression string
	 * @return a new filter with the debug hook attached
	 */
	default ProtocolFilter onExpression(Consumer<String> debugAction) {
		return b -> this.emit(b).onExpressionAction(debugAction, _ -> {});
	}

	/**
	 * Registers a callback that receives the final expression and a registration
	 * handle.
	 *
	 * @param debugAction  consumer for the expression string
	 * @param registration consumer for the registration object (for cleanup if
	 *                     needed)
	 * @return a new filter with the advanced debug hook attached
	 */
	default ProtocolFilter onExpression(Consumer<String> debugAction, Consumer<Registration> registration) {
		return b -> this.emit(b).onExpressionAction(debugAction, registration);
	}

	// -------------------------------------------------------------------------
	// Logical OR helpers
	// -------------------------------------------------------------------------

	/**
	 * Adds a logical OR with another protocol-level filter.
	 *
	 * @param other another protocol filter to OR with
	 * @return a new filter combining this and other with OR
	 */
	default ProtocolFilter orFilter(ProtocolFilter other) {
		return b -> other.emit(this.emit(b).or());
	}

	/**
	 * Adds a logical OR with a header operator applied to a new base filter.
	 *
	 * @param other operator that configures another filter
	 * @return a new filter combining this with the other condition via OR
	 */
	default ProtocolFilter or(HeaderOperator<ProtocolFilter> other) {
		return b -> other.apply(PacketFilter.of()).emit(this.emit(b).or());
	}
}