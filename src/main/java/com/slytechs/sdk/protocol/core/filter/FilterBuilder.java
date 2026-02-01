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

import com.slytechs.sdk.common.util.Registration;

/**
 * Backend-agnostic intermediate representation (IR) for packet filter
 * expressions.
 * <p>
 * {@code FilterBuilder} defines the primitive operations that all backend
 * compilers must implement. The filter DSL ({@link ProtocolFilter} and
 * {@link HeaderFilter}) emits calls to this interface, and each backend
 * translates them into its native syntax:
 * <ul>
 *   <li>{@code BpfFilterBuilder} - libpcap BPF expressions</li>
 *   <li>{@code RteFlowBuilder} - DPDK rte_flow patterns (C structs)</li>
 *   <li>{@code NtplFilterBuilder} - Napatech NTPL commands</li>
 * </ul>
 * </p>
 * <p>
 * Operations fall into several categories:
 * <ul>
 *   <li><b>Network primitives</b> - host, network/CIDR, port, port range</li>
 *   <li><b>Packet metadata</b> - length comparisons, broadcast, multicast</li>
 *   <li><b>Protocol presence</b> - match by protocol name</li>
 *   <li><b>Field comparisons</b> - match specific header fields by offset, size,
 *       and operator</li>
 *   <li><b>Logical structure</b> - AND, OR, grouping (parentheses)</li>
 *   <li><b>Observability</b> - expression action callbacks for debugging</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see ProtocolFilter
 * @see HeaderFilter
 * @see PacketFilter
 */
public interface FilterBuilder {

    /**
     * Comparison operators for field-level filter conditions.
     */
    enum Op {
        /** Equal. */
        EQ,
        /** Not equal. */
        NE,
        /** Less than. */
        LT,
        /** Less than or equal. */
        LE,
        /** Greater than. */
        GT,
        /** Greater than or equal. */
        GE,
        /** Bitwise mask (value AND mask != 0). */
        MASK,
        /** Membership in a set of values. */
        IN,
    }

    /**
     * Matches packets where source or destination IP equals the given address.
     *
     * @param ip IP address string (e.g. "10.0.0.1", "2001:db8::1")
     * @return this builder for chaining
     */
    FilterBuilder host(String ip);

    /**
     * Matches packets where source or destination IP equals the given address.
     *
     * @param ip IP address as byte array (4 bytes for IPv4, 16 for IPv6)
     * @return this builder for chaining
     */
    FilterBuilder host(byte[] ip);

    /**
     * Matches packets where the source IP equals the given address.
     *
     * @param ip IP address string
     * @return this builder for chaining
     */
    FilterBuilder srcHost(String ip);

    /**
     * Matches packets where the destination IP equals the given address.
     *
     * @param ip IP address string
     * @return this builder for chaining
     */
    FilterBuilder dstHost(String ip);

    /**
     * Matches packets where source or destination IP is within the given subnet.
     *
     * @param cidr CIDR notation (e.g. "192.168.0.0/24")
     * @return this builder for chaining
     */
    FilterBuilder net(String cidr);

    /**
     * Matches packets where the source IP is within the given subnet.
     *
     * @param cidr CIDR notation
     * @return this builder for chaining
     */
    FilterBuilder srcNet(String cidr);

    /**
     * Matches packets where the destination IP is within the given subnet.
     *
     * @param cidr CIDR notation
     * @return this builder for chaining
     */
    FilterBuilder dstNet(String cidr);

    /**
     * Matches packets where source or destination transport port equals the given
     * value (protocol-agnostic, applies to TCP and UDP).
     *
     * @param port port number (0-65535)
     * @return this builder for chaining
     */
    FilterBuilder port(int port);

    /**
     * Matches packets where the source transport port equals the given value.
     *
     * @param port source port number (0-65535)
     * @return this builder for chaining
     */
    FilterBuilder srcPort(int port);

    /**
     * Matches packets where the destination transport port equals the given value.
     *
     * @param port destination port number (0-65535)
     * @return this builder for chaining
     */
    FilterBuilder dstPort(int port);

    /**
     * Matches packets where source or destination port falls within the given
     * inclusive range.
     *
     * @param start lower bound (inclusive, 0-65535)
     * @param end   upper bound (inclusive, 0-65535)
     * @return this builder for chaining
     */
    FilterBuilder portRange(int start, int end);

    /**
     * Matches packets by total length using the specified comparison operator.
     *
     * @param op  comparison operator ({@link Op#EQ}, {@link Op#GT}, {@link Op#LT},
     *            etc.)
     * @param len length value in bytes
     * @return this builder for chaining
     */
    FilterBuilder length(Op op, int len);

    /**
     * Matches broadcast packets (destination is the broadcast address).
     *
     * @return this builder for chaining
     */
    FilterBuilder broadcast();

    /**
     * Matches multicast packets (destination is a multicast address).
     *
     * @return this builder for chaining
     */
    FilterBuilder multicast();

    /**
     * Adds a protocol presence check to the filter.
     * <p>
     * Protocol names are backend-agnostic identifiers (e.g. "ip4", "ip6", "tcp",
     * "udp", "vlan", "mpls", "esp", "ah", "eth") that each builder maps to its
     * native syntax.
     * </p>
     *
     * @param protocol protocol name
     * @return this builder for chaining
     */
    FilterBuilder protocol(String protocol);

    /**
     * Adds a protocol presence check at a specific stack depth.
     * <p>
     * Useful for tunneled or stacked protocols (e.g. inner vs. outer VLAN,
     * MPLS label depth).
     * </p>
     *
     * @param protocol protocol name
     * @param depth    nesting depth (0 = outermost)
     * @return this builder for chaining
     */
    FilterBuilder protocol(String protocol, int depth);

    /**
     * Adds a field-level comparison using a numeric value.
     *
     * @param name   field identifier (e.g. "tcp.srcPort", "ip4.ttl", "vlan.vid")
     * @param offset byte offset of the field within its header
     * @param bits   field width in bits
     * @param op     comparison operator
     * @param value  value to compare against
     * @return this builder for chaining
     */
    FilterBuilder field(String name, int offset, int bits, Op op, long value);

    /**
     * Adds a field-level comparison using a byte array value (e.g. MAC or IP
     * addresses).
     *
     * @param name   field identifier (e.g. "eth.dst", "ip6.src")
     * @param offset byte offset of the field within its header
     * @param bits   field width in bits
     * @param op     comparison operator
     * @param value  byte array to compare against
     * @return this builder for chaining
     */
    FilterBuilder field(String name, int offset, int bits, Op op, byte[] value);

    /**
     * Appends a logical AND conjunction.
     *
     * @return this builder for chaining
     */
    FilterBuilder and();

    /**
     * Appends a logical OR disjunction.
     *
     * @return this builder for chaining
     */
    FilterBuilder or();

    /**
     * Opens a parenthesized group for controlling operator precedence.
     *
     * @return this builder for chaining
     * @see #endGroup()
     */
    FilterBuilder group();

    /**
     * Closes a parenthesized group previously opened with {@link #group()}.
     *
     * @return this builder for chaining
     */
    FilterBuilder endGroup();

    /**
     * Registers a debug callback that receives the final expression string when
     * {@link #expression()} is called.
     * <p>
     * Intended for development and testing. The registration consumer allows
     * removal of the callback when no longer needed.
     * </p>
     *
     * @param debugAction  consumer that receives the expression string
     * @param registration consumer that receives a {@link Registration} handle for
     *                     later removal
     * @return this builder for chaining
     */
    FilterBuilder onExpressionAction(Consumer<String> debugAction, Consumer<Registration> registration);

    /**
     * Builds and returns the final filter expression string.
     * <p>
     * The format of the returned string is backend-specific (e.g. BPF syntax,
     * C struct declarations, NTPL commands). Any registered expression action
     * callbacks are invoked before the string is returned.
     * </p>
     *
     * @return the compiled filter expression
     */
    String expression();
}