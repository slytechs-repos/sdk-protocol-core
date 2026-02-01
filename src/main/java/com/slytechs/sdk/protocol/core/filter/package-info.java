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

/**
 * Type-safe, backend-agnostic packet filter DSL for high-performance network
 * capture and forwarding.
 *
 * <h2>Overview</h2>
 * <p>
 * This package provides a fluent API for defining packet filters that are
 * independent of any specific capture backend. A single filter definition can
 * be compiled to libpcap BPF, DPDK rte_flow, DPDK eBPF, Napatech NTPL, or any
 * future backend without modification.
 * </p>
 * <p>
 * The API follows a two-phase design:
 * <ol>
 * <li><b>Define</b> — Build a {@link PacketDsl} chain using static
 * factories on {@link PacketFilter}. Validation occurs immediately; invalid
 * values throw {@link FilterException}.</li>
 * <li><b>Compile</b> — Pass the chain to a backend-specific
 * {@link Emitter} to produce a compiled {@link PacketFilter} with a
 * backend-native representation.</li>
 * </ol>
 *
 * {@snippet :
 * // Define (backend-agnostic)
 * PacketDsl dsl = PacketFilter
 *     .vlan(v -> v.vid(100))
 *     .ip4()
 *     .tcp(tcp -> tcp.port(443));
 *
 * // Compile to libpcap BPF
 * PcapPacketFilter pcap = new BpfFilterBuilder().build(dsl);
 * pcap.toExpression();   // "vlan and vlan 100 and ip and tcp and ..."
 * pcap.toBpfProgram();   // compiled BPF bytecode
 *
 * // Same filter, compiled to DPDK rte_flow
 * DpdkPacketFilter dpdk = new RteFlowBuilder().build(dsl);
 * dpdk.toExpression();   // C struct rte_flow_item pattern[]
 * dpdk.toRteFlow(...);   // hardware-offloaded flow rule
 * }
 *
 * <h2>Architecture</h2>
 *
 * <pre>
 *   PacketFilter          Static factories (entry point) + compiled filter (exit point)
 *       |
 *       v
 *   PacketDsl        Fluent DSL chain — protocol, field, and primitive composition
 *       |
 *       |--- HeaderDsl          Base interface for protocol-specific field builders
 *       |      |--- EthernetFilter.EthernetDsl
 *       |      |--- VlanFilter.VlanDsl
 *       |      |--- Ip4Filter.Ip4Dsl
 *       |      |--- Ip6Filter.Ip6Dsl
 *       |      |--- TcpFilter.TcpDsl
 *       |      |--- UdpFilter.UdpDsl
 *       |      |--- IpSecFilter.IpSecDsl
 *       |      |--- MplsFilter.MplsDsl
 *       |
 *       v
 *   Emitter         Backend IR — primitives that each compiler implements
 *       |
 *       |--- BpfFilterBuilder      → PcapPacketFilter   (libpcap BPF)
 *       |--- RteFlowBuilder        → DpdkPacketFilter   (DPDK rte_flow / eBPF)
 *       |--- NtplFilterBuilder     → NtapiPacketFilter  (Napatech NTPL)
 * </pre>
 *
 * <h2>Filter Composition</h2>
 * <p>
 * Method chaining implies logical AND. Use
 * {@link PacketDsl#anyOf(HeaderDsl...)} or
 * {@link PacketDsl#anyOf(PacketDsl...)} for logical OR groups:
 * </p>
 *
 * {@snippet :
 * // Chaining = AND
 * PacketFilter.ip4().tcp().dstPort(443)
 * // "ip and tcp and tcp dst port 443"
 *
 * // anyOf = OR
 * PacketFilter.anyOf(VlanFilter.vid(100), VlanFilter.vid(200))
 * // "(vlan 100 or vlan 200)"
 *
 * // Combined
 * PacketFilter
 *     .anyOf(VlanFilter.vid(100), VlanFilter.vid(200))
 *     .ip4()
 *     .esp()
 *     .srcNet("10.0.0.0/8")
 * // "(vlan 100 or vlan 200) and ip and ip proto 50 and src net 10.0.0.0/8"
 * }
 *
 * <h2>Protocol Filters</h2>
 * <p>
 * Each protocol header has a dedicated filter interface with an outer factory
 * type and an inner builder type. The outer type provides static convenience
 * methods; the inner builder enables fluent field chaining:
 * </p>
 * <ul>
 * <li>{@link EthernetFilter} — MAC addresses, EtherType</li>
 * <li>{@link VlanFilter} — 802.1Q VID, PCP, DEI, TPID</li>
 * <li>{@link Ip4Filter} — IPv4 addresses, protocol, TTL</li>
 * <li>{@link Ip6Filter} — IPv6 addresses, Next Header, Hop Limit, Flow
 * Label</li>
 * <li>{@link TcpFilter} — ports, flags (SYN, ACK, FIN, RST, composite)</li>
 * <li>{@link UdpFilter} — ports</li>
 * <li>{@link IpSecFilter} — ESP/AH SPI and Sequence Number</li>
 * <li>{@link MplsFilter} — label, Traffic Class, Bottom of Stack, TTL</li>
 * </ul>
 *
 * <h2>Network Primitives</h2>
 * <p>
 * Higher-level primitives are available directly on {@link PacketFilter} and
 * {@link PacketDsl} without requiring a specific protocol scope:
 * </p>
 * <ul>
 * <li>{@code host()} / {@code srcHost()} / {@code dstHost()} — IP address
 * matching</li>
 * <li>{@code net()} / {@code srcNet()} / {@code dstNet()} — CIDR subnet
 * matching</li>
 * <li>{@code port()} / {@code portRange()} — transport port matching (TCP or
 * UDP)</li>
 * <li>{@code lengthGreater()} / {@code lengthLess()} — packet size
 * filtering</li>
 * <li>{@code broadcast()} / {@code multicast()} — traffic type matching</li>
 * </ul>
 *
 * <h2>Validation</h2>
 * <p>
 * All field values are validated at construction time against their protocol
 * specifications. Invalid values throw {@link FilterException} immediately,
 * before any backend compilation occurs. The {@link HeaderOperator} functional
 * interface propagates checked exceptions through lambda expressions.
 * </p>
 *
 * <h2>Supported Backends</h2>
 * <table>
 * <caption>Backend compilation targets</caption>
 * <tr>
 * <th>Builder</th>
 * <th>Compiled Filter</th>
 * <th>Target</th>
 * <th>Use Case</th>
 * </tr>
 * <tr>
 * <td>{@code BpfFilterBuilder}</td>
 * <td>{@code PcapPacketFilter}</td>
 * <td>libpcap BPF</td>
 * <td>Software packet capture</td>
 * </tr>
 * <tr>
 * <td>{@code RteFlowBuilder}</td>
 * <td>{@code DpdkPacketFilter}</td>
 * <td>DPDK rte_flow</td>
 * <td>NIC hardware offload</td>
 * </tr>
 * <tr>
 * <td>{@code RteFlowBuilder}</td>
 * <td>{@code DpdkPacketFilter}</td>
 * <td>DPDK eBPF</td>
 * <td>Software fallback for complex filters</td>
 * </tr>
 * <tr>
 * <td>{@code NtplFilterBuilder}</td>
 * <td>{@code NtapiPacketFilter}</td>
 * <td>Napatech NTPL</td>
 * <td>SmartNIC hardware offload</td>
 * </tr>
 * </table>
 *
 ** <h2>Catch-All Filter</h2>
 * <p>
 * Use {@link PacketFilter#all()} when no filtering is desired. Some backends
 * (notably Napatech NTPL) require an explicit accept-all directive; without it,
 * all packets are dropped. Other backends (libpcap, DPDK) treat catch-all as a
 * no-op — no native filter is installed.
 * </p>
 *
 * {@snippet :
 * // Required for NTPL, safe for all backends
 * PacketDsl dsl = PacketFilter.all();
 * PacketFilter filter = builder.build(dsl);
 *
 * if (!filter.isCatchAll()) {
 * 	// install native filter
 * }
 * }
 * <p>
 * The catch-all filter must not be combined with other filters or used inside
 * {@link PacketDsl#anyOf(PacketDsl...)}. Attempting to do so throws
 * {@link FilterException} at construction time.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see PacketFilter
 * @see PacketDsl
 * @see Emitter
 * @see FilterException
 */
package com.slytechs.sdk.protocol.core.filter;