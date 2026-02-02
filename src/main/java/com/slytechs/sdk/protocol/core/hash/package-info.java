/*
 * Apache License, Version 2.0
 * 
 * Copyright 2025 Sly Technologies Inc.
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
 * Packet hash calculation for channel distribution.
 * 
 * <p>This package provides hash calculation utilities for distributing packets
 * across multiple channels. Hash-based distribution ensures that packets
 * belonging to the same flow (identified by tuple fields) are consistently
 * routed to the same channel, enabling parallel processing while maintaining
 * flow affinity.
 * 
 * <h2>Hash Types</h2>
 * 
 * <p>The following hash types are supported:
 * 
 * <table border="1">
 * <caption>Supported Hash Types</caption>
 * <tr><th>Type</th><th>Fields</th><th>Use Case</th></tr>
 * <tr><td>ROUND_ROBIN</td><td>None</td><td>Equal distribution without flow affinity</td></tr>
 * <tr><td>HASH_2_TUPLE</td><td>Src IP, Dst IP</td><td>Basic flow distribution</td></tr>
 * <tr><td>HASH_5_TUPLE</td><td>Src IP, Dst IP, Src Port, Dst Port, Protocol</td><td>Full flow identification</td></tr>
 * <tr><td>HASH_INNER_*</td><td>Inner packet fields</td><td>Tunneled traffic (GRE, VXLAN, GTP)</td></tr>
 * <tr><td>HASH_3_TUPLE_GTP</td><td>Src IP, Dst IP, TEID</td><td>Mobile/telco GTP traffic</td></tr>
 * <tr><td>HASH_*_MPLS</td><td>MPLS labels</td><td>MPLS networks</td></tr>
 * <tr><td>HASH_*_VLAN</td><td>VLAN IDs</td><td>VLAN-based distribution</td></tr>
 * </table>
 * 
 * <h2>Sorted Variants</h2>
 * 
 * <p>Sorted hash types (e.g., {@code HASH_5_TUPLE_SORTED}) normalize field order
 * before hashing, ensuring that packets in both directions of a bidirectional
 * flow produce the same hash value. This is essential for stateful processing
 * where both directions must be handled by the same worker.
 * 
 * <h2>Usage</h2>
 * 
 * <pre>{@code
 * // Get a calculator for 5-tuple sorted hashing
 * HashCalculator calc = HashCalculator.of(HashTypes.HASH_5_TUPLE_SORTED);
 * 
 * // Calculate hash from ByteBuffer (uses position/limit)
 * int hash = calc.calculate(packetBuffer);
 * 
 * // Calculate hash from MemorySegment with offset
 * int hash = calc.calculate(segment, packetOffset);
 * 
 * // Distribute to channel
 * int channelIndex = Math.abs(hash) % numChannels;
 * }</pre>
 * 
 * <h2>Performance</h2>
 * 
 * <p>Calculators are designed for high-speed packet processing:
 * <ul>
 *   <li>Pre-allocated internal arrays (no allocation per packet)</li>
 *   <li>Direct field extraction from packet headers</li>
 *   <li>Efficient XOR-based hash mixing</li>
 *   <li>VLAN tag skipping handled automatically</li>
 *   <li>Tunnel header parsing for inner packet hashing</li>
 * </ul>
 * 
 * <h2>Type/Info Pattern</h2>
 * 
 * <p>This package follows the jNetWorks Type/Info pattern:
 * <ul>
 *   <li>{@link com.slytechs.sdk.protocol.core.hash.HashTypes} - Interface with integer
 *       constants for use in switch statements and hot paths</li>
 *   <li>{@link com.slytechs.sdk.protocol.core.hash.HashInfo} - Enum implementing
 *       HashTypes for API usage, toString, and conversion</li>
 * </ul>
 * 
 * <pre>{@code
 * // Use constant for hot path
 * int type = HashTypes.HASH_5_TUPLE;
 * 
 * // Use enum for API
 * HashInfo info = HashInfo.HASH_5_TUPLE;
 * 
 * // Convert between them
 * HashInfo info = HashInfo.valueOf(HashTypes.HASH_5_TUPLE);
 * int id = info.id();
 * }</pre>
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
package com.slytechs.sdk.protocol.core.hash;