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

import com.slytechs.sdk.protocol.core.filter.FilterDsl.Emitter.Op;

/**
 * Factory and builder interface for constructing Ethernet (IEEE 802.3 / Ethernet II) filter expressions.
 * <p>
 * This interface provides both static convenience methods for creating simple single-condition Ethernet filters
 * and a fluent builder pattern for combining multiple Ethernet field conditions (destination MAC, source MAC, EtherType/length).
 * </p>
 * <p>
 * All setter methods perform input validation according to the Ethernet specification:
 * <ul>
 *   <li>Destination/Source MAC: 6-byte array (48 bits); must not be null and exactly 6 bytes long</li>
 *   <li>EtherType/Length: 0–65535 (16 bits, unsigned)</li>
 * </ul>
 * Any invalid input throws a {@link FilterException}.
 * </p>
 * <p>
 * <strong>Note on EtherType/Length interpretation:</strong>
 * <ul>
 *   <li>If the value ≤ 1500 (0x05DC), it is interpreted as the payload length (IEEE 802.3 format)</li>
 *   <li>If the value ≥ 1536 (0x0600), it is interpreted as an EtherType (Ethernet II format), identifying the encapsulated protocol</li>
 *   <li>Values 1501–1535 (0x05DD–0x05FF) are reserved/invalid</li>
 * </ul>
 * Common EtherType values include:
 * <ul>
 *   <li>0x0800 (IPv4)</li>
 *   <li>0x0806 (ARP)</li>
 *   <li>0x86DD (IPv6)</li>
 *   <li>0x8100 (802.1Q VLAN tag)</li>
 *   <li>0x88A8 (802.1ad / Q-in-Q)</li>
 * </ul>
 * This interface does not enforce restrictions on reserved values, as they may be valid in some filter contexts.
 * </p>
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Single condition (convenience)
 * EthernetDsl filter1 = EthernetFilter.dst(new byte[] {(byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55});
 *
 * // Combined conditions (fluent builder)
 * EthernetDsl filter2 = EthernetFilter.of()
 *     .src(new byte[] {(byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0xFF})
 *     .type(0x0800);  // IPv4
 *
 * // Chained with validation
 * EthernetDsl filter3 = EthernetFilter.src(new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF})  // Broadcast
 *     .type(0x0806);  // ARP
 * }</pre>
 */
public interface EthernetFilter {

    /**
     * Creates an empty Ethernet builder (no conditions).
     *
     * @return a new {@link EthernetDsl} instance with no filters applied
     */
    static EthernetDsl of() {
        return b -> b;
    }

    /**
     * Creates an Ethernet filter that matches a specific destination MAC address.
     *
     * @param mac the 6-byte destination MAC address
     * @return a {@link EthernetDsl} configured with the destination MAC condition
     * @throws FilterException if mac is null or not exactly 6 bytes long
     */
    static EthernetDsl dst(byte[] mac) throws FilterException {
        if (mac == null || mac.length != 6) {
            throw new FilterException("MAC address must be 6 bytes, got: " + mac.length);
        }
        return of().dst(mac);
    }

    /**
     * Creates an Ethernet filter that matches a specific source MAC address.
     *
     * @param mac the 6-byte source MAC address
     * @return a {@link EthernetDsl} configured with the source MAC condition
     * @throws FilterException if mac is null or not exactly 6 bytes long
     */
    static EthernetDsl src(byte[] mac) throws FilterException {
        if (mac == null || mac.length != 6) {
            throw new FilterException("MAC address must be 6 bytes, got: " + mac.length);
        }
        return of().src(mac);
    }

    /**
     * Creates an Ethernet filter that matches a specific EtherType (or length) value.
     * <p>
     * Common values: 0x0800 (IPv4), 0x0806 (ARP), 0x86DD (IPv6), 0x8100 (802.1Q VLAN).
     * </p>
     *
     * @param etherType the 16-bit EtherType/length value (must be 0–65535)
     * @return a {@link EthernetDsl} configured with the type condition
     * @throws FilterException if etherType is not in the range 0–65535
     */
    static EthernetDsl type(int etherType) throws FilterException {
        if (etherType < 0 || etherType > 65535) {
            throw new FilterException("EtherType/length must be 0-65535, got: " + etherType);
        }
        return of().type(etherType);
    }

    /**
     * Fluent builder interface for constructing complex Ethernet filter expressions.
     * <p>
     * Each method adds an equality condition on the corresponding Ethernet header field and returns
     * a new builder instance for method chaining.
     * </p>
     * <p>
     * All methods perform the same validation as their static counterparts.
     * </p>
     */
    interface EthernetDsl extends HeaderDsl {

        /**
         * Adds a condition that the destination MAC address field must equal the given value.
         *
         * @param mac 6-byte destination MAC address
         * @return this builder for chaining
         * @throws FilterException if mac is null or not exactly 6 bytes long
         */
        default EthernetDsl dst(byte[] mac) throws FilterException {
            if (mac == null || mac.length != 6) {
                throw new FilterException("MAC address must be 6 bytes, got: " + mac.length);
            }
            return b -> this.emit(b).and().field("eth.dst", 0, 48, Op.EQ, mac);
        }

        /**
         * Adds a condition that the source MAC address field must equal the given value.
         *
         * @param mac 6-byte source MAC address
         * @return this builder for chaining
         * @throws FilterException if mac is null or not exactly 6 bytes long
         */
        default EthernetDsl src(byte[] mac) throws FilterException {
            if (mac == null || mac.length != 6) {
                throw new FilterException("MAC address must be 6 bytes, got: " + mac.length);
            }
            return b -> this.emit(b).and().field("eth.src", 6, 48, Op.EQ, mac);
        }

        /**
         * Adds a condition that the EtherType/length field must equal the given value.
         *
         * @param etherType 16-bit EtherType/length value (0–65535)
         * @return this builder for chaining
         * @throws FilterException if etherType is not in the range 0–65535
         */
        default EthernetDsl type(int etherType) throws FilterException {
            if (etherType < 0 || etherType > 65535) {
                throw new FilterException("EtherType/length must be 0-65535, got: " + etherType);
            }
            return b -> this.emit(b).and().field("eth.type", 12, 16, Op.EQ, etherType);
        }
    }
}