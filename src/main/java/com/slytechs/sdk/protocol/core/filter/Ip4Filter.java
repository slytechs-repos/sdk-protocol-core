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
 * Factory and builder interface for constructing IPv4 (Internet Protocol version 4) filter expressions.
 * <p>
 * This interface provides both static convenience methods for creating simple single-condition IPv4 filters
 * and a fluent builder pattern for combining multiple IPv4 header field conditions (source/destination address,
 * protocol, TTL).
 * </p>
 * <p>
 * All setter methods perform input validation according to RFC 791 and related standards:
 * <ul>
 *   <li>Source/Destination IP: either 4-byte array or 32-bit integer (big-endian network byte order); array must be exactly 4 bytes</li>
 *   <li>Protocol: 0–255 (8 bits, IANA-assigned protocol numbers; common: 1=ICMP, 6=TCP, 17=UDP, etc.)</li>
 *   <li>TTL (Time to Live): 0–255 (8 bits); typically 1–255 in practice (0 drops packet immediately)</li>
 * </ul>
 * Any invalid input throws a {@link FilterException}.
 * </p>
 * <p>
 * <strong>Notes:</strong>
 * <ul>
 *   <li>IPv4 addresses are represented in network byte order (big-endian) when using byte arrays.</li>
 *   <li>Common protocol values (per IANA): 1 (ICMP), 2 (IGMP), 6 (TCP), 17 (UDP), 41 (IPv6 encapsulation), 89 (OSPF), etc.</li>
 *   <li>TTL=0 is technically valid in the header but routers drop such packets; filters may still match them.</li>
 *   <li>This builder focuses on frequently filtered core fields; additional fields (e.g., DSCP/ECN, flags, fragment offset) are not included here.</li>
 * </ul>
 * </p>
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Single condition (convenience)
 * Ip4Dsl filter1 = Ip4Filter.src(0xC0A80101);  // 192.168.1.1
 *
 * // Using byte array
 * Ip4Dsl filter2 = Ip4Filter.dst(new byte[] {(byte)192, (byte)168, 1, 254});
 *
 * // Combined conditions (fluent builder)
 * Ip4Dsl filter3 = Ip4Filter.of()
 *     .src(new byte[] {(byte)10, 0, 0, 1})
 *     .protocol(6)   // TCP
 *     .ttl(64);
 *
 * // Chained with validation
 * Ip4Dsl filter4 = Ip4Filter.protocol(17)   // UDP
 *     .dst(0x08080808)  // 8.8.8.8
 *     .ttl(128);
 * }</pre>
 */
public interface Ip4Filter {

    /**
     * Creates an empty IPv4 builder (no conditions).
     *
     * @return a new {@link Ip4Dsl} instance with no filters applied
     */
    static Ip4Dsl of() {
        return b -> b;
    }

    /**
     * Creates an IPv4 filter that matches a specific source IP address (integer form).
     *
     * @param addr 32-bit source IPv4 address in network byte order (e.g., 0xC0A80101 for 192.168.1.1)
     * @return a {@link Ip4Dsl} configured with the source address condition
     */
    static Ip4Dsl src(int addr) {
        return of().src(addr);
    }

    /**
     * Creates an IPv4 filter that matches a specific source IP address (byte array form).
     *
     * @param addr 4-byte source IPv4 address
     * @return a {@link Ip4Dsl} configured with the source address condition
     * @throws FilterException if addr is null or not exactly 4 bytes long
     */
    static Ip4Dsl src(byte[] addr) throws FilterException {
        if (addr == null || addr.length != 4) {
            throw new FilterException("IPv4 address must be a 4-byte array");
        }
        return of().src(addr);
    }

    /**
     * Creates an IPv4 filter that matches a specific destination IP address (integer form).
     *
     * @param addr 32-bit destination IPv4 address in network byte order
     * @return a {@link Ip4Dsl} configured with the destination address condition
     */
    static Ip4Dsl dst(int addr) {
        return of().dst(addr);
    }

    /**
     * Creates an IPv4 filter that matches a specific destination IP address (byte array form).
     *
     * @param addr 4-byte destination IPv4 address
     * @return a {@link Ip4Dsl} configured with the destination address condition
     * @throws FilterException if addr is null or not exactly 4 bytes long
     */
    static Ip4Dsl dst(byte[] addr) throws FilterException {
        if (addr == null || addr.length != 4) {
            throw new FilterException("IPv4 address must be a 4-byte array");
        }
        return of().dst(addr);
    }

    /**
     * Creates an IPv4 filter that matches a specific IP protocol number.
     * <p>
     * Common values (per IANA): 1 (ICMP), 6 (TCP), 17 (UDP), 41 (IPv6), 89 (OSPF), etc.
     * </p>
     *
     * @param proto protocol number (must be 0–255)
     * @return a {@link Ip4Dsl} configured with the protocol condition
     * @throws FilterException if proto is not in the range 0–255
     */
    static Ip4Dsl protocol(int proto) throws FilterException {
        if (proto < 0 || proto > 255) {
            throw new FilterException("IP protocol number must be 0-255, got: " + proto);
        }
        return of().protocol(proto);
    }

    /**
     * Creates an IPv4 filter that matches a specific Time to Live (TTL) value.
     *
     * @param ttl TTL value (must be 0–255)
     * @return a {@link Ip4Dsl} configured with the TTL condition
     * @throws FilterException if ttl is not in the range 0–255
     */
    static Ip4Dsl ttl(int ttl) throws FilterException {
        if (ttl < 0 || ttl > 255) {
            throw new FilterException("TTL must be 0-255, got: " + ttl);
        }
        return of().ttl(ttl);
    }

    /**
     * Fluent builder interface for constructing complex IPv4 filter expressions.
     * <p>
     * Each method adds an equality condition on the corresponding IPv4 header field and returns
     * a new builder instance for method chaining.
     * </p>
     * <p>
     * All methods perform the same validation as their static counterparts.
     * </p>
     */
    interface Ip4Dsl extends HeaderDsl {

        /**
         * Adds a condition that the source IP address field must equal the given value (integer form).
         *
         * @param addr 32-bit source IPv4 address in network byte order
         * @return this builder for chaining
         */
        default Ip4Dsl src(int addr) {
            return b -> this.emit(b).and().field("ip4.src", 12, 32, Op.EQ, addr);
        }

        /**
         * Adds a condition that the source IP address field must equal the given value (byte array form).
         *
         * @param addr 4-byte source IPv4 address
         * @return this builder for chaining
         * @throws FilterException if addr is null or not exactly 4 bytes long
         */
        default Ip4Dsl src(byte[] addr) throws FilterException {
            if (addr == null || addr.length != 4) {
                throw new FilterException("IPv4 address must be a 4-byte array");
            }
            return b -> this.emit(b).and().field("ip4.src", 12, 32, Op.EQ, addr);
        }

        /**
         * Adds a condition that the destination IP address field must equal the given value (integer form).
         *
         * @param addr 32-bit destination IPv4 address in network byte order
         * @return this builder for chaining
         */
        default Ip4Dsl dst(int addr) {
            return b -> this.emit(b).and().field("ip4.dst", 16, 32, Op.EQ, addr);
        }

        /**
         * Adds a condition that the destination IP address field must equal the given value (byte array form).
         *
         * @param addr 4-byte destination IPv4 address
         * @return this builder for chaining
         * @throws FilterException if addr is null or not exactly 4 bytes long
         */
        default Ip4Dsl dst(byte[] addr) throws FilterException {
            if (addr == null || addr.length != 4) {
                throw new FilterException("IPv4 address must be a 4-byte array");
            }
            return b -> this.emit(b).and().field("ip4.dst", 16, 32, Op.EQ, addr);
        }

        /**
         * Adds a condition that the protocol field must equal the given value.
         *
         * @param proto protocol number (8 bits, 0–255)
         * @return this builder for chaining
         * @throws FilterException if proto is not in the range 0–255
         */
        default Ip4Dsl protocol(int proto) throws FilterException {
            if (proto < 0 || proto > 255) {
                throw new FilterException("IP protocol number must be 0-255, got: " + proto);
            }
            return b -> this.emit(b).and().field("ip4.proto", 9, 8, Op.EQ, proto);
        }

        /**
         * Adds a condition that the Time to Live (TTL) field must equal the given value.
         *
         * @param ttl TTL value (8 bits, 0–255)
         * @return this builder for chaining
         * @throws FilterException if ttl is not in the range 0–255
         */
        default Ip4Dsl ttl(int ttl) throws FilterException {
            if (ttl < 0 || ttl > 255) {
                throw new FilterException("TTL must be 0-255, got: " + ttl);
            }
            return b -> this.emit(b).and().field("ip4.ttl", 8, 8, Op.EQ, ttl);
        }
    }
}