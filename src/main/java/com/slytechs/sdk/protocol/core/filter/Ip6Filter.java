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
 * Factory and builder interface for constructing IPv6 (Internet Protocol version 6) filter expressions.
 * <p>
 * This interface provides both static convenience methods for creating simple single-condition IPv6 filters
 * and a fluent builder pattern for combining multiple IPv6 header field conditions (source/destination address,
 * Next Header, Hop Limit, Flow Label).
 * </p>
 * <p>
 * All setter methods perform input validation according to RFC 8200 (IPv6 Specification) and related standards:
 * <ul>
 *   <li>Source/Destination IP: exactly 16-byte array (128 bits)</li>
 *   <li>Next Header: 0–255 (8 bits, same IANA protocol numbers as IPv4; common: 6=TCP, 17=UDP, 58=ICMPv6, 0=Hop-by-Hop, 43=Routing, 44=Fragment, etc.)</li>
 *   <li>Hop Limit: 0–255 (8 bits); typically 64 or higher in practice (0 drops immediately)</li>
 *   <li>Flow Label: 0–1048575 (20 bits); 0 indicates no flow labeling</li>
 * </ul>
 * Any invalid input throws a {@link FilterException}.
 * </p>
 * <p>
 * <strong>Notes:</strong>
 * <ul>
 *   <li>IPv6 addresses are represented as 16-byte arrays in network byte order.</li>
 *   <li>Next Header uses the same values as IPv4 Protocol (see IANA Protocol Numbers); includes extension headers (e.g., 0=Hop-by-Hop, 44=Fragment) and upper-layer protocols (e.g., 6=TCP, 17=UDP, 58=ICMPv6).</li>
 *   <li>Flow Label is typically set randomly by the source for flow identification; value 0 means no specific flow.</li>
 *   <li>Hop Limit replaces IPv4 TTL; decremented by each forwarding node; often defaults to 64 (Linux) or 128 (Windows).</li>
 *   <li>This builder focuses on core fixed-header fields; extension headers (e.g., Hop-by-Hop options, Fragment) are not directly filtered here.</li>
 * </ul>
 * </p>
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Single condition (convenience)
 * Ip6Dsl filter1 = Ip6Filter.src(new byte[] {
 *     0x20, 0x01, 0x0d, (byte)0xb8, 0, 0, 0, 0, 0, 0, (byte)0xff, 0, 0, 0, 0, 0x01  // 2001:db8::ff00:0:1
 * });
 *
 * // Combined conditions (fluent builder)
 * Ip6Dsl filter2 = Ip6Filter.of()
 *     .dst(new byte[] { 0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x68 })  // example IPv6
 *     .nextHeader(17)  // UDP
 *     .hopLimit(64)
 *     .flowLabel(123456);
 *
 * // Chained with validation
 * Ip6Dsl filter3 = Ip6Filter.nextHeader(58)   // ICMPv6
 *     .hopLimit(128)
 *     .src(new byte[16]);  // all-zeroes address
 * }</pre>
 */
public interface Ip6Filter {

    /**
     * Creates an empty IPv6 builder (no conditions).
     *
     * @return a new {@link Ip6Dsl} instance with no filters applied
     */
    static Ip6Dsl of() {
        return b -> b;
    }

    /**
     * Creates an IPv6 filter that matches a specific source IPv6 address.
     *
     * @param addr 16-byte source IPv6 address (network byte order)
     * @return a {@link Ip6Dsl} configured with the source address condition
     * @throws FilterException if addr is null or not exactly 16 bytes long
     */
    static Ip6Dsl src(byte[] addr) throws FilterException {
        if (addr == null || addr.length != 16) {
            throw new FilterException("IPv6 address must be a 16-byte array");
        }
        return of().src(addr);
    }

    /**
     * Creates an IPv6 filter that matches a specific destination IPv6 address.
     *
     * @param addr 16-byte destination IPv6 address (network byte order)
     * @return a {@link Ip6Dsl} configured with the destination address condition
     * @throws FilterException if addr is null or not exactly 16 bytes long
     */
    static Ip6Dsl dst(byte[] addr) throws FilterException {
        if (addr == null || addr.length != 16) {
            throw new FilterException("IPv6 address must be a 16-byte array");
        }
        return of().dst(addr);
    }

    /**
     * Creates an IPv6 filter that matches a specific Next Header value.
     * <p>
     * Common values (per IANA): 0 (Hop-by-Hop), 6 (TCP), 17 (UDP), 43 (Routing), 44 (Fragment), 58 (ICMPv6), etc.
     * </p>
     *
     * @param protocol Next Header value (must be 0–255)
     * @return a {@link Ip6Dsl} configured with the Next Header condition
     * @throws FilterException if protocol is not in the range 0–255
     */
    static Ip6Dsl nextHeader(int protocol) throws FilterException {
        if (protocol < 0 || protocol > 255) {
            throw new FilterException("Next Header value must be 0-255, got: " + protocol);
        }
        return of().nextHeader(protocol);
    }

    /**
     * Creates an IPv6 filter that matches a specific Hop Limit value.
     *
     * @param limit Hop Limit value (must be 0–255)
     * @return a {@link Ip6Dsl} configured with the Hop Limit condition
     * @throws FilterException if limit is not in the range 0–255
     */
    static Ip6Dsl hopLimit(int limit) throws FilterException {
        if (limit < 0 || limit > 255) {
            throw new FilterException("Hop Limit must be 0-255, got: " + limit);
        }
        return of().hopLimit(limit);
    }

    /**
     * Creates an IPv6 filter that matches a specific Flow Label value.
     * <p>
     * Valid range: 0–1,048,575 (20 bits); 0 indicates no flow.
     * </p>
     *
     * @param label Flow Label value (must be 0–1048575)
     * @return a {@link Ip6Dsl} configured with the Flow Label condition
     * @throws FilterException if label is not in the range 0–1048575
     */
    static Ip6Dsl flowLabel(int label) throws FilterException {
        if (label < 0 || label > 0xFFFFF) {
            throw new FilterException("Flow Label must be 0-1048575 (0xFFFFF), got: " + label);
        }
        return of().flowLabel(label);
    }

    /**
     * Fluent builder interface for constructing complex IPv6 filter expressions.
     * <p>
     * Each method adds an equality condition on the corresponding IPv6 header field and returns
     * a new builder instance for method chaining.
     * </p>
     * <p>
     * All methods perform the same validation as their static counterparts.
     * </p>
     */
    interface Ip6Dsl extends HeaderDsl {

        /**
         * Adds a condition that the source IPv6 address field must equal the given value.
         *
         * @param addr 16-byte source IPv6 address (network byte order)
         * @return this builder for chaining
         * @throws FilterException if addr is null or not exactly 16 bytes long
         */
        default Ip6Dsl src(byte[] addr) throws FilterException {
            if (addr == null || addr.length != 16) {
                throw new FilterException("IPv6 address must be a 16-byte array");
            }
            return b -> this.emit(b).and().field("ip6.src", 8, 128, Op.EQ, addr);
        }

        /**
         * Adds a condition that the destination IPv6 address field must equal the given value.
         *
         * @param addr 16-byte destination IPv6 address (network byte order)
         * @return this builder for chaining
         * @throws FilterException if addr is null or not exactly 16 bytes long
         */
        default Ip6Dsl dst(byte[] addr) throws FilterException {
            if (addr == null || addr.length != 16) {
                throw new FilterException("IPv6 address must be a 16-byte array");
            }
            return b -> this.emit(b).and().field("ip6.dst", 24, 128, Op.EQ, addr);
        }

        /**
         * Adds a condition that the Next Header field must equal the given value.
         *
         * @param protocol Next Header value (8 bits, 0–255)
         * @return this builder for chaining
         * @throws FilterException if protocol is not in the range 0–255
         */
        default Ip6Dsl nextHeader(int protocol) throws FilterException {
            if (protocol < 0 || protocol > 255) {
                throw new FilterException("Next Header value must be 0-255, got: " + protocol);
            }
            return b -> this.emit(b).and().field("ip6.nextHeader", 6, 8, Op.EQ, protocol);
        }

        /**
         * Adds a condition that the Hop Limit field must equal the given value.
         *
         * @param limit Hop Limit value (8 bits, 0–255)
         * @return this builder for chaining
         * @throws FilterException if limit is not in the range 0–255
         */
        default Ip6Dsl hopLimit(int limit) throws FilterException {
            if (limit < 0 || limit > 255) {
                throw new FilterException("Hop Limit must be 0-255, got: " + limit);
            }
            return b -> this.emit(b).and().field("ip6.hopLimit", 7, 8, Op.EQ, limit);
        }

        /**
         * Adds a condition that the Flow Label field must equal the given value.
         *
         * @param label Flow Label value (20 bits, 0–1048575)
         * @return this builder for chaining
         * @throws FilterException if label is not in the range 0–1048575
         */
        default Ip6Dsl flowLabel(int label) throws FilterException {
            if (label < 0 || label > 0xFFFFF) {
                throw new FilterException("Flow Label must be 0-1048575 (0xFFFFF), got: " + label);
            }
            return b -> this.emit(b).and().field("ip6.flowLabel", 1, 20, Op.EQ, label);
        }
    }
}