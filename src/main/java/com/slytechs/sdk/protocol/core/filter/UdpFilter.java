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

import com.slytechs.sdk.protocol.core.filter.FilterBuilder.Op;

/**
 * Factory and builder interface for constructing UDP (User Datagram Protocol) filter expressions.
 * <p>
 * This interface provides both static convenience methods for creating simple UDP filters
 * and a fluent builder pattern for combining multiple UDP header field conditions (source port,
 * destination port, or either port matching the same value).
 * </p>
 * <p>
 * All port-related setter methods perform input validation according to RFC 768 (UDP) and RFC 6335:
 * <ul>
 *   <li>Ports: 0–65535 (16 bits, unsigned); 0 is valid (unspecified/ephemeral)</li>
 * </ul>
 * Ports are divided into ranges (per IANA/RFC 6335):
 * <ul>
 *   <li>0–1023: System Ports (well-known, often require elevated privileges)</li>
 *   <li>1024–49151: User Ports (registered services)</li>
 *   <li>49152–65535: Dynamic/Private/Ephemeral Ports</li>
 * </ul>
 * Any value outside 0–65535 throws a {@link FilterException}.
 * </p>
 * <p>
 * <strong>Notes:</strong>
 * <ul>
 *   <li>The {@code port(int)} method matches either source or destination port (logical OR).</li>
 *   <li>UDP ports are not always required; port 0 indicates "no specific port" or is used for ephemeral selection.</li>
 *   <li>Common UDP ports: 53 (DNS), 67/68 (DHCP), 123 (NTP), 161 (SNMP), etc.</li>
 *   <li>This builder focuses on core UDP header fields (source/destination ports); checksum and length are not filtered here.</li>
 * </ul>
 * </p>
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Single condition (convenience)
 * UdpBuilder filter1 = UdpFilter.srcPort(53);  // DNS
 *
 * // Combined conditions (fluent builder)
 * UdpBuilder filter2 = UdpFilter.of()
 *     .srcPort(123)
 *     .dstPort(123);  // NTP
 *
 * // Match either source or destination port
 * UdpBuilder filter3 = UdpFilter.port(161);  // SNMP
 *
 * // Chained with validation
 * UdpBuilder filter4 = UdpFilter.srcPort(0)   // ephemeral source
 *     .dstPort(53);
 * }</pre>
 */
public interface UdpFilter {

    /**
     * Creates an empty UDP builder (no conditions).
     *
     * @return a new {@link UdpBuilder} instance with no filters applied
     */
    static UdpBuilder of() {
        return b -> b;
    }

    /**
     * Creates a UDP filter that matches a specific source port.
     *
     * @param port source port number (must be 0–65535)
     * @return a {@link UdpBuilder} configured with the source port condition
     * @throws FilterException if port is not in the range 0–65535
     */
    static UdpBuilder srcPort(int port) throws FilterException {
        if (port < 0 || port > 65535) {
            throw new FilterException("UDP port must be 0-65535, got: " + port);
        }
        return of().srcPort(port);
    }

    /**
     * Creates a UDP filter that matches a specific destination port.
     *
     * @param port destination port number (must be 0–65535)
     * @return a {@link UdpBuilder} configured with the destination port condition
     * @throws FilterException if port is not in the range 0–65535
     */
    static UdpBuilder dstPort(int port) throws FilterException {
        if (port < 0 || port > 65535) {
            throw new FilterException("UDP port must be 0-65535, got: " + port);
        }
        return of().dstPort(port);
    }

    /**
     * Creates a UDP filter that matches packets where either the source or destination port equals the given value.
     *
     * @param port port number to match on source or destination (must be 0–65535)
     * @return a {@link UdpBuilder} configured with the OR condition on ports
     * @throws FilterException if port is not in the range 0–65535
     */
    static UdpBuilder port(int port) throws FilterException {
        if (port < 0 || port > 65535) {
            throw new FilterException("UDP port must be 0-65535, got: " + port);
        }
        return of().port(port);
    }

    /**
     * Fluent builder interface for constructing complex UDP filter expressions.
     * <p>
     * Each method adds an equality condition on the corresponding UDP header field (or logical OR for {@code port()})
     * and returns a new builder instance for method chaining.
     * </p>
     * <p>
     * All methods perform the same range validation as their static counterparts.
     * </p>
     */
    interface UdpBuilder extends HeaderFilter {

        /**
         * Adds a condition that the source port field must equal the given value.
         *
         * @param port source port number (16 bits, 0–65535)
         * @return this builder for chaining
         * @throws FilterException if port is not in the range 0–65535
         */
        default UdpBuilder srcPort(int port) throws FilterException {
            if (port < 0 || port > 65535) {
                throw new FilterException("UDP port must be 0-65535, got: " + port);
            }
            return b -> this.emit(b).and().field("udp.srcPort", 0, 16, Op.EQ, port);
        }

        /**
         * Adds a condition that the destination port field must equal the given value.
         *
         * @param port destination port number (16 bits, 0–65535)
         * @return this builder for chaining
         * @throws FilterException if port is not in the range 0–65535
         */
        default UdpBuilder dstPort(int port) throws FilterException {
            if (port < 0 || port > 65535) {
                throw new FilterException("UDP port must be 0-65535, got: " + port);
            }
            return b -> this.emit(b).and().field("udp.dstPort", 2, 16, Op.EQ, port);
        }

        /**
         * Adds a grouped condition that either the source port or destination port must equal the given value.
         *
         * @param port port number to match on source or destination (16 bits, 0–65535)
         * @return this builder for chaining
         * @throws FilterException if port is not in the range 0–65535
         */
        default UdpBuilder port(int port) throws FilterException {
            if (port < 0 || port > 65535) {
                throw new FilterException("UDP port must be 0-65535, got: " + port);
            }
            return b -> this.emit(b)
                    .and()
                    .group()
                    .field("udp.srcPort", 0, 16, Op.EQ, port)
                    .or()
                    .field("udp.dstPort", 2, 16, Op.EQ, port)
                    .endGroup();
        }
    }
}