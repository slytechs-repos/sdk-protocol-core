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
 * Factory and builder interface for constructing TCP (Transmission Control Protocol) filter expressions.
 * <p>
 * This interface provides both static convenience methods for creating simple TCP filters
 * and a fluent builder pattern for combining multiple TCP header field conditions (source/destination port,
 * either port matching, composite flags value, or individual flag checks).
 * </p>
 * <p>
 * All port-related and flags-related setter methods perform input validation according to RFC 9293 (TCP):
 * <ul>
 *   <li>Ports: 0–65535 (16 bits, unsigned); same IANA ranges as UDP</li>
 *   <li>Flags (composite): 0–255 (8 bits); but only bits 0–7 are defined (CWR,ECE,URG,ACK,PSH,RST,SYN,FIN)</li>
 *   <li>Individual flags: set via dedicated methods (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04, etc.) using MASK operator</li>
 * </ul>
 * Any invalid value throws a {@link FilterException}.
 * </p>
 * <p>
 * <strong>Notes:</strong>
 * <ul>
 *   <li>The {@code port(int)} method matches either source or destination port (logical OR).</li>
 *   <li>{@code flags(int)} matches the exact 8-bit flags value (all bits must match).</li>
 *   <li>Individual flag methods (e.g. {@code flagSyn()}) check only that specific flag bit is set (using MASK operator).</li>
 *   <li>Common TCP ports: 80/443 (HTTP/HTTPS), 22 (SSH), 25 (SMTP), 53 (DNS over TCP), etc.</li>
 *   <li>TCP flags bits (per RFC 9293): bit 0=FIN, 1=SYN, 2=RST, 3=PSH, 4=ACK, 5=URG, 6=ECE, 7=CWR</li>
 *   <li>This builder focuses on core fields; sequence/ack numbers, window, options, etc., are not included.</li>
 * </ul>
 * </p>
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Single condition (convenience)
 * TcpDsl filter1 = TcpFilter.dstPort(443);  // HTTPS
 *
 * // SYN-ACK packet
 * TcpDsl filter2 = TcpFilter.of()
 *     .flagSyn()
 *     .flagAck();
 *
 * // Match either port (e.g. any side of SSH connection)
 * TcpDsl filter3 = TcpFilter.port(22);
 *
 * // Exact flags match (e.g. only RST set)
 * TcpDsl filter4 = TcpFilter.flags(0x04);
 *
 * // Chained with validation
 * TcpDsl filter5 = TcpFilter.srcPort(1024)
 *     .dstPort(80)
 *     .flagFin();
 * }</pre>
 */
public interface TcpFilter {

    /**
     * Creates an empty TCP builder (no conditions).
     *
     * @return a new {@link TcpDsl} instance with no filters applied
     */
    static TcpDsl of() {
        return b -> b;
    }

    /**
     * Creates a TCP filter that matches a specific source port.
     *
     * @param port source port number (must be 0–65535)
     * @return a {@link TcpDsl} configured with the source port condition
     * @throws FilterException if port is not in the range 0–65535
     */
    static TcpDsl srcPort(int port) throws FilterException {
        if (port < 0 || port > 65535) {
            throw new FilterException("TCP port must be 0-65535, got: " + port);
        }
        return of().srcPort(port);
    }

    /**
     * Creates a TCP filter that matches a specific destination port.
     *
     * @param port destination port number (must be 0–65535)
     * @return a {@link TcpDsl} configured with the destination port condition
     * @throws FilterException if port is not in the range 0–65535
     */
    static TcpDsl dstPort(int port) throws FilterException {
        if (port < 0 || port > 65535) {
            throw new FilterException("TCP port must be 0-65535, got: " + port);
        }
        return of().dstPort(port);
    }

    /**
     * Creates a TCP filter that matches packets where either the source or destination port equals the given value.
     *
     * @param port port number to match on source or destination (must be 0–65535)
     * @return a {@link TcpDsl} configured with the OR condition on ports
     * @throws FilterException if port is not in the range 0–65535
     */
    static TcpDsl port(int port) throws FilterException {
        if (port < 0 || port > 65535) {
            throw new FilterException("TCP port must be 0-65535, got: " + port);
        }
        return of().port(port);
    }

    /**
     * Creates a TCP filter that matches an exact 8-bit TCP flags value.
     * <p>
     * Use for matching specific flag combinations (e.g., 0x12 = SYN+ACK).
     * For checking individual flags, prefer the dedicated flag methods.
     * </p>
     *
     * @param flags exact 8-bit flags value (0–255)
     * @return a {@link TcpDsl} configured with the exact flags condition
     * @throws FilterException if flags is not in the range 0–255
     */
    static TcpDsl flags(int flags) throws FilterException {
        if (flags < 0 || flags > 255) {
            throw new FilterException("TCP flags must be 0-255, got: " + flags);
        }
        return of().flags(flags);
    }

    /**
     * Creates a TCP filter that matches packets with the SYN flag set.
     *
     * @return a {@link TcpDsl} configured with SYN=1 condition
     */
    static TcpDsl flagSyn() {
        return of().flagSyn();
    }

    /**
     * Creates a TCP filter that matches packets with the ACK flag set.
     *
     * @return a {@link TcpDsl} configured with ACK=1 condition
     */
    static TcpDsl flagAck() {
        return of().flagAck();
    }

    /**
     * Creates a TCP filter that matches packets with the FIN flag set.
     *
     * @return a {@link TcpDsl} configured with FIN=1 condition
     */
    static TcpDsl flagFin() {
        return of().flagFin();
    }

    /**
     * Creates a TCP filter that matches packets with the RST flag set.
     *
     * @return a {@link TcpDsl} configured with RST=1 condition
     */
    static TcpDsl flagRst() {
        return of().flagRst();
    }

    /**
     * Fluent builder interface for constructing complex TCP filter expressions.
     * <p>
     * Each method adds an equality or mask condition on the corresponding TCP header field.
     * </p>
     * <p>
     * All methods perform the same validation as their static counterparts.
     * </p>
     */
    interface TcpDsl extends HeaderDsl {

        /**
         * Adds a condition that the source port field must equal the given value.
         *
         * @param port source port number (16 bits, 0–65535)
         * @return this builder for chaining
         * @throws FilterException if port is not in the range 0–65535
         */
        default TcpDsl srcPort(int port) throws FilterException {
            if (port < 0 || port > 65535) {
                throw new FilterException("TCP port must be 0-65535, got: " + port);
            }
            return b -> this.emit(b).and().field("tcp.srcPort", 0, 16, Op.EQ, port);
        }

        /**
         * Adds a condition that the destination port field must equal the given value.
         *
         * @param port destination port number (16 bits, 0–65535)
         * @return this builder for chaining
         * @throws FilterException if port is not in the range 0–65535
         */
        default TcpDsl dstPort(int port) throws FilterException {
            if (port < 0 || port > 65535) {
                throw new FilterException("TCP port must be 0-65535, got: " + port);
            }
            return b -> this.emit(b).and().field("tcp.dstPort", 2, 16, Op.EQ, port);
        }

        /**
         * Adds a grouped condition that either the source port or destination port must equal the given value.
         *
         * @param port port number to match on source or destination (16 bits, 0–65535)
         * @return this builder for chaining
         * @throws FilterException if port is not in the range 0–65535
         */
        default TcpDsl port(int port) throws FilterException {
            if (port < 0 || port > 65535) {
                throw new FilterException("TCP port must be 0-65535, got: " + port);
            }
            return b -> this.emit(b)
                    .and()
                    .group()
                    .field("tcp.srcPort", 0, 16, Op.EQ, port)
                    .or()
                    .field("tcp.dstPort", 2, 16, Op.EQ, port)
                    .endGroup();
        }

        /**
         * Adds a condition that the flags field must equal the given 8-bit value exactly.
         *
         * @param flags exact flags value (8 bits, 0–255)
         * @return this builder for chaining
         * @throws FilterException if flags is not in the range 0–255
         */
        default TcpDsl flags(int flags) throws FilterException {
            if (flags < 0 || flags > 255) {
                throw new FilterException("TCP flags must be 0-255, got: " + flags);
            }
            return b -> this.emit(b).and().field("tcp.flags", 13, 8, Op.EQ, flags);
        }

        /**
         * Adds a condition that the SYN flag bit must be set.
         *
         * @return this builder for chaining
         */
        default TcpDsl flagSyn() {
            return b -> this.emit(b).and().field("tcp.flags.syn", 13, 8, Op.MASK, 0x02);
        }

        /**
         * Adds a condition that the ACK flag bit must be set.
         *
         * @return this builder for chaining
         */
        default TcpDsl flagAck() {
            return b -> this.emit(b).and().field("tcp.flags.ack", 13, 8, Op.MASK, 0x10);
        }

        /**
         * Adds a condition that the FIN flag bit must be set.
         *
         * @return this builder for chaining
         */
        default TcpDsl flagFin() {
            return b -> this.emit(b).and().field("tcp.flags.fin", 13, 8, Op.MASK, 0x01);
        }

        /**
         * Adds a condition that the RST flag bit must be set.
         *
         * @return this builder for chaining
         */
        default TcpDsl flagRst() {
            return b -> this.emit(b).and().field("tcp.flags.rst", 13, 8, Op.MASK, 0x04);
        }
    }
}