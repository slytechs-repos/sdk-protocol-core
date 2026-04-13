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
 * Factory and builder interface for constructing IPsec (AH and ESP) filter expressions.
 * <p>
 * This interface supports filtering on core fields of the two main IPsec protocols:
 * <ul>
 *   <li>ESP (Encapsulating Security Payload) — IP Protocol 50 (RFC 4303)</li>
 *   <li>AH (Authentication Header) — IP Protocol 51 (RFC 4302)</li>
 * </ul>
 * Both protocols share similar header structures for SPI (Security Parameters Index) and Sequence Number fields.
 * </p>
 * <p>
 * All setter methods perform input validation according to RFC 4303 (ESP) and RFC 4302 (AH):
 * <ul>
 *   <li>SPI: 0–4,294,967,295 (32 bits, unsigned); value 0 is reserved for local use and MUST NOT be sent on the wire; 1–255 are reserved by IANA for future use</li>
 *   <li>Sequence Number: 0–4,294,967,295 (32 bits, unsigned); monotonically increasing per SA for anti-replay protection (extended 64-bit ESN mode exists but only low 32 bits are transmitted)</li>
 * </ul>
 * Any value outside the valid 32-bit unsigned range throws a {@link FilterException}.
 * </p>
 * <p>
 * <strong>Notes:</strong>
 * <ul>
 *   <li>SPI identifies the Security Association (SA) and is combined with destination IP (and optionally source IP) to look up the SA.</li>
 *   <li>Sequence Number provides anti-replay protection; sender increments it per packet; receiver checks against a window.</li>
 *   <li>ESP encrypts payload and may include authentication (ICV); AH only authenticates (no encryption).</li>
 *   <li>This builder targets the fixed parts of AH/ESP headers; it does not cover encrypted payload, ICV, padding, or extension headers.</li>
 *   <li>Common practice: SPI values often start from 256 or higher to avoid reserved range; sequence starts at 0 or 1.</li>
 * </ul>
 * </p>
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Single condition (convenience)
 * IpSecDsl filter1 = IpSecFilter.espSpi(0x12345678L);
 *
 * // Combined ESP conditions
 * IpSecDsl filter2 = IpSecFilter.of()
 *     .espSpi(0xABCDEF01L)
 *     .espSeq(1000L);
 *
 * // AH example
 * IpSecDsl filter3 = IpSecFilter.ahSpi(0x00001000L)
 *     .ahSeq(500L);
 *
 * // Chained with validation
 * IpSecDsl filter4 = IpSecFilter.espSpi(256L)   // Avoid reserved low values
 *     .espSeq(1L);
 * }</pre>
 */
public interface IpSecFilter {

    /**
     * Creates an empty IPsec builder (no conditions).
     *
     * @return a new {@link IpSecDsl} instance with no filters applied
     */
    static IpSecDsl of() {
        return b -> b;
    }

    /**
     * Creates an IPsec filter that matches a specific ESP Security Parameters Index (SPI).
     *
     * @param spi ESP SPI value (must be 0–4294967295)
     * @return a {@link IpSecDsl} configured with the ESP SPI condition
     * @throws FilterException if spi is not in the range 0–4294967295
     */
    static IpSecDsl espSpi(long spi) throws FilterException {
        if (spi < 0 || spi > 0xFFFFFFFFL) {
            throw new FilterException("ESP SPI must be 0-4294967295 (0xFFFFFFFF), got: " + spi);
        }
        return of().espSpi(spi);
    }

    /**
     * Creates an IPsec filter that matches a specific AH Security Parameters Index (SPI).
     *
     * @param spi AH SPI value (must be 0–4294967295)
     * @return a {@link IpSecDsl} configured with the AH SPI condition
     * @throws FilterException if spi is not in the range 0–4294967295
     */
    static IpSecDsl ahSpi(long spi) throws FilterException {
        if (spi < 0 || spi > 0xFFFFFFFFL) {
            throw new FilterException("AH SPI must be 0-4294967295 (0xFFFFFFFF), got: " + spi);
        }
        return of().ahSpi(spi);
    }

    /**
     * Fluent builder interface for constructing complex IPsec (AH/ESP) filter expressions.
     * <p>
     * Each method adds an equality condition on the corresponding IPsec header field and returns
     * a new builder instance for method chaining.
     * </p>
     * <p>
     * All methods perform the same range validation as their static counterparts.
     * </p>
     */
    interface IpSecDsl extends HeaderDsl {

        /**
         * Adds a condition that the ESP Security Parameters Index (SPI) field must equal the given value.
         *
         * @param spi ESP SPI value (32 bits, 0–4294967295)
         * @return this builder for chaining
         * @throws FilterException if spi is not in the range 0–4294967295
         */
        default IpSecDsl espSpi(long spi) throws FilterException {
            if (spi < 0 || spi > 0xFFFFFFFFL) {
                throw new FilterException("ESP SPI must be 0-4294967295 (0xFFFFFFFF), got: " + spi);
            }
            return b -> this.emit(b).and().field("esp.spi", 0, 32, Op.EQ, spi);
        }

        /**
         * Adds a condition that the ESP Sequence Number field must equal the given value.
         *
         * @param seq ESP Sequence Number value (32 bits, 0–4294967295)
         * @return this builder for chaining
         * @throws FilterException if seq is not in the range 0–4294967295
         */
        default IpSecDsl espSeq(long seq) throws FilterException {
            if (seq < 0 || seq > 0xFFFFFFFFL) {
                throw new FilterException("ESP Sequence Number must be 0-4294967295 (0xFFFFFFFF), got: " + seq);
            }
            return b -> this.emit(b).and().field("esp.seq", 4, 32, Op.EQ, seq);
        }

        /**
         * Adds a condition that the AH Security Parameters Index (SPI) field must equal the given value.
         *
         * @param spi AH SPI value (32 bits, 0–4294967295)
         * @return this builder for chaining
         * @throws FilterException if spi is not in the range 0–4294967295
         */
        default IpSecDsl ahSpi(long spi) throws FilterException {
            if (spi < 0 || spi > 0xFFFFFFFFL) {
                throw new FilterException("AH SPI must be 0-4294967295 (0xFFFFFFFF), got: " + spi);
            }
            return b -> this.emit(b).and().field("ah.spi", 4, 32, Op.EQ, spi);
        }

        /**
         * Adds a condition that the AH Sequence Number field must equal the given value.
         *
         * @param seq AH Sequence Number value (32 bits, 0–4294967295)
         * @return this builder for chaining
         * @throws FilterException if seq is not in the range 0–4294967295
         */
        default IpSecDsl ahSeq(long seq) throws FilterException {
            if (seq < 0 || seq > 0xFFFFFFFFL) {
                throw new FilterException("AH Sequence Number must be 0-4294967295 (0xFFFFFFFF), got: " + seq);
            }
            return b -> this.emit(b).and().field("ah.seq", 8, 32, Op.EQ, seq);
        }
    }
}