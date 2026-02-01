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
 * Factory and builder interface for constructing MPLS (Multi-Protocol Label Switching) filter expressions.
 * <p>
 * This interface provides both static convenience methods for creating simple MPLS filters
 * and a fluent builder pattern for combining multiple MPLS label stack entry field conditions
 * (Label, Traffic Class/TC, Bottom of Stack/S bit, TTL).
 * </p>
 * <p>
 * All setter methods perform input validation according to RFC 3032 (MPLS Label Stack Encoding),
 * RFC 5462 (TC field renaming), and related standards:
 * <ul>
 *   <li>Label: 0–1,048,575 (20 bits); values 0–15 are reserved/special-purpose (e.g., 0=IPv4 Explicit NULL, 1=Router Alert, 3=Implicit NULL); 16–1,048,575 are usable for normal LSPs</li>
 *   <li>Traffic Class (TC, formerly EXP): 0–7 (3 bits); used for QoS/DiffServ mapping</li>
 *   <li>Bottom of Stack (S/BOS): 0 or 1 (1 bit); 1 indicates this is the last label in the stack</li>
 *   <li>TTL (Time to Live): 0–255 (8 bits); analogous to IP TTL/Hop Limit; 0 typically drops the packet</li>
 * </ul>
 * Any value outside the valid range throws a {@link FilterException}.
 * </p>
 * <p>
 * <strong>Notes:</strong>
 * <ul>
 *   <li>MPLS supports label stacking; filters here apply to a single label entry (shim header).</li>
 *   <li>Reserved labels (0–15) have special meanings and restrictions (e.g., Explicit NULL only valid at bottom of stack).</li>
 *   <li>TC field supports up to 8 traffic classes, often mapped to DiffServ PHBs (Per-Hop Behaviors).</li>
 *   <li>TTL is decremented at each LSR (Label Switching Router); behavior configurable (propagate, uniform model, etc.).</li>
 *   <li>This builder targets a single MPLS shim; for multi-label stacks or specific label positions, additional logic may be required outside this interface.</li>
 * </ul>
 * </p>
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Single condition (convenience)
 * MplsDsl filter1 = MplsFilter.label(100);  // Matches label 100
 *
 * // Combined conditions (fluent builder)
 * MplsDsl filter2 = MplsFilter.of()
 *     .label(50000)
 *     .trafficClass(5)      // High priority QoS
 *     .bottomOfStack()
 *     .ttl(64);
 *
 * // Bottom-of-stack only
 * MplsDsl filter3 = MplsFilter.bottomOfStack();
 *
 * // Chained with validation
 * MplsDsl filter4 = MplsFilter.label(16)   // First non-reserved label
 *     .trafficClass(0)
 *     .ttl(255);
 * }</pre>
 */
public interface MplsFilter {

    /**
     * Creates an empty MPLS builder (no conditions).
     *
     * @return a new {@link MplsDsl} instance with no filters applied
     */
    static MplsDsl of() {
        return b -> b;
    }

    /**
     * Creates an MPLS filter that matches a specific label value.
     * <p>
     * Valid range: 0–1,048,575 (0x00000–0xFFFFF). Values 0–15 are reserved/special-purpose.
     * </p>
     *
     * @param label MPLS label value (must be 0–1048575)
     * @return a {@link MplsDsl} configured with the label condition
     * @throws FilterException if label is not in the range 0–1048575
     */
    static MplsDsl label(int label) throws FilterException {
        if (label < 0 || label > 0xFFFFF) {
            throw new FilterException("MPLS label must be 0-1048575 (0xFFFFF), got: " + label);
        }
        return of().label(label);
    }

    /**
     * Creates an MPLS filter that matches a specific Traffic Class (TC, formerly EXP) value.
     *
     * @param tc Traffic Class value (must be 0–7)
     * @return a {@link MplsDsl} configured with the TC condition
     * @throws FilterException if tc is not in the range 0–7
     */
    static MplsDsl trafficClass(int tc) throws FilterException {
        if (tc < 0 || tc > 7) {
            throw new FilterException("MPLS Traffic Class (TC) must be 0-7, got: " + tc);
        }
        return of().trafficClass(tc);
    }

    /**
     * Creates an MPLS filter that matches when the Bottom of Stack (BOS/S bit) is set (1).
     *
     * @return a {@link MplsDsl} configured with BOS=1 condition
     */
    static MplsDsl bottomOfStack() {
        return of().bottomOfStack();
    }

    /**
     * Fluent builder interface for constructing complex MPLS filter expressions.
     * <p>
     * Each method adds an equality condition on the corresponding MPLS label stack entry field
     * and returns a new builder instance for method chaining.
     * </p>
     * <p>
     * All methods perform the same range validation as their static counterparts.
     * </p>
     */
    interface MplsDsl extends HeaderDsl {

        /**
         * Adds a condition that the MPLS label field must equal the given value.
         *
         * @param label MPLS label value (20 bits, 0–1048575)
         * @return this builder for chaining
         * @throws FilterException if label is not in the range 0–1048575
         */
        default MplsDsl label(int label) throws FilterException {
            if (label < 0 || label > 0xFFFFF) {
                throw new FilterException("MPLS label must be 0-1048575 (0xFFFFF), got: " + label);
            }
            return b -> this.emit(b).and().field("mpls.label", 0, 20, Op.EQ, label);
        }

        /**
         * Adds a condition that the Traffic Class (TC) field must equal the given value.
         *
         * @param tc Traffic Class value (3 bits, 0–7)
         * @return this builder for chaining
         * @throws FilterException if tc is not in the range 0–7
         */
        default MplsDsl trafficClass(int tc) throws FilterException {
            if (tc < 0 || tc > 7) {
                throw new FilterException("MPLS Traffic Class (TC) must be 0-7, got: " + tc);
            }
            return b -> this.emit(b).and().field("mpls.tc", 2, 3, Op.EQ, tc);
        }

        /**
         * Adds a condition that the Bottom of Stack (BOS/S bit) must be set (1).
         *
         * @return this builder for chaining
         */
        default MplsDsl bottomOfStack() {
            return b -> this.emit(b).and().field("mpls.bos", 2, 1, Op.EQ, 1);
        }

        /**
         * Adds a condition that the TTL field must equal the given value.
         *
         * @param ttl TTL value (8 bits, 0–255)
         * @return this builder for chaining
         * @throws FilterException if ttl is not in the range 0–255
         */
        default MplsDsl ttl(int ttl) throws FilterException {
            if (ttl < 0 || ttl > 255) {
                throw new FilterException("MPLS TTL must be 0-255, got: " + ttl);
            }
            return b -> this.emit(b).and().field("mpls.ttl", 3, 8, Op.EQ, ttl);
        }
    }
}