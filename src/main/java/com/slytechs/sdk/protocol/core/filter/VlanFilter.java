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
 * Factory and builder interface for constructing VLAN (IEEE 802.1Q) filter
 * expressions.
 * <p>
 * This interface provides both static convenience methods for creating simple
 * single-condition VLAN filters and a fluent builder pattern for combining
 * multiple VLAN field conditions (PCP, DEI, VID, TPID/type).
 * </p>
 * <p>
 * All setter methods perform input validation according to the IEEE 802.1Q
 * specification:
 * <ul>
 * <li>PCP (Priority Code Point): 0–7 (3 bits)</li>
 * <li>DEI (Drop Eligible Indicator): 0–1 (1 bit)</li>
 * <li>VID (VLAN Identifier): 0–4095 (12 bits)</li>
 * <li>Type/TPID (Tag Protocol Identifier): 0–65535 (16 bits)</li>
 * </ul>
 * Any value outside these ranges throws a {@link FilterException}.
 * </p>
 * <p>
 * <strong>Note on reserved VID values:</strong>
 * <ul>
 * <li>VID 0 — priority-tagged frames (no VLAN membership)</li>
 * <li>VID 4095 (0xFFF) — reserved, should not be used for regular VLANs</li>
 * </ul>
 * This interface does not enforce restrictions on these reserved values, as
 * they may be valid in some filter contexts.
 * </p>
 *
 * <h2>Usage Examples</h2>
 * 
 * <pre>{@code
 * // Single condition (convenience)
 * VlanBuilder filter1 = VlanFilter.vid(100);
 *
 * // Combined conditions (fluent builder)
 * VlanBuilder filter2 = VlanFilter.of()
 * 		.pcp(5)
 * 		.dei(0)
 * 		.vid(200)
 * 		.type(0x8100);
 *
 * // Chained with validation
 * VlanBuilder filter3 = VlanFilter.pcp(3)
 * 		.vid(4094)
 * 		.type(0x88A8); // e.g. for 802.1ad / Q-in-Q outer tag
 * }</pre>
 */
public interface VlanFilter {

	/**
	 * Creates an empty VLAN builder (no conditions).
	 *
	 * @return a new {@link VlanBuilder} instance with no filters applied
	 */
	static VlanBuilder of() {
		return b -> b;
	}

	/**
	 * Creates a VLAN filter that matches a specific Priority Code Point (PCP /
	 * 802.1p priority).
	 *
	 * @param priority the PCP value (must be 0–7)
	 * @return a {@link VlanBuilder} configured with the PCP condition
	 * @throws FilterException if priority is not in the range 0–7
	 */
	static VlanBuilder pcp(int priority) throws FilterException {
		if (priority < 0 || priority > 7) {
			throw new FilterException("PCP (priority) must be 0-7, got: " + priority);
		}
		return of().pcp(priority);
	}

	/**
	 * Creates a VLAN filter that matches a specific Drop Eligible Indicator (DEI)
	 * value.
	 *
	 * @param dropEligible the DEI value (must be 0 or 1)
	 * @return a {@link VlanBuilder} configured with the DEI condition
	 * @throws FilterException if dropEligible is not 0 or 1
	 */
	static VlanBuilder dei(int dropEligible) throws FilterException {
		if (dropEligible < 0 || dropEligible > 1) {
			throw new FilterException("DEI (drop eligible) must be 0-1, got: " + dropEligible);
		}
		return of().dei(dropEligible);
	}

	/**
	 * Creates a VLAN filter that matches a specific VLAN Identifier (VID).
	 *
	 * @param vid the VLAN ID (must be 0–4095)
	 * @return a {@link VlanBuilder} configured with the VID condition
	 * @throws FilterException if vid is not in the range 0–4095
	 */
	static VlanBuilder vid(int vid) throws FilterException {
		if (vid < 0 || vid > 4095) {
			throw new FilterException("VLAN ID must be 0-4095, got: " + vid);
		}
		return of().vid(vid);
	}

	/**
	 * Creates a VLAN filter that matches a specific Tag Protocol Identifier (TPID /
	 * EtherType in the VLAN tag).
	 * <p>
	 * Common values: 0x8100 (standard 802.1Q), 0x88A8 (802.1ad / Q-in-Q outer),
	 * 0x9100, 0x9200 (some vendor implementations).
	 * </p>
	 *
	 * @param etherType the 16-bit TPID value (must be 0–65535)
	 * @return a {@link VlanBuilder} configured with the type/TPID condition
	 * @throws FilterException if etherType is not in the range 0–65535
	 */
	static VlanBuilder type(int etherType) throws FilterException {
		if (etherType < 0 || etherType > 65535) {
			throw new FilterException("VLAN type (EtherType/TPID) must be 0-65535, got: " + etherType);
		}
		return of().type(etherType);
	}

	/**
	 * Fluent builder interface for constructing complex VLAN filter expressions.
	 * <p>
	 * Each method adds an equality condition on the corresponding VLAN tag field
	 * and returns a new builder instance for method chaining.
	 * </p>
	 * <p>
	 * All methods perform the same range validation as their static counterparts.
	 * </p>
	 */
	interface VlanBuilder extends HeaderFilter {

		/**
		 * Adds a condition that the Priority Code Point (PCP) field must equal the
		 * given value.
		 *
		 * @param priority PCP value (3 bits, 0–7)
		 * @return this builder for chaining
		 * @throws FilterException if priority is not in the range 0–7
		 */
		default VlanBuilder pcp(int priority) throws FilterException {
			if (priority < 0 || priority > 7) {
				throw new FilterException("PCP (priority) must be 0-7, got: " + priority);
			}
			return b -> this.emit(b).and().field("vlan.pcp", 0, 3, Op.EQ, priority);
		}

		/**
		 * Adds a condition that the Drop Eligible Indicator (DEI) field must equal the
		 * given value.
		 *
		 * @param dropEligible DEI value (1 bit, 0 or 1)
		 * @return this builder for chaining
		 * @throws FilterException if dropEligible is not 0 or 1
		 */
		default VlanBuilder dei(int dropEligible) throws FilterException {
			if (dropEligible < 0 || dropEligible > 1) {
				throw new FilterException("DEI (drop eligible) must be 0-1, got: " + dropEligible);
			}
			return b -> this.emit(b).and().field("vlan.dei", 0, 1, Op.EQ, dropEligible);
		}

		/**
		 * Adds a condition that the VLAN Identifier (VID) field must equal the given
		 * value.
		 *
		 * @param vid VLAN ID (12 bits, 0–4095)
		 * @return this builder for chaining
		 * @throws FilterException if vid is not in the range 0–4095
		 */
		default VlanBuilder vid(int vid) throws FilterException {
			if (vid < 0 || vid > 4095) {
				throw new FilterException("VLAN ID must be 0-4095, got: " + vid);
			}
			return b -> this.emit(b).and().field("vlan.vid", 0, 12, Op.EQ, vid);
		}

		/**
		 * Adds a condition that the Tag Protocol Identifier (TPID / type) field must
		 * equal the given value.
		 *
		 * @param etherType 16-bit TPID value (0–65535)
		 * @return this builder for chaining
		 * @throws FilterException if etherType is not in the range 0–65535
		 */
		default VlanBuilder type(int etherType) throws FilterException {
			if (etherType < 0 || etherType > 65535) {
				throw new FilterException("VLAN type (EtherType/TPID) must be 0-65535, got: " + etherType);
			}
			return b -> this.emit(b).and().field("vlan.type", 2, 16, Op.EQ, etherType);
		}
	}
}