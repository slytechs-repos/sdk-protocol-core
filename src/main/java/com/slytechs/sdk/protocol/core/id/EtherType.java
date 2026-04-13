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

package com.slytechs.sdk.protocol.core.id;

import com.slytechs.sdk.common.util.IntId;

/**
 * Type-safe EtherType enum table for well-known Ethernet Type values.
 *
 * <p>
 * Each constant maps to a wire-level value defined in {@link EtherTypes}. Use
 * {@link #id()} to get the 16-bit wire value, or {@link #valueOf(int)} to
 * resolve a wire value to its enum constant.
 * </p>
 *
 * <p>
 * Not all {@link EtherTypes} constants have a corresponding enum entry here;
 * only actively parsed protocols are represented. Unrecognized values resolve
 * to {@link #UNKNOWN}.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see EtherTypes
 */
public enum EtherType implements EtherTypes, IntId {

	// @formatter:off
	UNKNOWN   (EtherTypes.UNKNOWN),
	IPv4      (EtherTypes.IPv4),
	IPv6      (EtherTypes.IPv6),
	ARP       (EtherTypes.ARP),
	RARP      (EtherTypes.RARP),
	VLAN      (EtherTypes.VLAN),
	QINQ      (EtherTypes.QINQ),
	VLAN_9100 (EtherTypes.VLAN_9100),
	VLAN_9200 (EtherTypes.VLAN_9200),
	VLAN_9300 (EtherTypes.VLAN_9300),
	MPLS      (EtherTypes.MPLS),
	MPLS_MC   (EtherTypes.MPLS_MC),
	PPPoE_D   (EtherTypes.PPPoE_D),
	PPPoE_S   (EtherTypes.PPPoE_S),
	LLDP      (EtherTypes.LLDP),
	LOOPBACK  (EtherTypes.LOOPBACK);
	// @formatter:on

	/**
	 * Returns the EtherType for the given wire value.
	 *
	 * @param etherType the 16-bit wire value
	 * @return the corresponding EtherType, or {@link #UNKNOWN} if not mapped
	 */
	public static EtherType valueOf(int etherType) {
		for (var e : values()) {
			if (e.value == etherType)
				return e;
		}

		return UNKNOWN;
	}

	private final int value;

	EtherType(int value) {
		this.value = value;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return the 16-bit EtherType value
	 */
	@Override
	public int id() {
		return value;
	}

	@Override
	public String toString() {
		return EtherTypes.nameOf(value);
	}
}