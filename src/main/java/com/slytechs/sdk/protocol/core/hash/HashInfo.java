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
package com.slytechs.sdk.protocol.core.hash;

/**
 * Hash type enumeration for packet distribution across channels.
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public enum HashInfo implements HashType {

	NONE(HashType.NONE),
	ROUND_ROBIN(HashType.ROUND_ROBIN),
	HASH_2_TUPLE(HashType.HASH_2_TUPLE),
	HASH_2_TUPLE_SORTED(HashType.HASH_2_TUPLE_SORTED),
	HASH_5_TUPLE(HashType.HASH_5_TUPLE),
	HASH_5_TUPLE_SORTED(HashType.HASH_5_TUPLE_SORTED),
	HASH_INNER_2_TUPLE(HashType.HASH_INNER_2_TUPLE),
	HASH_INNER_2_TUPLE_SORTED(HashType.HASH_INNER_2_TUPLE_SORTED),
	HASH_INNER_5_TUPLE(HashType.HASH_INNER_5_TUPLE),
	HASH_INNER_5_TUPLE_SORTED(HashType.HASH_INNER_5_TUPLE_SORTED),
	HASH_5_TUPLE_SCTP(HashType.HASH_5_TUPLE_SCTP),
	HASH_5_TUPLE_SCTP_SORTED(HashType.HASH_5_TUPLE_SCTP_SORTED),
	HASH_3_TUPLE_GTP(HashType.HASH_3_TUPLE_GTP),
	HASH_3_TUPLE_GTP_SORTED(HashType.HASH_3_TUPLE_GTP_SORTED),
	HASH_LAST_MPLS_LABEL(HashType.HASH_LAST_MPLS_LABEL),
	HASH_ALL_MPLS_LABELS(HashType.HASH_ALL_MPLS_LABELS),
	HASH_LAST_VLAN_ID(HashType.HASH_LAST_VLAN_ID),
	HASH_ALL_VLAN_IDS(HashType.HASH_ALL_VLAN_IDS),

	;

	private final int id;
	private final HashCalculator calculator;

	HashInfo(int id) {
		this.id = id;
		this.calculator = HashCalculators.of(id);
	}

	public HashCalculator calculator() {
		return calculator;
	}

	@Override
	public int id() {
		return id;
	}

	public static HashInfo valueOf(int id) {
		for (HashInfo info : values()) {
			if (info.id == id)
				return info;
		}

		return null;
	}
}