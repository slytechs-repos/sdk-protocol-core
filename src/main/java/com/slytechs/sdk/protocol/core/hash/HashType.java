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

import com.slytechs.sdk.common.util.IntId;

/**
 * Hash type enumeration for packet distribution across channels.
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public enum HashType implements HashTypes, IntId {

	NONE(HashTypes.NONE),
	ROUND_ROBIN(HashTypes.ROUND_ROBIN),
	HASH_2_TUPLE(HashTypes.HASH_2_TUPLE),
	HASH_2_TUPLE_SORTED(HashTypes.HASH_2_TUPLE_SORTED),
	HASH_5_TUPLE(HashTypes.HASH_5_TUPLE),
	HASH_5_TUPLE_SORTED(HashTypes.HASH_5_TUPLE_SORTED),
	HASH_INNER_2_TUPLE(HashTypes.HASH_INNER_2_TUPLE),
	HASH_INNER_2_TUPLE_SORTED(HashTypes.HASH_INNER_2_TUPLE_SORTED),
	HASH_INNER_5_TUPLE(HashTypes.HASH_INNER_5_TUPLE),
	HASH_INNER_5_TUPLE_SORTED(HashTypes.HASH_INNER_5_TUPLE_SORTED),
	HASH_5_TUPLE_SCTP(HashTypes.HASH_5_TUPLE_SCTP),
	HASH_5_TUPLE_SCTP_SORTED(HashTypes.HASH_5_TUPLE_SCTP_SORTED),
	HASH_3_TUPLE_GTP(HashTypes.HASH_3_TUPLE_GTP),
	HASH_3_TUPLE_GTP_SORTED(HashTypes.HASH_3_TUPLE_GTP_SORTED),
	HASH_LAST_MPLS_LABEL(HashTypes.HASH_LAST_MPLS_LABEL),
	HASH_ALL_MPLS_LABELS(HashTypes.HASH_ALL_MPLS_LABELS),
	HASH_LAST_VLAN_ID(HashTypes.HASH_LAST_VLAN_ID),
	HASH_ALL_VLAN_IDS(HashTypes.HASH_ALL_VLAN_IDS),

	;

	private final int id;
	private final HashCalculator calculator;

	HashType(int id) {
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

	public static HashType valueOf(int id) {
		for (HashType info : values()) {
			if (info.id == id)
				return info;
		}

		return null;
	}
}