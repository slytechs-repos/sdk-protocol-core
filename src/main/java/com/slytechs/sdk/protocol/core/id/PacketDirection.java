/*
 * Sly Technologies Free License
 * 
 * Copyright 2025 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.sdk.protocol.core.id;

import com.slytechs.sdk.common.util.IntId;

/**
 * Provides contextual metadata (port, direction, user data). Maps to DPDK
 * (rte_mbuf.port, userdata), Napatech (descriptor meta), Pcap (from handle).
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public enum PacketDirection implements IntId {
	UNKNOWN(-1), RX(0), TX(1), INOUT(2);

	private final int id;

	PacketDirection(int id) {
		this.id = id;
	}

	@Override
	public int id() {
		return id;
	}

	public static PacketDirection of(int value) {
		for (PacketDirection dir : values()) {
			if (dir.id == value) {
				return dir;
			}
		}
		return UNKNOWN;
	}
}
