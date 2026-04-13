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
package com.slytechs.sdk.protocol.core.pack;

import com.slytechs.sdk.common.util.IntId;
import com.slytechs.sdk.protocol.core.id.ProtocolIds;

/**
 * Type-safe enum of protocol pack identifiers.
 *
 * <p>
 * Each constant corresponds to a protocol pack module and maps to the pack ID
 * encoded in the upper byte of the descriptor portion of a
 * {@link ProtocolIds protocol ID}. Use {@link #valueOf(int)} to resolve a pack
 * or protocol ID to its pack constant.
 * </p>
 *
 * <h2>Usage</h2>
 *
 * {@snippet :
 * // Resolve from a full protocol ID
 * PackId pack = PackId.valueOf(ProtocolIds.IPv4);  // TCPIP
 *
 * // Resolve from a pack ID
 * PackId pack = PackId.valueOf(ProtocolIds.PACK_TCPIP);  // TCPIP
 *
 * // Get the raw pack ID value
 * int rawId = PackId.TCPIP.id();  // 0x0200
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see ProtocolIds
 * @see ProtocolPack
 */
public enum PackId implements IntId {

	/** Unrecognized or invalid pack identifier. */
	UNKNOWN(-1),

	/** System protocols: PAYLOAD, UNKNOWN, PAD. */
	BUILTIN(ProtocolIds.PACK_BUILTIN),

	/** Infrastructure: bridge, routing, discovery, management. */
	INFRA(ProtocolIds.PACK_INFRA),

	/** Core TCP/IP stack: Ethernet, IP, TCP, UDP, IPsec, MPLS, etc. */
	TCPIP(ProtocolIds.PACK_TCPIP),

	/** Application layer: HTTP, HTML, TLS, DNS, DHCP, etc. */
	WEB(ProtocolIds.PACK_WEB),

	/** Telecommunications: GTP, SCTP, SS7, PFCP, etc. */
	TELCO(ProtocolIds.PACK_TELCO),

	/** Industrial protocols: SCADA, Modbus, DNP3 (future). */
	INDUSTRIAL(ProtocolIds.PACK_INDUSTRIAL),

	;

	private final int id;

	PackId(int id) {
		this.id = id;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return the raw pack ID value as encoded in {@link ProtocolIds}
	 */
	@Override
	public int id() {
		return id;
	}

	/**
	 * Resolves a pack or protocol ID to its {@code PackId} constant.
	 *
	 * <p>
	 * Extracts the pack portion from the given ID using
	 * {@link ProtocolIds#packId(int)} and matches it against known pack
	 * constants.
	 * </p>
	 *
	 * @param packOrProtocolId a raw pack ID or a full 32-bit protocol ID
	 * @return the matching {@code PackId}, or {@link #UNKNOWN} if not recognized
	 */
	public static PackId valueOf(int packOrProtocolId) {
		int id = ProtocolIds.packId(packOrProtocolId);

		for (var c : values()) {
			if (c.id == id)
				return c;
		}

		return UNKNOWN;
	}

}