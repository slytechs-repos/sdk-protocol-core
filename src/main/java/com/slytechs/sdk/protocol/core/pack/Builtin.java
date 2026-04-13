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

import com.slytechs.sdk.protocol.core.id.ProtocolId;
import com.slytechs.sdk.protocol.core.id.ProtocolIds;

/**
 * Protocol ID table for the builtin system protocols.
 *
 * <p>
 * Builtin protocols are defined in the core module and are always available
 * regardless of which protocol pack modules are loaded. These represent
 * structural elements of a packet rather than specific wire protocols.
 * </p>
 *
 * <p>
 * {@code PAYLOAD} is the catch-all that represents the data portion of a packet
 * when no further protocol dissection is possible or configured.
 * </p>
 *
 * <h2>Usage</h2>
 *
 * {@snippet :
 * // Check if a header is a raw payload
 * if (header.id() == Builtin.PAYLOAD.id()) {
 *     // treat as undissected data
 * }
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see ProtocolIds#PAYLOAD
 * @see PackId#BUILTIN
 */
public enum Builtin implements ProtocolId {

	/** Generic payload data, used when no further dissection is available. */
	PAYLOAD(ProtocolIds.PAYLOAD),

	;

	private final int protocolId;

	Builtin(int protocolId) {
		this.protocolId = protocolId;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @return the builtin protocol ID
	 */
	@Override
	public int id() {
		return protocolId;
	}

}