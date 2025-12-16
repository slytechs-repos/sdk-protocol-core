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
package com.slytechs.jnet.protocol.api.builtin;

import static com.slytechs.jnet.protocol.api.pack.ProtocolPack.*;

import java.util.Optional;

import com.slytechs.jnet.protocol.api.Header;
import com.slytechs.jnet.protocol.api.HeaderFactory;
import com.slytechs.jnet.protocol.api.Protocol;
import com.slytechs.jnet.protocol.api.pack.ProtocolPackManager;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public enum L3FrameType {
	L3_FRAME_TYPE_OTHER(Constants.L3_FRAME_TYPE_OTHER, Builtin.Constants.PAYLOAD_ID),
	L3_FRAME_TYPE_IPv4(Constants.L3_FRAME_TYPE_IPv4, Constants.L3_PROTOCOL_IPv4_ID),
	L3_FRAME_TYPE_IPv6(Constants.L3_FRAME_TYPE_IPv6, Constants.L3_PROTOCOL_IPv6_ID),
	L3_FRAME_TYPE_IPX(Constants.L3_FRAME_TYPE_IPX, Builtin.Constants.PAYLOAD_ID),

	;

	public interface Constants {
		int L3_FRAME_TYPE_OTHER = 0;
		int L3_FRAME_TYPE_IPv4 = 1;
		int L3_FRAME_TYPE_IPv6 = 2;
		int L3_FRAME_TYPE_IPX = 3;

		int L3_PROTOCOL_IPv4_ID = TCPIP_ID | 21;
		int L3_PROTOCOL_IPv6_ID = TCPIP_ID | 22;

	}

	/** The id. */
	private final int protocolId;
	private final int l3Type;

	/** The supplier. */
	private final Optional<Protocol> protocol;
	private final HeaderFactory.ProxyCreated<?> factory;

	/**
	 * Instantiates a new layer 3 frame type.
	 *
	 * @param id       the id
	 * @param supplier the supplier
	 */
	L3FrameType(int id, int protocolId) {
		this.protocolId = protocolId;
		this.l3Type = id;
		this.protocol = ProtocolPackManager.findProtocol(protocolId);

		if (protocol.isEmpty())
			this.factory = () -> {
				throw new UnsupportedOperationException("L2 frame type protocol not found "
						+ "0x" + Integer.toHexString(protocolId).toUpperCase());
			};
		else
			this.factory = protocol.get()
					.headerFactory()
					.proxy();
	}

	/**
	 * Value of integer l2 type to enum constant.
	 *
	 * @param l3Type the layer2 frame type
	 * @return the enum constant
	 */
	public static L3FrameType valueOf(int l3Type) {
		return values()[l3Type];
	}

	/**
	 * Gets the l 2 frame type as int.
	 *
	 * @return the l 2 frame type as int
	 */
	public int l3TypeId() {
		return l3Type;
	}

	/**
	 * Gets the header id.
	 *
	 * @return the header id
	 * @see com.slytechs.jnet.protocol.api.common.HeaderInfo#descriptorId()
	 */
	public int protocolId() {
		return protocolId;
	}

	public Protocol protocol() {
		return protocol.orElse(null);
	}

	/**
	 * New header instance.
	 *
	 * @return the header
	 * @see com.slytechs.jnet.protocol.api.common.HeaderSupplier#newHeaderInstance()
	 */
	public Header newHeaderInstance() {
		return factory.newHeader();
	}
}
