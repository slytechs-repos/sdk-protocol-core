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

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public enum PackId {

	PACK_ID_BUILTIN(Constants.PACK_ID_BUILTIN),
	PACK_ID_TCPIP(Constants.PACK_ID_TCPIP),
	PACK_ID_WEB(Constants.PACK_ID_WEB),

	;

	private final int id;

	PackId(int id) {
		this.id = id;
	}

	public int packId() {
		return id;
	}

	public static int packId(int id) {
		return (id & Constants.PACK_MASK_PACK_ID) >> Constants.PACK_BITSHIFT_PACK_ID;
	}

	public static PackId valueOf(int packOrProtocolId) {
		int ordinal = (packOrProtocolId & Constants.PACK_MASK_PACK_ID) >> Constants.PACK_BITSHIFT_PROTO_ID;

		return values()[ordinal];
	}

	public interface Constants {

		int PACK_FLAG_PROTO_EXTENSION = (1 << 22);
		int PACK_FLAG_PROTO_OPTION = (1 << 23);

		int PACK_MASK_PROTO_ID = 0x0000FF;
		int PACK_MASK_PACK_ID = 0x00FF00;
		int PACK_MASK_OPTION_ID = 0x3F0000;
		int PACK_MASK_EXTENSION_ID = 0x3F0000;
		int PACK_MASK_FLAGS = 0xC00000;
		
		int PACK_BITSHIFT_PROTO_ID = 0;
		int PACK_BITSHIFT_PACK_ID = 8;
		int PACK_BITSHIFT_OPTION_ID = 16;
		int PACK_BITSHIFT_EXTENSION_ID = 16;

		int PACK_ID_BUILTIN = (0 << PACK_BITSHIFT_PACK_ID);
		int PACK_ID_TCPIP = (2 << PACK_BITSHIFT_PACK_ID);
		int PACK_ID_WEB = (3 << PACK_BITSHIFT_PACK_ID);
	}

}
