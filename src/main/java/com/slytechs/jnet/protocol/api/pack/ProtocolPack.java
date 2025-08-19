/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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
package com.slytechs.jnet.protocol.api.pack;

import java.util.List;
import java.util.Optional;

import com.slytechs.jnet.protocol.api.Header;
import com.slytechs.jnet.protocol.api.Protocol;

/**
 * {@snippet lang = c:
 * struct pack_id_s {
 * 	 uint16_t
 * 		ordinal:8,  // Index within the protocol pack
 * 		pack:8;     // Protocol pack unique number
 * 
 * 	 uint16_t class_mask;
 * }
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface ProtocolPack {

	/** The builtin header types such as PAYLOAD. */
	int BUILTIN_ID = (0 << 8);

	/**
	 * Shared IDs for options, typically for the preceding header type within a
	 * packet
	 */
	int OPTIONS_ID = (1 << 8);

	/** The TCP/IP protocol pack. */
	int TCPIP_ID = (2 << 8);

	/** The TCP/IP protocol pack. */
	int WEB_ID = (3 << 8);

	String name();

	String description();

	boolean isLoaded();

	boolean isEnabled();

	void setEnable(boolean b);

	int id();

	List<Protocol> listProtocols();

	Protocol mapProtocolUsingId(int protocolId);

	Optional<Protocol> findProtocol(Class<? extends Header> headerClass);
}
