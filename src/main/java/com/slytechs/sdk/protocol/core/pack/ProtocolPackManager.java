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

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import com.slytechs.sdk.protocol.core.Header;
import com.slytechs.sdk.protocol.core.Protocol;
import com.slytechs.sdk.protocol.core.ProtocolException;
import com.slytechs.sdk.protocol.core.dissector.DissectorPlugin;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface ProtocolPackManager {

	static Protocol lookupProtocol(Class<? extends Header> headerClass) {
		return listProtocolPacks().stream()
				.map(p -> p.findProtocol(headerClass))
				.filter(o -> o.isPresent())
				.map(o -> o.get())
				.findAny()
				.orElseThrow(() -> new ProtocolException("Protocol for header class " + headerClass + " not found"));
	}

	static Protocol lookupProtocol(int protocolId) {
		return listProtocolPacks().stream()
				.map(p -> p.mapProtocolUsingId(protocolId))
				.findAny()
				.orElseThrow(() -> new ProtocolException("Protocol for protocol ID "
						+ "0x" + Integer.toHexString(protocolId).toUpperCase()
						+ " not found"));
	}

	static Optional<Protocol> findProtocol(int protocolId) {
		return listProtocolPacks().stream()
				.map(p -> p.mapProtocolUsingId(protocolId))
				.findAny();
	}

	public static List<ProtocolPack> listProtocolPacks() {
		return Collections.emptyList();
	}
	
	public static List<DissectorPlugin> listDissectors() {
		return Collections.emptyList();
	}
}
