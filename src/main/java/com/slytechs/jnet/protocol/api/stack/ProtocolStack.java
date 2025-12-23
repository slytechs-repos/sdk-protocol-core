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
package com.slytechs.jnet.protocol.api.stack;

import com.slytechs.jnet.protocol.api.Protocol;
import com.slytechs.jnet.protocol.api.stack.processor.Processor;
import com.slytechs.jnet.protocol.api.stack.processor.PassthroughProcessor;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class ProtocolStack {

	public static ProtocolStack packetDissectionOnly() {
		return new ProtocolStack();
	}

	private final PacketPolicy packetPolicy = new PacketPolicy()
			.zeroCopy();
	private Processor root = new PassthroughProcessor();

	/**
	 * 
	 */
	public ProtocolStack() {}

	public <T extends Protocol> T getProtocol(Class<T> protocolClass) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	public PacketPolicy getPacketPolicy() {
		return packetPolicy;
	}

	public Processor getRootProcessor() {
		return root;
	}

}
