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
package com.slytechs.sdk.protocol.core.stack.processor;

import java.util.function.Consumer;

import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.ProtocolObject;
import com.slytechs.sdk.protocol.core.stack.Analyzer;
import com.slytechs.sdk.protocol.core.stack.LayerContext;
import com.slytechs.sdk.protocol.core.stack.ProcessorContext;
import com.slytechs.sdk.protocol.core.stack.ProcessorStats;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class PassthroughProcessor implements Processor {

	/**
	 * 
	 */
	public PassthroughProcessor() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.stack.processor.Processor#processPacket(com.slytechs.sdk.protocol.core.Packet, com.slytechs.sdk.protocol.core.stack.ProcessorContext, com.slytechs.sdk.protocol.core.stack.LayerContext)
	 */
	@Override
	public Packet processPacket(Packet packet, ProcessorContext ctx, LayerContext layer) {
		return packet;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.stack.processor.Processor#processProtocol(com.slytechs.sdk.protocol.core.stack.ProcessorContext, com.slytechs.sdk.protocol.core.stack.LayerContext)
	 */
	@Override
	public ProtocolObject processProtocol(ProcessorContext ctx, LayerContext layer) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.stack.processor.Processor#setAnalyzer(com.slytechs.sdk.protocol.core.stack.Analyzer)
	 */
	@Override
	public void setAnalyzer(Analyzer analyzer) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.stack.processor.Processor#tick(long)
	 */
	@Override
	public void tick(long nowNs) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.stack.processor.Processor#flush(java.util.function.Consumer)
	 */
	@Override
	public void flush(Consumer<ProtocolObject> emit) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.stack.processor.Processor#stats()
	 */
	@Override
	public ProcessorStats stats() {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
