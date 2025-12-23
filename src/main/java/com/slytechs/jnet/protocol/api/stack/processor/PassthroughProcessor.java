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
package com.slytechs.jnet.protocol.api.stack.processor;

import java.util.function.Consumer;

import com.slytechs.jnet.protocol.api.Packet;
import com.slytechs.jnet.protocol.api.ProtocolObject;
import com.slytechs.jnet.protocol.api.stack.Analyzer;
import com.slytechs.jnet.protocol.api.stack.LayerContext;
import com.slytechs.jnet.protocol.api.stack.ProcessorContext;
import com.slytechs.jnet.protocol.api.stack.ProcessorStats;

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
	 * @see com.slytechs.jnet.protocol.api.stack.processor.Processor#processPacket(com.slytechs.jnet.protocol.api.Packet, com.slytechs.jnet.protocol.api.stack.ProcessorContext, com.slytechs.jnet.protocol.api.stack.LayerContext)
	 */
	@Override
	public Packet processPacket(Packet packet, ProcessorContext ctx, LayerContext layer) {
		return packet;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.stack.processor.Processor#processProtocol(com.slytechs.jnet.protocol.api.stack.ProcessorContext, com.slytechs.jnet.protocol.api.stack.LayerContext)
	 */
	@Override
	public ProtocolObject processProtocol(ProcessorContext ctx, LayerContext layer) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.stack.processor.Processor#setAnalyzer(com.slytechs.jnet.protocol.api.stack.Analyzer)
	 */
	@Override
	public void setAnalyzer(Analyzer analyzer) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.stack.processor.Processor#tick(long)
	 */
	@Override
	public void tick(long nowNs) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.stack.processor.Processor#flush(java.util.function.Consumer)
	 */
	@Override
	public void flush(Consumer<ProtocolObject> emit) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.stack.processor.Processor#stats()
	 */
	@Override
	public ProcessorStats stats() {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
