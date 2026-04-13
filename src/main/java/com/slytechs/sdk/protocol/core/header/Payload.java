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
package com.slytechs.sdk.protocol.core.header;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.ValueLayout;

import com.slytechs.sdk.common.text.DataEmitter;
import com.slytechs.sdk.protocol.core.id.ProtocolIds;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class Payload extends FixedHeader {

	public static final int ID = ProtocolIds.PAYLOAD;

	public static final MemoryLayout LAYOUT = ValueLayout.JAVA_BYTE;

	// @formatter:off
	private static final DataEmitter<Payload> PAYLOAD_EMITTER;
	static {
		PAYLOAD_EMITTER = new DataEmitter<>();

		PAYLOAD_EMITTER.section("Data ({payload.len} bytes)", sec -> sec
				.field("Length", p -> p.headerLength(), "payload.len"));
	}
	// @formatter:on
	/**
	 * @param id
	 * @param layout
	 */
	public Payload() {
		super(ID, LAYOUT);
	}

	/**
	 * @see com.slytechs.sdk.common.text.Textual#dataEmitter()
	 */
	@Override
	public DataEmitter<?> dataEmitter() {
		return PAYLOAD_EMITTER;
	}

}
