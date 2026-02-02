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

import com.slytechs.sdk.common.memory.BindableView;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public non-sealed class FixedHeader extends Header {

	/**
	 * @param id
	 * @param layout
	 */
	public FixedHeader(int id, MemoryLayout layout) {
		super(id, layout);
	}

	/**
	 * Binds this header to packet data with extension information.
	 * 
	 * @param packet     the packet to bind to
	 * @param id the protocol ID
	 * @param depth      the header depth in packet
	 * @param offset     the offset within packet
	 * @param length     the header length
	 * @param options    encoded extension information
	 * @return true if binding successful
	 */
	@Override
	public final boolean bindHeader(
			BindableView packet,
			int protocolId,
			int innerDepth,
			long offset,
			long extendedLength) {

		return super.bindHeader(packet, protocolId, innerDepth, offset, extendedLength);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.header.Header#isFixedHeader()
	 */
	@Override
	public final boolean isFixedHeader() {
		return true;
	}
}
