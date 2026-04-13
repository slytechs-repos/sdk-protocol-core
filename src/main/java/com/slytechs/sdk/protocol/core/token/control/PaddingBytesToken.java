/*
 * Copyright 2005-2026 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.protocol.core.token.control;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;

import com.slytechs.sdk.protocol.core.token.Tokens;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public record PaddingBytesToken(long token64) implements ControlToken {

	private static final long template64 = Tokens.token64(
			0,
			0,
			0,
			Tokens.CONTROL_DOMAIN,
			Tokens.PADDING_BYTES_CONTROL_TOKEN);

	public PaddingBytesToken(int paddingLength) {
		this(Tokens.setLength(template64, paddingLength));
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#wordLength()
	 */
	@Override
	public int wordLength() {
		return 0; // Extended format
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#length()
	 */
	@Override
	public int length() {
		return Tokens.length(token64);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#type()
	 */
	@Override
	public int type() {
		return Tokens.PADDING_BYTES_CONTROL_TOKEN;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#write(java.nio.ByteBuffer,
	 *      int)
	 */
	@Override
	public int write(ByteBuffer b, int index) {
		b.putLong(index, token64);

		return 8;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#write(com.slytechs.sdk.common.memory.Memory,
	 *      long)
	 */
	@Override
	public int write(MemorySegment seg, long offset) {
		return Tokens.u64(seg, offset, token64);
	}

}
