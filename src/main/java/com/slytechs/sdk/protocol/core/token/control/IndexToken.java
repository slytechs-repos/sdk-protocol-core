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
public record IndexToken(
		long token64,
		long streamPos,
		long minPacketIndex,
		long minPacketOffset,
		long minTimestampNs)
		implements ControlToken {

	public IndexToken(long token64, MemorySegment seg, long offset) {
		this(token64,
				Tokens.u64(seg, offset + 8),
				Tokens.u64(seg, offset + 16),
				Tokens.u64(seg, offset + 24),
				Tokens.u64(seg, offset + 32));
	}

	public IndexToken(long token64, ByteBuffer b, int index) {
		this(token64,
				b.getLong(index + 8),
				b.getLong(index + 16),
				b.getLong(index + 24),
				b.getLong(index + 32));
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#write(java.nio.ByteBuffer,
	 *      int)
	 */
	@Override
	public int write(ByteBuffer b, int index) {
		b.putLong(index + 0, token64);
		b.putLong(index + 8, streamPos);
		b.putLong(index + 16, minPacketIndex);
		b.putLong(index + 24, minPacketOffset);
		b.putLong(index + 32, minTimestampNs);

		return LENGTH;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#write(com.slytechs.sdk.common.memory.Memory,
	 *      long)
	 */
	@Override
	public int write(MemorySegment seg, long offset) {

		Tokens.u64(seg, offset + 0, token64);
		Tokens.u64(seg, offset + 8, streamPos);
		Tokens.u64(seg, offset + 16, minPacketIndex);
		Tokens.u64(seg, offset + 24, minPacketOffset);
		Tokens.u64(seg, offset + 32, minTimestampNs);

		return LENGTH;
	}

	public static final int LENGTH = 32;

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#wordLength()
	 */
	@Override
	public int wordLength() {
		return LENGTH >> 2;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#length()
	 */
	@Override
	public int length() {
		return LENGTH;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#type()
	 */
	@Override
	public int type() {
		return Tokens.INDEX_CONTROL_TOKEN;
	}

}
