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
package com.slytechs.sdk.protocol.core.token;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class ProtocolToken implements Token {

	private final long token64;

	public ProtocolToken(int length, int protocolId) {
		this(length, protocolId, 0, 0);
	}

	public ProtocolToken(int length, int protocolId, int status, int lod) {
		assert length % 4 == 0;

		this.token64 = Tokens.token(length, status, lod, Tokens.PROTOCOL_DOMAIN, protocolId);
	}

	/**
	 * A addressing domain for this token type. A 'domain' is a u8 field that
	 * describes the token 'type' field which is domain specific.
	 * 
	 * @return 8-bit token type domain
	 */
	@Override
	public int domain() {
		return Tokens.PROTOCOL_DOMAIN;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#write(java.nio.ByteBuffer,
	 *      int)
	 */
	@Override
	public int write(ByteBuffer b, int index) {
		if (isToken64()) {
			b.putLong(index, token64);

			return 8;
		}

		b.putInt(index, (int) token64);

		return 4;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#write(java.lang.foreign.MemorySegment,
	 *      long)
	 */
	@Override
	public int write(MemorySegment seg, long offset) {
		if (isToken64()) {
			Tokens.u64(seg, offset, token64);

			return 8;
		}

		Tokens.u32(seg, offset, (int) token64);

		return 4;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#token64()
	 */
	@Override
	public long token64() {
		return token64;
	}
}
