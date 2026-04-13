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
public record Token64(long token64) implements Token {

	public Token64(int status, int lod, int domain, int type) {
		this(Tokens.token64(8, status, lod, domain, type));
	}

	public Token64(int length, int status, int lod, int domain, int type) {
		this(Tokens.token64(length, status, lod, domain, type));
	}

	public Token64(int domain, int type) {
		this(Tokens.token64(8, Token.NORMAL_STATUS, Token.NORMAL_LOD, domain, type));
	}

	public Token64(int length, int domain, int type) {
		this(Tokens.token64(length, Token.NORMAL_STATUS, Token.NORMAL_LOD, domain, type));
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#wordLength()
	 */
	@Override
	public int wordLength() {
		return Tokens.wordLength(token64);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#length()
	 */
	@Override
	public int length() {
		return Tokens.length(token64);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#write(java.nio.ByteBuffer,
	 *      int)
	 */
	@Override
	public int write(ByteBuffer b, int index) {
		b.putLong(index, token64);

		return length();
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#write(com.slytechs.sdk.common.memory.Memory,
	 *      long)
	 */
	@Override
	public int write(MemorySegment seg, long offset) {
		Tokens.u64(seg, offset, token64);

		return length();
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#domain()
	 */
	@Override
	public int domain() {
		return Tokens.domain(token64);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#type()
	 */
	@Override
	public int type() {
		return Tokens.type(token64);
	}

}
