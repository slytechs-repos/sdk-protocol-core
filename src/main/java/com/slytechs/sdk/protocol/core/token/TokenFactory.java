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
 * A token factory which creates new tokens from the backing memory or buffer.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface TokenFactory {

	static TokenFactory global() {
		return DefaultTokenFactory.INSTANCE;
	}

	default Token newToken(ByteBuffer b) {
		int index = b.position();
		Token token = newToken(b, index);
		b.position(index + token.length());

		return null;
	}

	default Token newToken(ByteBuffer b, int index) {
		long token = Tokens.header(b, index);

		return newToken(token, b, index + 8);
	}

	default Token newToken(MemorySegment seg, long offset) {
		long token = Tokens.header(seg, offset);

		return newToken(token, seg, offset + 8);
	}

	Token newToken(long token, ByteBuffer b, int index);

	Token newToken(long token, MemorySegment seg, long offset);

}
