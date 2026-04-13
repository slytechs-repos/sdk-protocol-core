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
import java.util.ServiceLoader;
import java.util.ServiceLoader.Provider;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
final class DefaultTokenFactory implements TokenFactory {

	public static final DefaultTokenFactory INSTANCE = new DefaultTokenFactory();

	private static final TokenFactory[] factories = loadAllTokenFactories();

	private static TokenFactory[] loadAllTokenFactories() {
		return ServiceLoader.load(TokenFactory.class)
				.stream()
				.map(Provider::get)
				.toArray(TokenFactory[]::new);
	}

	public DefaultTokenFactory() {}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.TokenFactory#newToken(long,
	 *      java.nio.ByteBuffer, int)
	 */
	@Override
	public Token newToken(long token, ByteBuffer b, int index) {
		for (TokenFactory f : factories) {
			Token t = f.newToken(token, b, index);
			if (t != null)
				return t;
		}

		throw new UndefinedTokenType("token=0x%016X".formatted(token));
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.TokenFactory#newToken(long,
	 *      java.lang.foreign.MemorySegment, long)
	 */
	@Override
	public Token newToken(long token, MemorySegment seg, long offset) {
		for (TokenFactory f : factories) {
			Token t = f.newToken(token, seg, offset);
			if (t != null)
				return t;
		}

		throw new UndefinedTokenType("token=0x%016X".formatted(token));
	}

}
