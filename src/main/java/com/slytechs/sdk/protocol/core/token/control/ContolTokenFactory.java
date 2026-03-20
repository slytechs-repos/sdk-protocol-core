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

import com.slytechs.sdk.protocol.core.token.Token;
import com.slytechs.sdk.protocol.core.token.TokenFactory;
import com.slytechs.sdk.protocol.core.token.Tokens;
import com.slytechs.sdk.protocol.core.token.UndefinedTokenType;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public final class ContolTokenFactory implements TokenFactory {

	private static Token controlToken(long token) {
		return switch (Tokens.type(token)) {
		case Tokens.PADDING_BYTES_CONTROL_TOKEN -> new PaddingBytesToken(token);

		default -> throw new UndefinedTokenType("control token=0x%016X".formatted(token));
		};
	}

	public ContolTokenFactory() {}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.TokenFactory#newToken(long,
	 *      java.nio.ByteBuffer, int)
	 */
	@Override
	public Token newToken(long token, ByteBuffer b, int index) {
		if (Tokens.domain(token) != Tokens.CONTROL_DOMAIN)
			return null;

		return switch (Tokens.type(token)) {
		case Tokens.INDEX_CONTROL_TOKEN -> new IndexToken(token, b, index);
		case Tokens.SECTION_MARK_CONTROL_TOKEN -> new SectionMarkToken(token, b, index);
		case Tokens.ANALYSIS_VERSION_CONTROL_TOKEN -> new AnalysisVersionToken(token, b, index);

		default -> controlToken(token);
		};
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.TokenFactory#newToken(long,
	 *      java.lang.foreign.MemorySegment, long)
	 */
	@Override
	public Token newToken(long token, MemorySegment seg, long offset) {
		if (Tokens.domain(token) != Tokens.CONTROL_DOMAIN)
			return null;

		return switch (Tokens.type(token)) {
		case Tokens.INDEX_CONTROL_TOKEN -> new IndexToken(token, seg, offset);
		case Tokens.SECTION_MARK_CONTROL_TOKEN -> new SectionMarkToken(token, seg, offset);
		case Tokens.ANALYSIS_VERSION_CONTROL_TOKEN -> new AnalysisVersionToken(token, seg, offset);

		default -> controlToken(token);
		};
	}

}
