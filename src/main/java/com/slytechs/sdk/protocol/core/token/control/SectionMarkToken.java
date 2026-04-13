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
public record SectionMarkToken(
		long token64,
		long indexStart,
		long tsStart,
		long tsEnd)
		implements ControlToken {

	public static final int LENGTH = 32;
	private static final int SECTION_INDEX_SHIFT = 32;
	private static final long SECTION_INDEX_MASK = 0xFFFFFFFF;

	public SectionMarkToken(long token64, MemorySegment seg, long offset) {
		this(token64,
				Tokens.u64(seg, offset + 12),
				Tokens.u64(seg, offset + 20),
				Tokens.u64(seg, offset + 28));
	}

	public SectionMarkToken(long token64, ByteBuffer b, int index) {
		this(token64,
				b.getLong(index + 12),
				b.getLong(index + 20),
				b.getLong(index + 28));
	}

	public int sectionIndex() {
		return (int) ((token64 >> SECTION_INDEX_SHIFT) & SECTION_INDEX_MASK);
	}

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
		return Tokens.SECTION_MARK_CONTROL_TOKEN;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#write(java.nio.ByteBuffer,
	 *      int)
	 */
	@Override
	public int write(ByteBuffer b, int index) {
		b.putLong(index + 0, token64);
		b.putLong(index + 8, indexStart);
		b.putLong(index + 16, tsStart);
		b.putLong(index + 24, tsEnd);

		return LENGTH;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#write(com.slytechs.sdk.common.memory.Memory,
	 *      long)
	 */
	@Override
	public int write(MemorySegment seg, long offset) {

		Tokens.u64(seg, offset + 0, token64);
		Tokens.u64(seg, offset + 8, indexStart);
		Tokens.u64(seg, offset + 16, tsStart);
		Tokens.u64(seg, offset + 24, tsEnd);

		return LENGTH;
	}

}
