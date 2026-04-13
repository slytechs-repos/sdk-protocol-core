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
public record AnalysisVersionToken(
		long token64,
		long tsStart)
		implements ControlToken {

	public static final int LENGTH = 20;
	private static final int ANALYSIS_VERSION_SHIFT = 32;
	private static final long ANALYSIS_VERSION_MASK = 0xFFFF;
	private static final int PASS_TYPE_SHIFT = 48;
	private static final long PASS_TYPE_MASK = 0xF;
	private static final int DOMAIN_MASK_SHIFT = 56;
	private static final long DOMAIN_MASK_MASK = 0xF;

	public AnalysisVersionToken(long token64, MemorySegment seg, long offset) {
		this(token64, Tokens.u64(seg, offset + 8));
	}

	public AnalysisVersionToken(long token64, ByteBuffer b, int index) {
		this(token64, b.getLong(8));
	}

	public int analysisVersion() {
		return (int) ((token64 >> ANALYSIS_VERSION_SHIFT) & ANALYSIS_VERSION_MASK);
	}

	public int passType() {
		return (int) ((token64 >> PASS_TYPE_SHIFT) & PASS_TYPE_MASK);
	}

	public int domainMask() {
		return (int) ((token64 >> DOMAIN_MASK_SHIFT) & DOMAIN_MASK_MASK);
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
		return Tokens.ANALYSIS_VERSION_CONTROL_TOKEN;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#write(java.nio.ByteBuffer,
	 *      int)
	 */
	@Override
	public int write(ByteBuffer b, int index) {
		b.putLong(index + 0, token64);
		b.putLong(index + 8, tsStart);

		return LENGTH;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.token.Token#write(java.lang.foreign.MemorySegment,
	 *      long)
	 */
	@Override
	public int write(MemorySegment seg, long offset) {
		Tokens.u64(seg, offset + 0, token64);
		Tokens.u64(seg, offset + 8, tsStart);

		return LENGTH;
	}

}
