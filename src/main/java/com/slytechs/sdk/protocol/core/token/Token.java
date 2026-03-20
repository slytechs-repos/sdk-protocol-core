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

import com.slytechs.sdk.common.memory.Memory;

/**
 * An immutable analysis token carrying a domain, type, status, and LOD hint.
 *
 * <p>
 * Tokens record analysis events during protocol decoding and other pipeline
 * operations. Every token is held in a {@code long} (u64) regardless of its
 * on-wire format, which may be either standard (u32, 4 bytes) or extended (u64,
 * 8+ bytes). The {@code len} nibble in bits 3:0 of the first byte selects the
 * format: a non-zero value encodes the total size in 32-bit words; zero signals
 * that the actual byte length follows in the next u16 field of the extended
 * header.
 * </p>
 *
 * <p>
 * All tokens are stored in little-endian byte order. Reading a full u64 from
 * memory is always safe: for standard tokens the upper 32 bits are zero-padded,
 * and for extended tokens the upper 32 bits carry the extended length and opaque
 * fields. Callers may therefore read u64 unconditionally and branch on
 * {@link #isToken32()} / {@link #isToken64()} after the fact.
 * </p>
 *
 * <pre>
 * Standard token header (u32, 4 bytes):
 *   bits  0-3    len       u4   0 = extended format; 1-15 = total size in 32-bit words
 *   bits  4-5    status    u2   0=INFO  1=NORMAL  2=WARNING  3=ANOMALY
 *   bits  6-7    lod_hint  u2   QAT key-promotion hint (0=ADVANCED .. 3=LEARNING)
 *   bits  8-15   domain    u8   token namespace (see {@link Tokens} domain constants)
 *   bits 16-31   type      u16  domain-specific token type
 *
 * Extended token header (u64, 8 bytes, only when len == 0):
 *   bits 32-47   token_len u16  total token size in bytes including all headers
 *   bits 48-63   opaque    u16  domain-defined; reserved for standard control tokens
 * </pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Tokens
 */
public interface Token {

	/** Size of the standard token header in bytes. */
	int LENGTH_BYTES = 4;

	/** Size of the standard token header in bits. */
	int LENGTH_BITS = 32;

	/**
	 * Status value indicating an informational event with no anomaly signal.
	 * This is the default status for most protocol-stack tokens.
	 */
	int INFO_STATUS = 0;

	/**
	 * Status value indicating a normal, expected event.
	 */
	int NORMAL_STATUS = 1;

	/**
	 * Status value indicating a condition that warrants attention but is not
	 * definitively anomalous (e.g. retransmit, slow handshake).
	 */
	int WARNING_STATUS = 2;

	/**
	 * Status value indicating a detected anomaly (e.g. protocol violation,
	 * IDS rule match, TLS downgrade).
	 */
	int ANOMALY_STATUS = 3;

	/**
	 * LOD hint for expert-level consumers. Token carries full protocol detail
	 * and is relevant at all analysis depths. This is the default LOD for most
	 * tokens.
	 */
	int ADVANCED_LOD = 0;

	/**
	 * LOD hint indicating the token is relevant at normal analyst depth.
	 * Consumers operating in learning or friendly modes may suppress it.
	 */
	int NORMAL_LOD = 1;

	/**
	 * LOD hint indicating the token is only relevant to non-technical consumers.
	 * Expert and advanced consumers typically suppress tokens at this LOD.
	 */
	int FRIENDLY_LOD = 2;

	/**
	 * LOD hint indicating the token is a narrative or high-level summary
	 * intended for learning mode only. All other LOD levels suppress it.
	 */
	int LEARNING_LOD = 3;

	/**
	 * Reads a token from the current position of the given buffer, advancing
	 * the buffer position by 8 bytes (u64 read).
	 *
	 * @param b the little-endian buffer to read from
	 * @return the decoded token
	 */
	static Token readToken(ByteBuffer b) {
		return TokenFactory.global().newToken(b);
	}

	/**
	 * Reads a token from the given absolute index in the buffer without
	 * advancing the buffer position.
	 *
	 * @param b     the little-endian buffer to read from
	 * @param index byte offset within the buffer
	 * @return the decoded token
	 */
	static Token readToken(ByteBuffer b, int index) {
		return TokenFactory.global().newToken(b, index);
	}

	/**
	 * Reads a token from a {@link MemorySegment} at the given byte offset.
	 *
	 * @param seg    the memory segment to read from
	 * @param offset byte offset within the segment
	 * @return the decoded token
	 */
	static Token readToken(MemorySegment seg, long offset) {
		return TokenFactory.global().newToken(seg, offset);
	}

	/**
	 * Reads a token from a {@link Memory} region at the given byte offset.
	 *
	 * @param memory the memory region to read from
	 * @param offset byte offset within the region
	 * @return the decoded token
	 */
	static Token readToken(Memory memory, long offset) {
		return TokenFactory.global().newToken(memory.segment(), offset);
	}

	/**
	 * Writes this token to the given buffer at the specified absolute index.
	 * Always writes 8 bytes (u64) regardless of token format, so the caller
	 * must ensure at least 8 bytes of capacity from {@code index}.
	 *
	 * @param b     the destination buffer
	 * @param index byte offset within the buffer
	 * @return number of bytes written (always 8)
	 */
	int write(ByteBuffer b, int index);

	/**
	 * Writes this token to the given {@link Memory} region at the specified
	 * byte offset. Delegates to {@link #write(MemorySegment, long)}.
	 *
	 * @param memory the destination memory region
	 * @param offset byte offset within the region
	 * @return number of bytes written (always 8)
	 */
	default int write(Memory memory, long offset) {
		return write(memory.segment(), offset);
	}

	/**
	 * Writes this token to the given {@link MemorySegment} at the specified
	 * byte offset. Always writes 8 bytes (u64).
	 *
	 * @param seg    the destination memory segment
	 * @param offset byte offset within the segment
	 * @return number of bytes written (always 8)
	 */
	int write(MemorySegment seg, long offset);

	/**
	 * Returns the token domain — the 8-bit namespace that scopes the
	 * {@link #type()} field. Each domain has its own type assignment table.
	 * See the {@link Tokens} domain constants (e.g. {@link Tokens#CONTROL_DOMAIN},
	 * {@link Tokens#PROTOCOL_DOMAIN}).
	 *
	 * @return u8 domain identifier, 0x00-0xFF
	 */
	default int domain() {
		return Tokens.domain(token64());
	}

	/**
	 * Returns the total length of this token in bytes, including all headers
	 * and payload.
	 *
	 * <p>For standard tokens ({@link #isToken32()}), this is
	 * {@code wordLength() * 4}. For extended tokens ({@link #isToken64()}),
	 * this is the value stored in the {@code token_len} u16 field at bits
	 * 47:32 of the u64 header.</p>
	 *
	 * @return total token length in bytes
	 */
	default int length() {
		return Tokens.length(token64());
	}

	/**
	 * Returns {@code true} if this is a standard 32-bit token.
	 *
	 * <p>Standard tokens have a non-zero {@link #wordLength()} nibble and a
	 * total size that is a multiple of 4 bytes, up to 60 bytes (wordLength
	 * 1-15). The header occupies the first 4 bytes.</p>
	 *
	 * @return {@code true} when {@code wordLength() > 0}
	 */
	default boolean isToken32() {
		return Tokens.wordLength(token64()) > 0;
	}

	/**
	 * Returns {@code true} if this is an extended 64-bit token.
	 *
	 * <p>Extended tokens have {@code wordLength() == 0} and carry their actual
	 * byte length in a u16 field at bits 47:32 of the u64 header, allowing
	 * payloads up to 65,535 bytes. The header occupies the first 8 bytes.</p>
	 *
	 * @return {@code true} when {@code wordLength() == 0}
	 */
	default boolean isToken64() {
		return Tokens.wordLength(token64()) == 0;
	}

	/**
	 * Returns the combined 4-bit level field formed by overlaying the 2-bit
	 * {@link #status()} and 2-bit {@link #lod()} fields.
	 *
	 * <p>The encoding is {@code lod << 2 | status}, producing a 0-15 scale
	 * that can be used as a unified priority or verbosity level.</p>
	 *
	 * @return 4-bit level (0-15)
	 */
	default int level() {
		return status() | (lod() << 2);
	}

	/**
	 * Returns the 2-bit level-of-detail hint for this token.
	 *
	 * <p>The LOD hint guides QAT key promotion and Lynx rendering decisions.
	 * It does not affect token storage or stream ordering. The default
	 * implementation returns {@link #ADVANCED_LOD}.</p>
	 *
	 * @return 2-bit LOD value (0=ADVANCED, 1=NORMAL, 2=FRIENDLY, 3=LEARNING)
	 * @see #ADVANCED_LOD
	 * @see #NORMAL_LOD
	 * @see #FRIENDLY_LOD
	 * @see #LEARNING_LOD
	 */
	default int lod() {
		return Token.ADVANCED_LOD;
	}

	/**
	 * Returns a copy of this token with the domain field set to
	 * {@code newDomain}. The default implementation throws
	 * {@link UnsupportedOperationException}; immutable token records
	 * should override this to return a new instance.
	 *
	 * @param newDomain u8 domain value (0x00-0xFF)
	 * @return token with the updated domain
	 * @throws UnsupportedOperationException if mutation is not supported
	 */
	default Token setDomain(int newDomain) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns a copy of this token with the length field set to
	 * {@code newLengthInBytes}. For standard tokens the value must be a
	 * multiple of 4 and fit in the 4-bit word-length field (4-60 bytes).
	 * For extended tokens the full u16 range applies.
	 *
	 * @param newLengthInBytes total token length in bytes
	 * @return token with the updated length
	 * @throws UnsupportedOperationException if mutation is not supported
	 */
	default Token setLength(int newLengthInBytes) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns a copy of this token with the LOD hint set to {@code newLod}.
	 *
	 * @param newLod 2-bit LOD value (0-3)
	 * @return token with the updated LOD hint
	 * @throws UnsupportedOperationException if mutation is not supported
	 */
	default Token setLod(int newLod) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns a copy of this token with the status field set to
	 * {@code newState}.
	 *
	 * @param newState 2-bit status value (0=INFO, 1=NORMAL, 2=WARNING, 3=ANOMALY)
	 * @return token with the updated status
	 * @throws UnsupportedOperationException if mutation is not supported
	 */
	default Token setStatus(int newState) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns a copy of this token with both the status and LOD fields set
	 * from the combined 4-bit {@code newStatusLod} value.
	 * Encoding is {@code lod << 2 | status}.
	 *
	 * @param newStatusLod 4-bit combined status/LOD value (0-15)
	 * @return token with the updated status and LOD
	 * @throws UnsupportedOperationException if mutation is not supported
	 */
	default Token setStatusLod(int newStatusLod) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns a copy of this token with the type field set to {@code newType}.
	 *
	 * @param newType u16 domain-specific type value (0x0000-0xFFFF)
	 * @return token with the updated type
	 * @throws UnsupportedOperationException if mutation is not supported
	 */
	default Token setType(int newType) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns a copy of this token with the word-length field set to
	 * {@code newWordLength}. A value of 0 selects the extended format.
	 *
	 * @param newWordLength 4-bit word length (0-15); 0 = extended format
	 * @return token with the updated word length
	 * @throws UnsupportedOperationException if mutation is not supported
	 */
	default Token setWorldLength(int newWordLength) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns the 2-bit status of this token.
	 *
	 * <p>Status signals the severity or classification of the event recorded
	 * by this token. The default implementation returns {@link #INFO_STATUS}.</p>
	 *
	 * @return 2-bit status value (0=INFO, 1=NORMAL, 2=WARNING, 3=ANOMALY)
	 * @see #INFO_STATUS
	 * @see #NORMAL_STATUS
	 * @see #WARNING_STATUS
	 * @see #ANOMALY_STATUS
	 */
	default int status() {
		return Token.INFO_STATUS;
	}

	/**
	 * Returns the 16-bit domain-specific token type.
	 *
	 * <p>The type is interpreted within the context of {@link #domain()}.
	 * For {@link Tokens#PROTOCOL_DOMAIN}, the type maps directly to a
	 * {@code ProtocolId} (lower 16 bits). For {@link Tokens#CONTROL_DOMAIN},
	 * the type selects a built-in control operation such as
	 * {@link Tokens#PADDING_BYTES_CONTROL_TOKEN}.</p>
	 *
	 * @return u16 token type (0x0000-0xFFFF)
	 */
	default int type() {
		return Tokens.type(token64());
	}

	/**
	 * Returns the 4-bit word-length field from the standard token header.
	 *
	 * <p>A non-zero value gives the total token size in 32-bit words;
	 * multiply by 4 to obtain the byte count. A value of zero indicates
	 * an extended token whose byte length is stored in the u16 field at
	 * bits 47:32 of the u64 header.</p>
	 *
	 * @return 4-bit word count (0-15); 0 means extended format
	 * @see #isToken32()
	 * @see #isToken64()
	 * @see #length()
	 */
	default int wordLength() {
		return Tokens.wordLength(token64());
	}

	/**
	 * Returns the raw u64 token value.
	 *
	 * <p>For standard tokens the upper 32 bits are zero. For extended tokens
	 * the upper 32 bits carry the {@code token_len} u16 at bits 47:32 and the
	 * {@code opaque} u16 at bits 63:48. All bit-level accessors in {@link Tokens}
	 * operate on this value.</p>
	 *
	 * @return the 64-bit token word in host byte order
	 */
	long token64();
}