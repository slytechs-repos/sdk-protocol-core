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
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Static utility methods and constants for encoding, decoding, and
 * memory-accessing VQFS analysis tokens.
 *
 * <p>
 * All token values are little-endian u64 quantities. Standard tokens occupy
 * bits 0-31 (wordLength &gt; 0); extended tokens use the full 64 bits
 * (wordLength == 0, with byte length in bits 47:32). The field layout is:
 * </p>
 *
 * <pre>
 * bits  0- 3   len       u4    word count; 0 = extended format
 * bits  4- 5   status    u2    severity (INFO/NORMAL/WARNING/ANOMALY)
 * bits  6- 7   lod_hint  u2    QAT key-promotion hint
 * bits  8-15   domain    u8    token namespace
 * bits 16-31   type      u16   domain-specific event type
 * bits 32-47   token_len u16   extended only: total byte count
 * bits 48-63   opaque    u16   extended only: domain-defined
 * </pre>
 *
 * <p>
 * The mask/shift pair for each field follows the convention:
 * {@code (token >> FIELD_SHIFT) & FIELD_MASK}.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Token
 */
public interface Tokens {

	// @formatter:off

	/** Mask for the 4-bit word-length field in bits 3:0. */
	int LEN_MASK           = 0xF;

	/** Bit shift for the word-length field (bits 3:0). */
	int LEN_SHIFT          = 0;

	/** Mask for the extended token byte-length field in bits 47:32 (u16). */
	int EXT_LEN_MASK       = 0xFFFF;

	/** Bit shift for the extended token byte-length field (bits 47:32). */
	int EXT_LEN_SHIFT      = 32;

	/** Mask for the extended opaque field in bits 63:48 (u16). */
	int EXT_OPAQUE_MASK    = 0xFFFF;

	/** Bit shift for the extended opaque field (bits 63:48). */
	int EXT_OPAQUE_SHIFT   = 48;

	/** Mask for the 2-bit status field in bits 5:4. */
	int STATUS_MASK        = 0x3;

	/** Bit shift for the status field (bits 5:4). */
	int STATUS_SHIFT       = 4;

	/** Mask for the 2-bit LOD hint field in bits 7:6. */
	int LOD_MASK           = 0x3;

	/** Bit shift for the LOD hint field (bits 7:6). */
	int LOD_SHIFT          = 6;

	/**
	 * Mask for the combined 4-bit status+LOD field in bits 7:2.
	 * Encoding: {@code lod << 2 | status}.
	 */
	int STATUS_LOD_MASK    = 0xF;

	/** Bit shift for the combined status+LOD field (bits 7:2). */
	int STATUS_LOD_SHIFT   = 2;

	/** Mask for the 8-bit domain field in bits 15:8. */
	int DOMAIN_MASK        = 0xFF;

	/** Bit shift for the domain field (bits 15:8). */
	int DOMAIN_SHIFT       = 8;

	/** Mask for the 16-bit type field in bits 31:16. */
	int TYPE_MASK          = 0xFFFF;

	/** Bit shift for the type field (bits 31:16). */
	int TYPE_SHIFT         = 16;

	// @formatter:on

	// @formatter:off

	/** Domain 0x00 — built-in control tokens (padding, index marks, etc.). */
	int CONTROL_DOMAIN              = 0x00;

	/**
	 * Domain 0x01 — protocol-stack tokens. The {@code type} field maps
	 * directly to the lower 16 bits of a {@code ProtocolId}.
	 */
	int PROTOCOL_DOMAIN             = 0x01;

	/** Domain 0x02 — Suricata IDS alert and event tokens. */
	int SURICATA_DOMAIN             = 0x02;

	/** Domain 0x03 — Zeek NSM log entry tokens. */
	int ZEEK_DOMAIN                 = 0x03;

	/** Domain 0x04 — Lynx UI annotation tokens. */
	int LYNX_DOMAIN                 = 0x04;

	/** Domain 0x05 — Vantage Query rule-match and PII-redaction tokens. */
	int VANTAGE_QUERY_DOMAIN        = 0x05;

	/** Domain 0x06 — Vantage Ledger chain-of-custody audit tokens. */
	int VANTAGE_LEDGER_DOMAIN       = 0x06;

	/** Domain 0x07 — user-registered custom analyzer tokens. */
	int USER_DOMAIN                 = 0x07;

	// @formatter:on

	// @formatter:off

	/**
	 * Control token type 0x0000 — padding bytes.
	 * Used to align the token stream to a 4-byte boundary. Always uses the
	 * extended format so that the padding length can be expressed in exact bytes.
	 */
	int PADDING_BYTES_CONTROL_TOKEN         = 0x0000;

	/**
	 * Control token type 0x0001 — seek index entry.
	 * Written by the AEVT jump-table builder to mark a seekable position in
	 * the token stream.
	 */
	int INDEX_CONTROL_TOKEN                 = 0x0001;

	/**
	 * Control token type 0x0002 — PCAPNG section boundary mark.
	 * Emitted when a capture section closes, carrying tombstone state for
	 * flows that span the boundary.
	 */
	int SECTION_MARK_CONTROL_TOKEN          = 0x0002;

	/**
	 * Control token type 0x0003 — analysis version marker.
	 * Appended to the stream when a re-analysis pass begins, allowing readers
	 * to identify the highest analysis version for any token reference.
	 */
	int ANALYSIS_VERSION_CONTROL_TOKEN      = 0x0003;

	// @formatter:on

	/**
	 * {@link VarHandle} for reading and writing a full token u64 from a
	 * {@link MemorySegment} at an arbitrary (unaligned) byte offset,
	 * using little-endian byte order.
	 */
	VarHandle TOKEN_VARHANDLE = ValueLayout.JAVA_LONG_UNALIGNED
			.withOrder(ByteOrder.LITTLE_ENDIAN)
			.withName("token")
			.varHandle();

	/** Little-endian {@link VarHandle} for single-byte (u8) segment access. */
	VarHandle U8  = ValueLayout.JAVA_BYTE .withOrder(ByteOrder.LITTLE_ENDIAN).varHandle();

	/** Little-endian {@link VarHandle} for two-byte (u16) segment access. */
	VarHandle U16 = ValueLayout.JAVA_SHORT.withOrder(ByteOrder.LITTLE_ENDIAN).varHandle();

	/** Little-endian {@link VarHandle} for four-byte (u32) segment access. */
	VarHandle U32 = ValueLayout.JAVA_INT  .withOrder(ByteOrder.LITTLE_ENDIAN).varHandle();

	/** Little-endian {@link VarHandle} for eight-byte (u64) segment access. */
	VarHandle U64 = ValueLayout.JAVA_LONG .withOrder(ByteOrder.LITTLE_ENDIAN).varHandle();

	/**
	 * Reads an unsigned byte from {@code seg} at {@code offset}.
	 *
	 * @param seg    the source memory segment
	 * @param offset byte offset within the segment
	 * @return unsigned byte value (0-255)
	 */
	static int u8(MemorySegment seg, long offset) {
		return Byte.toUnsignedInt((byte) U8.get(seg, offset));
	}

	/**
	 * Writes a byte value to {@code seg} at {@code offset}.
	 *
	 * @param seg      the destination memory segment
	 * @param offset   byte offset within the segment
	 * @param newValue the byte to write
	 * @return number of bytes written (always 1)
	 */
	static int u8(MemorySegment seg, long offset, byte newValue) {
		U8.set(seg, offset, newValue);
		return 1;
	}

	/**
	 * Writes the low byte of {@code newValue} to {@code seg} at {@code offset}.
	 *
	 * @param seg      the destination memory segment
	 * @param offset   byte offset within the segment
	 * @param newValue value whose low byte is written
	 * @return number of bytes written (always 1)
	 */
	static int u8(MemorySegment seg, long offset, int newValue) {
		U8.set(seg, offset, (byte) newValue);
		return 1;
	}

	/**
	 * Reads an unsigned 16-bit value from {@code seg} at {@code offset},
	 * using little-endian byte order.
	 *
	 * @param seg    the source memory segment
	 * @param offset byte offset within the segment
	 * @return unsigned 16-bit value (0-65535)
	 */
	static int u16(MemorySegment seg, long offset) {
		return Short.toUnsignedInt((short) U16.get(seg, offset));
	}

	/**
	 * Writes the low 16 bits of {@code newValue} to {@code seg} at {@code offset},
	 * using little-endian byte order.
	 *
	 * @param seg      the destination memory segment
	 * @param offset   byte offset within the segment
	 * @param newValue value whose low 16 bits are written
	 * @return number of bytes written (always 2)
	 */
	static int u16(MemorySegment seg, long offset, int newValue) {
		U16.set(seg, offset, (short) newValue);
		return 2;
	}

	/**
	 * Writes a {@code short} value to {@code seg} at {@code offset},
	 * using little-endian byte order.
	 *
	 * @param seg      the destination memory segment
	 * @param offset   byte offset within the segment
	 * @param newValue the short to write
	 * @return number of bytes written (always 2)
	 */
	static int u16(MemorySegment seg, long offset, short newValue) {
		U16.set(seg, offset, newValue);
		return 2;
	}

	/**
	 * Reads a signed 32-bit value from {@code seg} at {@code offset},
	 * using little-endian byte order.
	 *
	 * <p>Use {@code Integer.toUnsignedLong()} on the result when an unsigned
	 * interpretation is needed.</p>
	 *
	 * @param seg    the source memory segment
	 * @param offset byte offset within the segment
	 * @return 32-bit value (signed)
	 */
	static int u32(MemorySegment seg, long offset) {
		return (int) U32.get(seg, offset);
	}

	/**
	 * Writes a 32-bit value to {@code seg} at {@code offset},
	 * using little-endian byte order.
	 *
	 * @param seg      the destination memory segment
	 * @param offset   byte offset within the segment
	 * @param newValue the value to write
	 * @return number of bytes written (always 4)
	 */
	static int u32(MemorySegment seg, long offset, int newValue) {
		U32.set(seg, offset, newValue);
		return 4;
	}

	/**
	 * Reads a 64-bit token value from {@code seg} at {@code offset},
	 * using little-endian byte order.
	 *
	 * @param seg    the source memory segment
	 * @param offset byte offset within the segment
	 * @return 64-bit token word
	 */
	static long u64(MemorySegment seg, long offset) {
		return (long) U64.get(seg, offset);
	}

	/**
	 * Writes a 64-bit value to {@code seg} at {@code offset},
	 * using little-endian byte order.
	 *
	 * @param seg      the destination memory segment
	 * @param offset   byte offset within the segment
	 * @param newValue the value to write
	 * @return number of bytes written (always 8)
	 */
	static int u64(MemorySegment seg, long offset, long newValue) {
		U64.set(seg, offset, newValue);
		return 8;
	}

	/**
	 * Reads a u64 token header from the current position of {@code b},
	 * advancing the buffer position by 8 bytes.
	 *
	 * <p>Always reads 8 bytes. For a standard token the upper 32 bits will
	 * be zero (or contain unrelated stream data); callers should check
	 * {@link #wordLength(long)} before interpreting them.</p>
	 *
	 * @param b the little-endian source buffer
	 * @return 64-bit token word
	 */
	static long header(ByteBuffer b) {
		assert b.order() == ByteOrder.LITTLE_ENDIAN;
		return b.getLong();
	}

	/**
	 * Reads a u64 token header from {@code b} at the given absolute byte
	 * index without advancing the buffer position.
	 *
	 * @param b     the little-endian source buffer
	 * @param index byte offset within the buffer
	 * @return 64-bit token word
	 */
	static long header(ByteBuffer b, int index) {
		assert b.order() == ByteOrder.LITTLE_ENDIAN;
		return b.getLong(index);
	}

	/**
	 * Reads a u64 token header from {@code seg} at the given byte offset,
	 * using an unaligned little-endian read via {@link #TOKEN_VARHANDLE}.
	 *
	 * @param seg    the source memory segment
	 * @param offset byte offset within the segment
	 * @return 64-bit token word
	 */
	static long header(MemorySegment seg, long offset) {
		return (long) TOKEN_VARHANDLE.get(seg, offset);
	}

	/**
	 * Extracts the 2-bit LOD hint from a token word.
	 *
	 * @param token the 64-bit token word
	 * @return LOD value 0-3
	 */
	static int lod(long token) {
		return (int) ((token >> LOD_SHIFT) & LOD_MASK);
	}

	/**
	 * Extracts the 4-bit word-length field from a token word.
	 *
	 * <p>A non-zero return value is the token's total size in 32-bit words.
	 * Zero indicates extended format — call {@link #length(long)} to obtain
	 * the byte count from the extended header field.</p>
	 *
	 * @param token the 64-bit token word
	 * @return word count 0-15; 0 means extended format
	 */
	static int wordLength(long token) {
		return (int) (token & LEN_MASK);
	}

	/**
	 * Returns the total length of a token in bytes.
	 *
	 * <p>For standard tokens ({@code wordLength > 0}) the result is
	 * {@code wordLength * 4}. For extended tokens ({@code wordLength == 0})
	 * the result is the u16 value stored in bits 47:32.</p>
	 *
	 * @param token the 64-bit token word
	 * @return total token length in bytes
	 */
	static int length(long token) {
		int wlen = (int) (token & LEN_MASK);
		if (wlen != 0)
			return wlen << 2;

		return (int) ((token >> EXT_LEN_SHIFT) & EXT_LEN_MASK);
	}

	/**
	 * Extracts the opaque u16 field from an extended token (bits 63:48).
	 *
	 * <p>The opaque field is domain-defined. It is not present in standard
	 * tokens; calling this method on a standard token (wordLength &gt; 0)
	 * throws {@link IllegalStateException}.</p>
	 *
	 * @param token the 64-bit extended token word
	 * @return opaque value 0-65535
	 * @throws IllegalStateException if the token is not in extended format
	 */
	static int opaque(long token) {
		if ((token & LEN_MASK) != 0)
			throw new IllegalStateException("invalid extended token length");
		return (int) ((token >> EXT_OPAQUE_SHIFT) & EXT_OPAQUE_MASK);
	}

	/**
	 * Extracts the 2-bit status field from a token word.
	 *
	 * @param token the 64-bit token word
	 * @return status value 0-3 (INFO/NORMAL/WARNING/ANOMALY)
	 */
	static int status(long token) {
		return (int) ((token >> STATUS_SHIFT) & STATUS_MASK);
	}

	/**
	 * Extracts the combined 4-bit status+LOD field from a token word.
	 *
	 * <p>Encoding is {@code lod << 2 | status}, covering bits 7:2.</p>
	 *
	 * @param token the 64-bit token word
	 * @return combined status+LOD value 0-15
	 */
	static int statusLod(long token) {
		return (int) ((token >> STATUS_LOD_SHIFT) & STATUS_LOD_MASK);
	}

	/**
	 * Extracts the 8-bit domain field from a token word.
	 *
	 * @param token the 64-bit token word
	 * @return domain value 0x00-0xFF
	 */
	static int domain(long token) {
		return (int) ((token >> DOMAIN_SHIFT) & DOMAIN_MASK);
	}

	/**
	 * Extracts the 16-bit type field from a token word.
	 *
	 * @param token the 64-bit token word
	 * @return type value 0x0000-0xFFFF
	 */
	static int type(long token) {
		return (int) ((token >> TYPE_SHIFT) & TYPE_MASK);
	}

	/**
	 * Constructs an extended (u64) token word without an opaque value.
	 *
	 * <p>The word-length nibble (bits 3:0) is set to zero, signalling
	 * extended format. The byte length is stored in bits 47:32.</p>
	 *
	 * @param length total token length in bytes (0-65535)
	 * @param status 2-bit status value
	 * @param lod    2-bit LOD hint
	 * @param domain 8-bit domain
	 * @param type   16-bit type
	 * @return 64-bit extended token word
	 */
	static long token64(int length, int status, int lod, int domain, int type) {
		return 0L
				| ((long)(length & EXT_LEN_MASK) << EXT_LEN_SHIFT)
				| ((status & STATUS_MASK) << STATUS_SHIFT)
				| ((lod    & LOD_MASK)    << LOD_SHIFT)
				| ((domain & DOMAIN_MASK) << DOMAIN_SHIFT)
				| ((type   & TYPE_MASK)   << TYPE_SHIFT);
	}

	/**
	 * Constructs an extended (u64) token word with a domain-defined opaque value.
	 *
	 * @param length total token length in bytes (0-65535)
	 * @param status 2-bit status value
	 * @param lod    2-bit LOD hint
	 * @param domain 8-bit domain
	 * @param type   16-bit type
	 * @param opaque 16-bit domain-defined opaque value stored in bits 63:48
	 * @return 64-bit extended token word
	 */
	static long token64(int length, int status, int lod, int domain, int type, int opaque) {
		return 0L
				| ((long)(length & EXT_LEN_MASK) << EXT_LEN_SHIFT)
				| ((status & STATUS_MASK)         << STATUS_SHIFT)
				| ((lod    & LOD_MASK)             << LOD_SHIFT)
				| ((domain & DOMAIN_MASK)          << DOMAIN_SHIFT)
				| ((type   & TYPE_MASK)            << TYPE_SHIFT)
				| ((long)(opaque & EXT_OPAQUE_MASK) << EXT_OPAQUE_SHIFT);
	}

	/**
	 * Sets the extended byte-length field (bits 47:32) of an existing token
	 * word without disturbing any other field.
	 *
	 * <p>Intended for two-phase construction: build the header fields first
	 * with {@link #token64(int, int, int, int, int)}, then apply the final
	 * length once the payload size is known.</p>
	 *
	 * @param token  the existing 64-bit token word
	 * @param length byte length to OR into bits 47:32 (0-65535)
	 * @return updated token word
	 */
	static long setLength(long token, int length) {
		return token | ((long)(length & EXT_LEN_MASK) << EXT_LEN_SHIFT);
	}

	/**
	 * Constructs a token word, automatically selecting standard or extended
	 * format based on the requested length.
	 *
	 * <p>Tokens of 64 bytes or fewer are encoded as standard u32 tokens
	 * (zero-extended to u64). Tokens larger than 64 bytes use the extended
	 * u64 format. The length must be a multiple of 4.</p>
	 *
	 * @param length total token length in bytes; must be a multiple of 4
	 * @param status 2-bit status value
	 * @param lod    2-bit LOD hint
	 * @param domain 8-bit domain
	 * @param type   16-bit type
	 * @return 64-bit token word in standard or extended format
	 * @throws AssertionError if {@code length % 4 != 0} and assertions are enabled
	 */
	static long token(int length, int status, int lod, int domain, int type) {
		assert length % 4 == 0;

		if (length > 64)
			return Tokens.token64(length, status, lod, domain, type);
		else
			return Integer.toUnsignedLong(
					Tokens.token32(length, status, lod, domain, type));
	}

	/**
	 * Constructs a standard (u32) token word.
	 *
	 * <p>The {@code len} parameter is the total token size in bytes; it is
	 * converted to a word count ({@code len >> 2}) before being stored in
	 * the 4-bit word-length field. The caller is responsible for ensuring
	 * the value is a multiple of 4 and fits in 4 bits (4-60 bytes).</p>
	 *
	 * @param len    total token length in bytes (must be a multiple of 4, 4-60)
	 * @param status 2-bit status value
	 * @param lod    2-bit LOD hint
	 * @param domain 8-bit domain
	 * @param type   16-bit type
	 * @return 32-bit token word
	 */
	static int token32(int len, int status, int lod, int domain, int type) {
		return 0
				| (((len >> 2) & LEN_MASK) << LEN_SHIFT)
				| ((status & STATUS_MASK)  << STATUS_SHIFT)
				| ((lod    & LOD_MASK)     << LOD_SHIFT)
				| ((domain & DOMAIN_MASK)  << DOMAIN_SHIFT)
				| ((type   & TYPE_MASK)    << TYPE_SHIFT);
	}
}