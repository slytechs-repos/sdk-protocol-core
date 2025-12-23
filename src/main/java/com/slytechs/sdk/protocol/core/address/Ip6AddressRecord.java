/*
 * Sly Technologies Free License
 * 
 * Copyright 2025 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.sdk.protocol.core.address;

/**
 * IPv6 address implementation.
 */
public record Ip6AddressRecord(byte[] bytes, long asLongHigh, long asLongLow) implements Ip6Address {
	public Ip6AddressRecord(long high, long low) {
		this(new byte[] {
				(byte) (high >>> 56),
				(byte) (high >>> 48),
				(byte) (high >>> 40),
				(byte) (high >>> 32),
				(byte) (high >>> 24),
				(byte) (high >>> 16),
				(byte) (high >>> 8),
				(byte) high,

				(byte) (low >>> 56),
				(byte) (low >>> 48),
				(byte) (low >>> 40),
				(byte) (low >>> 32),
				(byte) (low >>> 24),
				(byte) (low >>> 16),
				(byte) (low >>> 8),
				(byte) low

		}, high, low);
	}

	public Ip6AddressRecord(byte[] addr) {
		this(addr,
				// Reconstitute high 64 bits from bytes 0-7
				((long) (addr[0] & 0xFF) << 56) |
						((long) (addr[1] & 0xFF) << 48) |
						((long) (addr[2] & 0xFF) << 40) |
						((long) (addr[3] & 0xFF) << 32) |
						((long) (addr[4] & 0xFF) << 24) |
						((long) (addr[5] & 0xFF) << 16) |
						((long) (addr[6] & 0xFF) << 8) |
						(addr[7] & 0xFF),

				// Reconstitute low 64 bits from bytes 8-15
				((long) (addr[8] & 0xFF) << 56) |
						((long) (addr[9] & 0xFF) << 48) |
						((long) (addr[10] & 0xFF) << 40) |
						((long) (addr[11] & 0xFF) << 32) |
						((long) (addr[12] & 0xFF) << 24) |
						((long) (addr[13] & 0xFF) << 16) |
						((long) (addr[14] & 0xFF) << 8) |
						(addr[15] & 0xFF));
	}

	public Ip6AddressRecord(String addr) {
		this(Ip6Address.parseIpv6Address(addr));
	}

	@Override
	public String toString() {
		return Ip6Address.formatIpv6Address(bytes);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Address#bytes(byte[])
	 */
	@Override
	public byte[] bytes(byte[] dst, int offset) {
		System.arraycopy(bytes, 0, dst, offset, LENGTH);

		return dst;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Address#bytes()
	 */
	@Override
	public byte[] bytes() {
		return bytes;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Address#byteAt(int)
	 */
	@Override
	public byte byteAt(int index) {
		if (index < 0 || index >= LENGTH)
			throw new IndexOutOfBoundsException("Index must be between 0 and 15, got: " + index);

		return bytes[index];
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Ip6Address#longs(long[])
	 */
	@Override
	public long[] longs(long[] dst) {
		dst[0] = asLongHigh;
		dst[1] = asLongLow;

		return dst;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Ip6Address#ints(int[])
	 */
	@Override
	public int[] ints(int[] dst) {
		dst[0] = (int) (asLongHigh >>> 32); // Upper 32 bits of high long
		dst[1] = (int) (asLongHigh & 0xFFFFFFFF); // Lower 32 bits of high long
		dst[2] = (int) (asLongLow >>> 32); // Upper 32 bits of low long
		dst[3] = (int) (asLongLow & 0xFFFFFFFF); // Lower 32 bits of low long
		return dst;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Ip6Address#intAt(int)
	 */
	@Override
	public int intAt(int index) {
		return switch (index) {
		case 0 -> (int) (asLongHigh >>> 32); // Upper 32 bits of high long
		case 1 -> (int) (asLongHigh & 0xFFFFFFFF); // Lower 32 bits of high long
		case 2 -> (int) (asLongLow >>> 32); // Upper 32 bits of low long
		case 3 -> (int) (asLongLow & 0xFFFFFFFF); // Lower 32 bits of low long
		default -> throw new IndexOutOfBoundsException("Index must be between 0 and 3, got: " + index);
		};
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Ip6Address#longAt(int)
	 */
	@Override
	public long longAt(int index) {
		if (index < 0 || index >= 2)
			throw new IndexOutOfBoundsException("Index must be between 0 and 1, got: " + index);

		return index == 0 ? asLongHigh : asLongLow;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Ip6Address other))
			return false;

		return asLongHigh == other.asLongHigh() && asLongLow == other.asLongLow();
	}

}