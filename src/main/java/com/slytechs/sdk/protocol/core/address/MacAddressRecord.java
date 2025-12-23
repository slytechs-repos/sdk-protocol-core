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
 * MAC (Ethernet) address implementation.
 */
public record MacAddressRecord(byte[] bytes, long asLong) implements MacAddress {

	public MacAddressRecord(byte[] bytes) {
		this(Addresses.validateLength(bytes, LENGTH),
				// Reconstitute 48-bit long from bytes 0-5 in big-endian order
				((long) (bytes[0] & 0xFF) << 40) |
						((long) (bytes[1] & 0xFF) << 32) |
						((long) (bytes[2] & 0xFF) << 24) |
						((long) (bytes[3] & 0xFF) << 16) |
						((long) (bytes[4] & 0xFF) << 8) |
						(bytes[5] & 0xFF));
	}

	public MacAddressRecord(long mac) {
		this(new byte[] {
				(byte) (mac >>> 40),
				(byte) (mac >>> 32),
				(byte) (mac >>> 24),
				(byte) (mac >>> 16),
				(byte) (mac >>> 8),
				(byte) mac
		}, mac);
	}

	public MacAddressRecord(String mac) {
		this(MacAddress.parseMacAddress(mac));
	}

	@Override
	public String toString() {
		return MacAddress.formatMacAddress(bytes);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Address#bytes(byte[])
	 */
	@Override
	public byte[] bytes(byte[] dst) {
		dst[0] = bytes[0];
		dst[1] = bytes[1];
		dst[2] = bytes[2];
		dst[3] = bytes[3];
		dst[4] = bytes[4];
		dst[5] = bytes[5];

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
		return bytes[index];
	}

	// Update the default methods in Address interface
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof MacAddress other))
			return false;

		return asLong == other.asLong();
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Address#bytes(byte[], int)
	 */
	@Override
	public byte[] bytes(byte[] dst, int offset) {
		System.arraycopy(bytes, 0, dst, offset, LENGTH);

		return dst;
	}
}