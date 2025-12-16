/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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
package com.slytechs.jnet.protocol.api.address;

import java.util.Arrays;

/**
 * Base class for all network addresses. Provides common functionality for
 * address types.
 */
public interface Address extends Comparable<Address> {

	/**
	 * Static equals method that compares two addresses with type safety. Validates
	 * that addresses are compatible types and their relevant values match.
	 * 
	 * @param addr1 first address (can be null)
	 * @param addr2 second address (can be null)
	 * @return true if addresses are logically equal
	 */
	static boolean equals(Address addr1, Address addr2) {
		// Handle null cases
		if (addr1 == addr2)
			return true; // Both null or same reference
		if (addr1 == null || addr2 == null)
			return false;

		// Must be same address family
		if (addr1.family() != addr2.family()) {
			return false;
		}

		// Must be same length
		if (addr1.length() != addr2.length()) {
			return false;
		}

		// Fallback to byte-by-byte comparison
		return byteArrayEquals(addr1, addr2);
	}

	default boolean defaultEquals(Object other) {
		if (other instanceof Address addr)
			return equals(this, addr);

		return false;
	}

	/**
	 * Byte-by-byte comparison fallback.
	 */
	static boolean byteArrayEquals(Address addr1, Address addr2) {
		long length = addr1.length();
		for (int i = 0; i < length; i++) {
			if (addr1.byteAt(i) != addr2.byteAt(i)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns the raw bytes of this address.
	 */
	default byte[] bytes() {
		return bytes(new byte[(int) length()]);
	}

	/**
	 * Copies address bytes into the supplied 'dst' array.
	 *
	 * @param dst the address bytes destination at offset 0
	 * @return the same supplied dst array
	 */
	default byte[] bytes(byte[] dst) {
		return bytes(dst, 0);
	}

	/**
	 * Copies address bytes into the supplied 'dst' array at specified offset.
	 *
	 * @param dst    the address bytes destination at offset 0
	 * @param offset the offset in bytes into the destination array
	 * @return the same supplied dst array
	 */
	byte[] bytes(byte[] dst, int offset);

	/**
	 * Retrieves a byte of the address at specified index.
	 *
	 * @param index the byte index into the address array
	 * @return the address byte
	 */
	byte byteAt(int index);

	/**
	 * Returns the length of this address in bytes.
	 */
	long length();

	/**
	 * Returns the address family/type.
	 */
	AddressFamily family();

	/**
	 * Returns true if this is a broadcast/multicast address.
	 */
	boolean isBroadcast();

	/**
	 * Returns true if this is a multicast address.
	 */
	boolean isMulticast();

	@Override
	default int compareTo(Address other) {
		if (this.length() != other.length())
			return Long.compare(this.length(), other.length());

		return Arrays.compare(this.bytes(), other.bytes());
	}

	default void setBytes(byte[] addr) {
		throw new UnsupportedOperationException(Addresses.unsupportedMessage(getClass().getSimpleName()));
	}

}