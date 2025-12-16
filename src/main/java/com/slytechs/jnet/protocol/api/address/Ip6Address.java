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
package com.slytechs.jnet.protocol.api.address;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface Ip6Address extends IpAddress {

	int LENGTH = 16;
	Ip6Address LOOPBACK = new Ip6AddressRecord("::1");
	Ip6Address ANY = new Ip6AddressRecord("::");

	/**
	 * Helper method to format IPv6 address bytes as a string. Implements basic IPv6
	 * address formatting with :: compression.
	 */
	static String formatIpv6Address(byte[] bytes) {
		// Convert bytes to 16-bit groups
		int[] groups = new int[8];
		for (int i = 0; i < 8; i++) {
			groups[i] = ((bytes[i * 2] & 0xFF) << 8) | (bytes[i * 2 + 1] & 0xFF);
		}

		// Find longest sequence of zeros for :: compression
		int longestZeroStart = -1;
		int longestZeroLength = 0;
		int currentZeroStart = -1;
		int currentZeroLength = 0;

		for (int i = 0; i < 8; i++) {
			if (groups[i] == 0) {
				if (currentZeroStart == -1) {
					currentZeroStart = i;
					currentZeroLength = 1;
				} else {
					currentZeroLength++;
				}
			} else {
				if (currentZeroLength > longestZeroLength) {
					longestZeroStart = currentZeroStart;
					longestZeroLength = currentZeroLength;
				}
				currentZeroStart = -1;
				currentZeroLength = 0;
			}
		}

		// Check final sequence
		if (currentZeroLength > longestZeroLength) {
			longestZeroStart = currentZeroStart;
			longestZeroLength = currentZeroLength;
		}

		// Format the address
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 8; i++) {
			if (longestZeroLength > 1 && i == longestZeroStart) {
				sb.append("::");
				i += longestZeroLength - 1;
			} else {
				if (i > 0)
					sb.append(":");
				sb.append(String.format("%x", groups[i]));
			}
		}

		return sb.toString();
	}

	static byte[] parseIpv6Address(String addr) {
		// This is a simplified parser - you'd want a more robust implementation
		if ("::".equals(addr)) {
			return new byte[16]; // All zeros
		}
		if ("::1".equals(addr)) {
			byte[] bytes = new byte[16];
			bytes[15] = 1;
			return bytes;
		}

		// For a full implementation, you'd handle IPv6 address parsing properly
		// including :: compression, mixed IPv4/IPv6 notation, etc.
		throw new UnsupportedOperationException("Full IPv6 parsing not implemented in this example");
	}

	long asLongHigh();

	long asLongLow();

	default long[] longs() {
		return longs(new long[2]);
	}

	long[] longs(long[] dst);

	default int[] ints() {
		return ints(new int[4]);
	}

	int[] ints(int[] dst);

	int intAt(int index);

	long longAt(int index);

	@Override
	default AddressFamily family() {
		return AddressFamily.IPv6;
	}

	@Override
	default boolean isBroadcast() {
		return false; // IPv6 doesn't have broadcast
	}

	@Override
	default boolean isLinkLocal() {
		// fe80::/10
		return (byteAt(0) & 0xFF) == 0xFE && (byteAt(1) & 0xC0) == 0x80;
	}

	@Override
	default boolean isLoopback() {
		return equals(LOOPBACK);
	}

	@Override
	default boolean isMulticast() {
		return (byteAt(0) & 0xFF) == 0xFF;
	}

	@Override
	default boolean isPrivate() {
		// Simplified - check for fc00::/7 (Unique Local Addresses)
		return (byteAt(0) & 0xFE) == 0xFC;
	}

	@Override
	default long length() {
		return LENGTH;
	}
}