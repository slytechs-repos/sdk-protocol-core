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
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface MacAddress extends Address {

	int LENGTH = 6;
	MacAddress BROADCAST = new MacAddressRecord(new byte[] {
			(byte) 0xFF,
			(byte) 0xFF,
			(byte) 0xFF,
			(byte) 0xFF,
			(byte) 0xFF,
			(byte) 0xFF
	});
	MacAddress ZERO = new MacAddressRecord(new byte[6]);

	static String formatMacAddress(byte[] bytes) {
		return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
				bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF,
				bytes[3] & 0xFF, bytes[4] & 0xFF, bytes[5] & 0xFF);
	}

	static byte[] parseMacAddress(String mac) {
		String[] parts = mac.split("[:-]");
		if (parts.length != 6) {
			throw new IllegalArgumentException("Invalid MAC address format: " + mac);
		}

		byte[] bytes = new byte[6];
		for (int i = 0; i < 6; i++) {
			bytes[i] = (byte) Integer.parseInt(parts[i], 16);
		}
		return bytes;
	}

	long asLong();

	default void setLong(long addr) {
		throw new UnsupportedOperationException(Addresses.unsupportedMessage(getClass().getSimpleName()));
	}

	@Override
	default AddressFamily family() {
		return AddressFamily.ETHERNET;
	}

	@Override
	default boolean isBroadcast() {
		return equals(BROADCAST);
	}

	@Override
	default boolean isMulticast() {
		return (byteAt(0) & 0x01) != 0;
	}

	default boolean isLocallyAdministered() {
		return (byteAt(0) & 0x02) != 0;
	}

	default boolean isUniversallyAdministered() {
		return !isLocallyAdministered();
	}

	@Override
	default long length() {
		return LENGTH;
	}
}