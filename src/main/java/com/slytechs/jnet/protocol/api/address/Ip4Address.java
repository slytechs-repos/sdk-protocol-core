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
public interface Ip4Address extends IpAddress {

	Ip4Address LOOPBACK = new Ip4AddressRecord("127.0.0.1");
	Ip4Address ANY = new Ip4AddressRecord("0.0.0.0");
	Ip4Address BROADCAST = new Ip4AddressRecord("255.255.255.255");

	int LENGTH = 4;

	static int parseIpv4Address(String addr) {
		String[] parts = addr.split("\\.");
		if (parts.length != 4) {
			throw new IllegalArgumentException("Invalid IPv4 address: " + addr);
		}

		int result = 0;
		for (String part : parts) {
			int octet = Integer.parseInt(part);
			if (octet < 0 || octet > 255) {
				throw new IllegalArgumentException("Invalid octet: " + octet);
			}
			result = (result << 8) | octet;
		}
		return result;
	}

	static String formatIpv4Address(byte[] bytes) {
		assert bytes.length == LENGTH;

		StringBuilder sb = new StringBuilder();

		sb.append(bytes[0] & 0xFF).append('.');
		sb.append(bytes[1] & 0xFF).append('.');
		sb.append(bytes[2] & 0xFF).append('.');
		sb.append(bytes[3] & 0xFF);

		return sb.toString();
	}

	int asInt();
	
	default void setInt(int addr) {
		throw new UnsupportedOperationException(Addresses.unsupportedMessage(getClass().getSimpleName()));
	}

	@Override
	default AddressFamily family() {
		return AddressFamily.IPv4;
	}

	@Override
	default int length() {
		return LENGTH;
	}

	@Override
	default boolean isBroadcast() {
		return equals(BROADCAST);
	}

	@Override
	default boolean isMulticast() {
		int firstOctet = bytes()[0] & 0xFF;
		return firstOctet >= 224 && firstOctet <= 239; // 224.0.0.0/4
	}

	@Override
	default boolean isLoopback() {
		return (bytes()[0] & 0xFF) == 127; // 127.0.0.0/8
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Ip4Address#isPrivate()
	 */
	@Override
	default boolean isPrivate() {
		var bytes = bytes();

		int firstOctet = bytes[0] & 0xFF;
		int secondOctet = bytes[1] & 0xFF;

		// 10.0.0.0/8
		if (firstOctet == 10)
			return true;

		// 172.16.0.0/12
		if (firstOctet == 172 && secondOctet >= 16 && secondOctet <= 31)
			return true;

		// 192.168.0.0/16
		if (firstOctet == 192 && secondOctet == 168)
			return true;

		return false;
	}

	@Override
	default boolean isLinkLocal() {
		var bytes = bytes();
		int firstOctet = bytes[0] & 0xFF;
		int secondOctet = bytes[1] & 0xFF;
		return firstOctet == 169 && secondOctet == 254; // 169.254.0.0/16
	}
}