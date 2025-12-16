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
 * IPv4 address implementation.
 */
public record Ip4AddressRecord(byte[] bytes, int asInt) implements Ip4Address {

	public Ip4AddressRecord(int addr) {
		this(new byte[] {
				(byte) (addr >>> 24),
				(byte) (addr >>> 16),
				(byte) (addr >>> 8),
				(byte) addr
		}, addr);
	}

	public Ip4AddressRecord(byte[] addr) {
		this(addr,
				// Reconstitute 32-bit int from bytes 0-3 in big-endian order
				((addr[0] & 0xFF) << 24) |
						((addr[1] & 0xFF) << 16) |
						((addr[2] & 0xFF) << 8) |
						(addr[3] & 0xFF));
	}

	public Ip4AddressRecord(String addr) {
		this(Ip4Address.parseIpv4Address(addr));
	}

	@Override
	public String toString() {
		return Ip4Address.formatIpv4Address(bytes);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Address#bytes(byte[])
	 */
	@Override
	public byte[] bytes(byte[] dst) {
		dst[0] = bytes[0];
		dst[1] = bytes[1];
		dst[2] = bytes[2];
		dst[3] = bytes[3];

		return dst;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Address#bytes()
	 */
	@Override
	public byte[] bytes() {
		return bytes;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Address#byteAt(int)
	 */
	@Override
	public byte byteAt(int index) {
		return bytes[index];
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Ip4Address other))
			return false;

		return asInt == other.asInt();
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Address#bytes(byte[], int)
	 */
	@Override
	public byte[] bytes(byte[] dst, int offset) {
		System.arraycopy(bytes, 0, dst, offset, (int) length());

		return dst;
	}
}