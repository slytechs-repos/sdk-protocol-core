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

import java.lang.foreign.MemoryLayout;

import com.slytechs.jnet.core.api.memory.MemoryHandle.ByteHandle;
import com.slytechs.jnet.core.api.memory.MemoryHandle.IntHandle;

import static java.lang.foreign.MemoryLayout.*;

/**
 * IPv4 address implementation.
 */
public final class Ip4AddressMemory extends IpAddressMemory implements Ip4Address {

	public static final MemoryLayout LAYOUT = unionLayout(
			sequenceLayout(LENGTH, U8_BE).withName("byte_array"),
			U32_BE_A1.withName("int_value")).withByteAlignment(1);

	// Use MemoryHandle instead of VarHandle
	private static final ByteHandle BYTE_ARRAY = new ByteHandle(LAYOUT, "byte_array[]");
	private static final IntHandle INT_VALUE = new IntHandle(LAYOUT, "int_value");

	public Ip4AddressMemory() {
		super(LAYOUT);
	}

	@Override
	public int asInt() {
		return INT_VALUE.getInt(view());
	}

	@Override
	public String toString() {
		return Ip4Address.formatIpv4Address(bytes());
	}

	@Override
	public byte byteAt(int index) {
		return BYTE_ARRAY.getByteAtIndex(view(), index);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Address#setBytes(byte[])
	 */
	@Override
	public void setBytes(byte[] addr) {
		if (addr.length != LENGTH) {
			throw new IllegalArgumentException("IPv4 address must be " + LENGTH + " bytes");
		}
		for (int i = 0; i < LENGTH; i++) {
			BYTE_ARRAY.setByteAtIndex(view(), i, addr[i]);
		}
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Ip4Address#setInt(int)
	 */
	@Override
	public void setInt(int addr) {
		INT_VALUE.setInt(view(), 0, addr);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Address#bytes(byte[], int)
	 */
	@Override
	public byte[] bytes(byte[] dst, int offset) {
		for (int i = 0; i < LENGTH; i++) {
			dst[offset + i] = BYTE_ARRAY.getByteAtIndex(view(), i);
		}
		return dst;
	}
}