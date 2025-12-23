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

import java.lang.foreign.MemoryLayout;

import com.slytechs.sdk.common.memory.MemoryHandle.ByteHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.IntHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.LongHandle;

import static java.lang.foreign.MemoryLayout.*;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class Ip6AddressMemory extends IpAddressMemory implements Ip6Address {

	public static final MemoryLayout LAYOUT = unionLayout(
			sequenceLayout(LENGTH / U8_BE.byteSize(), U8_BE).withName("byte_array"),
			sequenceLayout(LENGTH / U32_BE.byteSize(), U32_BE).withName("int_array"),
			sequenceLayout(LENGTH / U64_BE.byteSize(), U64_BE).withName("long_array"));

	// Use MemoryHandle instead of VarHandle
	private static final ByteHandle BYTE_ARRAY = new ByteHandle(LAYOUT, "byte_array[]");
	private static final IntHandle INT_ARRAY = new IntHandle(LAYOUT, "int_array[]");
	private static final LongHandle LONG_ARRAY = new LongHandle(LAYOUT, "long_array[]");

	public Ip6AddressMemory() {
		super(LAYOUT);
	}

	@Override
	public byte[] bytes(byte[] dst, int offset) {
		for (int i = 0; i < LENGTH; i++) {
			dst[offset + i] = BYTE_ARRAY.getByteAtIndex(view(), i);
		}
		return dst;
	}

	@Override
	public byte byteAt(int index) {
		return BYTE_ARRAY.getByteAtIndex(view(), index);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Ip6Address#asLongHigh()
	 */
	@Override
	public long asLongHigh() {
		return LONG_ARRAY.getLongAtIndex(view(), 0);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Ip6Address#asLongLow()
	 */
	@Override
	public long asLongLow() {
		return LONG_ARRAY.getLongAtIndex(view(), 1);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Ip6Address#longs(long[])
	 */
	@Override
	public long[] longs(long[] dst) {
		dst[0] = asLongHigh();
		dst[1] = asLongLow();
		return dst;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Ip6Address#ints(int[])
	 */
	@Override
	public int[] ints(int[] dst) {
		dst[0] = intAt(0);
		dst[1] = intAt(1);
		dst[2] = intAt(2);
		dst[3] = intAt(3);
		return dst;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Ip6Address#intAt(int)
	 */
	@Override
	public int intAt(int index) {
		return INT_ARRAY.getIntAtIndex(view(), index);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Ip6Address#longAt(int)
	 */
	@Override
	public long longAt(int index) {
		return LONG_ARRAY.getLongAtIndex(view(), index);
	}

	@Override
	public String toString() {
		return Ip6Address.formatIpv6Address(bytes());
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Address#setBytes(byte[])
	 */
	@Override
	public void setBytes(byte[] addr) {
		if (addr.length != LENGTH) {
			throw new IllegalArgumentException("IPv6 address must be " + LENGTH + " bytes");
		}
		for (int i = 0; i < LENGTH; i++) {
			BYTE_ARRAY.setByteAtIndex(view(), i, addr[i]);
		}
	}

	/**
	 * Sets the high 64 bits of the IPv6 address.
	 * 
	 * @param value the high 64 bits
	 */
	public void setLongHigh(long value) {
		LONG_ARRAY.setLongAtIndex(view(), 0, value);
	}

	/**
	 * Sets the low 64 bits of the IPv6 address.
	 * 
	 * @param value the low 64 bits
	 */
	public void setLongLow(long value) {
		LONG_ARRAY.setLongAtIndex(view(), 1, value);
	}

	/**
	 * Sets the IPv6 address from two longs.
	 * 
	 * @param high the high 64 bits
	 * @param low  the low 64 bits
	 */
	public void setLongs(long high, long low) {
		setLongHigh(high);
		setLongLow(low);
	}

	/**
	 * Sets an int value at the specified index.
	 * 
	 * @param index the index (0-3)
	 * @param value the int value
	 */
	public void setIntAt(int index, int value) {
		INT_ARRAY.setIntAtIndex(view(), index, value);
	}
}