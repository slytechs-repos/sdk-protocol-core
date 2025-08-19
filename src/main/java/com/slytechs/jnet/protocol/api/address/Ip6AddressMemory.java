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

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class Ip6AddressMemory extends IpAddressMemory implements Ip6Address {

	public static final MemoryLayout LAYOUT$BIG$SIZE_16 = unionLayout(
			sequenceLayout(LENGTH, JAVA_BYTE).withName("byte_array"),
			sequenceLayout(LENGTH / BIG_INT.byteSize(), BIG_INT).withName("int_array"),
			sequenceLayout(LENGTH / BIG_LONG.byteSize(), BIG_LONG).withName("long_array"));

	public static final MemoryLayout LAYOUT = LAYOUT$BIG$SIZE_16;

	private static final VarHandle BYTE_ARRAY = LAYOUT.varHandle(groupElement("byte_array"), sequenceElement());
	private static final VarHandle INT_ARRAY = LAYOUT.varHandle(groupElement("int_array"), sequenceElement());
	private static final VarHandle LONG_ARRAY = LAYOUT.varHandle(groupElement("long_array"), sequenceElement());

	public Ip6AddressMemory() {
		super(LAYOUT);
	}

	public Ip6AddressMemory(Arena arena) {
		super(LAYOUT, arena);
	}

	public Ip6AddressMemory(MemorySegment pointer) {
		super(LAYOUT, pointer);
	}

	public Ip6AddressMemory(MemorySegment pointer, Arena arena) {
		super(LAYOUT, pointer, arena);
	}

	public Ip6AddressMemory(MemorySegment segment, long offset) {
		super(LAYOUT, segment, offset);
	}

	@Override
	public byte[] bytes(byte[] dst, int offset) {
		return bytesUsingVarHandle(BYTE_ARRAY, dst, offset);
	}

	@Override
	public byte byteAt(int index) {
		return (byte) BYTE_ARRAY.get(asMemorySegment(), activeBytesStart(), index);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Ip6Address#asLongHigh()
	 */
	@Override
	public long asLongHigh() {
		return (long) LONG_ARRAY.get(asMemorySegment(), activeBytesStart(), 0);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Ip6Address#asLongLow()
	 */
	@Override
	public long asLongLow() {
		return (long) LONG_ARRAY.get(asMemorySegment(), activeBytesStart(), 1);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Ip6Address#longs(long[])
	 */
	@Override
	public long[] longs(long[] dst) {

		dst[0] = asLongHigh();
		dst[1] = asLongLow();

		return dst;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Ip6Address#ints(int[])
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
	 * @see com.slytechs.jnet.protocol.api.address.Ip6Address#intAt(int)
	 */
	@Override
	public int intAt(int index) {
		return (int) INT_ARRAY.get(asMemorySegment(), activeBytesStart(), index);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Ip6Address#longAt(int)
	 */
	@Override
	public long longAt(int index) {
		return (long) LONG_ARRAY.get(asMemorySegment(), activeBytesStart(), index);
	}

	@Override
	public String toString() {
		return Ip6Address.formatIpv6Address(bytes());
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Address#setBytes(byte[])
	 */
	@Override
	public void setBytes(byte[] addr) {
		setBytesUsingVarhandle(BYTE_ARRAY, addr);
	}
}
