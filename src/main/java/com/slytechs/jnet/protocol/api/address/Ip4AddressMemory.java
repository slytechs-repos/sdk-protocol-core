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
 * IPv4 address implementation.
 */
public final class Ip4AddressMemory extends IpAddressMemory implements Ip4Address {

	public static final MemoryLayout LAYOUT$BIG$SIZE_4 = unionLayout(
			sequenceLayout(LENGTH, JAVA_BYTE).withName("byte_array"),
			BIG_INT.withName("int_value")

	);

	public static final MemoryLayout LAYOUT = LAYOUT$BIG$SIZE_4;

	private static final VarHandle BYTE_ARRAY = LAYOUT.varHandle(groupElement("byte_array"), sequenceElement());
	private static final VarHandle INT_VALUE = LAYOUT.varHandle(groupElement("int_value"));

	public Ip4AddressMemory() {
		super(LAYOUT);
	}

	public Ip4AddressMemory(Arena arena) {
		super(LAYOUT, arena);
	}

	public Ip4AddressMemory(MemorySegment pointer, Arena arena) {
		super(LAYOUT, pointer, arena);
	}

	public Ip4AddressMemory(MemorySegment segment, long offset) {
		super(LAYOUT, segment, offset);
	}

	public Ip4AddressMemory(MemorySegment pointer) {
		super(LAYOUT, pointer);
	}

	@Override
	public int asInt() {
		return (int) INT_VALUE.get(asMemorySegment(), activeBytesStart());
	}

	@Override
	public String toString() {
		return Ip4Address.formatIpv4Address(bytes());
	}

	@Override
	public byte byteAt(int index) {
		return (byte) BYTE_ARRAY.get(asMemorySegment(), activeBytesStart(), index);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Address#setBytes(byte[])
	 */
	@Override
	public void setBytes(byte[] addr) {
		setBytesUsingVarhandle(BYTE_ARRAY, addr);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Ip4Address#setInt(int)
	 */
	@Override
	public void setInt(int addr) {
		INT_VALUE.set(asMemorySegment(), activeBytesStart(), addr);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Address#bytes(byte[], int)
	 */
	@Override
	public byte[] bytes(byte[] dst, int offset) {
		return bytesUsingVarHandle(BYTE_ARRAY, dst, offset);
	}
}