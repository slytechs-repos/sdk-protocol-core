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
public class MacAddressMemory extends AddressMemory implements MacAddress {
	public static final MemoryLayout LAYOUT$BIG$SIZE_6 = unionLayout(
			sequenceLayout(LENGTH, JAVA_BYTE).withName("byte_array"),
			structLayout(
					BIG_SHORT.withName("high"),
					BIG_INT.withName("low")

			).withName("fast_path")

	);

	public static final MemoryLayout LAYOUT = LAYOUT$BIG$SIZE_6;

	private static final VarHandle BYTE_ARRAY = LAYOUT.varHandle(groupElement("byte_array"), sequenceElement());
	private static final VarHandle HIGH = LAYOUT.varHandle(groupElement("fast_path"), groupElement("high"));
	private static final VarHandle LOW = LAYOUT.varHandle(groupElement("fast_path"), groupElement("low"));

	public MacAddressMemory(Arena arena) {
		super(LAYOUT, arena);
	}

	public MacAddressMemory() {
		super(LAYOUT);
	}

	public MacAddressMemory(MemorySegment pointer, Arena arena) {
		super(LAYOUT, pointer, arena);
	}

	public MacAddressMemory(MemorySegment segment, long offset) {
		super(LAYOUT, segment, offset);
	}

	public MacAddressMemory(MemorySegment pointer) {
		super(LAYOUT, pointer);
	}

	@Override
	public byte[] bytes(byte[] dst, int offset) {
		return bytesUsingVarHandle(BYTE_ARRAY, dst, offset);
	}

	@Override
	public byte byteAt(int index) {
		return (byte) BYTE_ARRAY.get(asMemorySegment(), activeBytesStart(), index);
	}

	@Override
	public long asLong() {
		// Read 1st 4 bytes quickly
		int high = (int) HIGH.get(asMemorySegment(), activeBytesStart());
		int low = (short) LOW.get(asMemorySegment(), activeBytesStart()) & 0xFFFF;

		return low | (high << 32);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Address#setBytes(byte[])
	 */
	@Override
	public void setBytes(byte[] addr) {
		setBytesUsingVarhandle(BYTE_ARRAY, addr);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.MacAddress#setLong(long)
	 */
	@Override
	public void setLong(long addr) {
		short high = (short) ((addr >> 32) & 0xFFFF);
		int low = (int) (addr & 0xFFFF);

		HIGH.set(asMemorySegment(), activeBytesStart(), high);
		LOW.set(asMemorySegment(), activeBytesStart(), low);
	}
}
