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
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

import com.slytechs.jnet.core.api.memory.MemoryStructureProxy;

import static java.lang.foreign.ValueLayout.*;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public abstract class AddressMemory extends MemoryStructureProxy implements Address {

	protected static final ValueLayout BIG_SHORT = JAVA_SHORT.withOrder(ByteOrder.BIG_ENDIAN).withByteAlignment(1);
	protected static final ValueLayout BIG_INT = JAVA_INT.withOrder(ByteOrder.BIG_ENDIAN).withByteAlignment(1);
	protected static final ValueLayout BIG_LONG = JAVA_LONG.withOrder(ByteOrder.BIG_ENDIAN).withByteAlignment(1);

	protected final byte[] bytesUsingVarHandle(VarHandle byteArrayHandle) {
		return bytesUsingVarHandle(byteArrayHandle, new byte[length()]);
	}

	protected final void setBytesUsingVarhandle(VarHandle byteArrayHandle, byte[] bytes) {
		assert bytes.length == length();

		for (int i = 0; i < bytes.length; i++) {
			byteArrayHandle.set(asMemorySegment(), activeBytesStart(), i, bytes[i]);
		}
	}

	protected final byte[] bytesUsingVarHandle(VarHandle byteArrayHandle, byte[] bytes) {
		return bytesUsingVarHandle(byteArrayHandle, bytes, 0);
	}

	protected final byte[] bytesUsingVarHandle(VarHandle byteArrayHandle, byte[] bytes, int bytesArrayOffset) {
		if (bytes.length != length())
			throw new IllegalArgumentException("array length must be equal to address length");

		for (int i = 0; i < bytes.length; i++)
			bytes[i + bytesArrayOffset] = (byte) byteArrayHandle.get(asMemorySegment(), activeBytesStart(), i);

		return bytes;
	}

	public AddressMemory(MemoryLayout layout) {
		super(layout);
	}

	public AddressMemory(MemoryLayout layout, Arena arena) {
		super(layout, arena);
	}

	public AddressMemory(MemoryLayout layout, MemorySegment pointer, Arena arena) {
		super(layout, pointer, arena);
	}

	public AddressMemory(MemoryLayout layout, MemorySegment segment, long offset) {
		super(layout, segment, offset);
	}

	public AddressMemory(MemoryLayout layout, MemorySegment pointer) {
		super(layout, pointer);
	}

	@Override
	public boolean equals(Object obj) {
		return defaultEquals(obj);
	}
}
