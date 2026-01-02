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
import java.lang.invoke.VarHandle;

import com.slytechs.sdk.common.memory.BoundView;
import com.slytechs.sdk.common.memory.MemoryStructure;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public abstract class AddressMemory extends BoundView implements Address, MemoryStructure {

	private final MemoryLayout layout;

	protected final byte[] bytesUsingVarHandle(VarHandle byteArrayHandle) {
		return bytesUsingVarHandle(byteArrayHandle, new byte[(int) length()]);
	}

	protected final void setBytesUsingVarhandle(VarHandle byteArrayHandle, byte[] bytes) {
		assert bytes.length == length();

		for (int i = 0; i < bytes.length; i++) {
			byteArrayHandle.set(segment(), view().start(), i, bytes[i]);
		}
	}

	protected final byte[] bytesUsingVarHandle(VarHandle byteArrayHandle, byte[] bytes) {
		return bytesUsingVarHandle(byteArrayHandle, bytes, 0);
	}

	protected final byte[] bytesUsingVarHandle(VarHandle byteArrayHandle, byte[] bytes, int bytesArrayOffset) {
		if (bytes.length != length())
			throw new IllegalArgumentException("array length must be equal to address length");

		for (int i = 0; i < bytes.length; i++)
			bytes[i + bytesArrayOffset] = (byte) byteArrayHandle.get(segment(), view().start(), i);

		return bytes;
	}

	public AddressMemory(MemoryLayout layout) {
		this.layout = layout;
	}

	@Override
	public boolean equals(Object obj) {
		return defaultEquals(obj);
	}
}
