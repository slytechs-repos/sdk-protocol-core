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
import com.slytechs.jnet.core.api.memory.MemoryHandle.ShortHandle;

import static java.lang.foreign.MemoryLayout.*;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class MacAddressMemory extends AddressMemory implements MacAddress {

	public static final MemoryLayout LAYOUT = unionLayout(
			sequenceLayout(LENGTH, U8_BE).withName("byte_array"),
			structLayout(
					U16_BE.withName("high"),
					U32_BE.withName("low")).withName("fast_path"));

	// Use MemoryHandle instead of VarHandle
	private static final ByteHandle BYTE_ARRAY = new ByteHandle(LAYOUT, "byte_array[]");
	private static final ShortHandle HIGH = new ShortHandle(LAYOUT, "fast_path", "high");
	private static final IntHandle LOW = new IntHandle(LAYOUT, "fast_path", "low");

	public MacAddressMemory() {
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

	@Override
	public long asLong() {
		// Read first 2 bytes as short (high order)
		long high = HIGH.getShort(view()) & 0xFFFFL;
		// Read last 4 bytes as int (low order)
		long low = LOW.getInt(view()) & 0xFFFFFFFFL;

		// Combine: high 16 bits in upper position, low 32 bits in lower
		return (high << 32) | low;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Address#setBytes(byte[])
	 */
	@Override
	public void setBytes(byte[] addr) {
		if (addr.length != LENGTH) {
			throw new IllegalArgumentException("MAC address must be " + LENGTH + " bytes");
		}
		for (int i = 0; i < LENGTH; i++) {
			BYTE_ARRAY.setByteAtIndex(view(), i, addr[i]);
		}
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.MacAddress#setLong(long)
	 */
	@Override
	public void setLong(long addr) {
		// Extract high 16 bits (first 2 bytes of MAC)
		short high = (short) ((addr >> 32) & 0xFFFF);
		// Extract low 32 bits (last 4 bytes of MAC)
		int low = (int) (addr & 0xFFFFFFFFL);

		HIGH.setShort(view(), 0, high);
		LOW.setInt(view(), 0, low);
	}

	@Override
	public String toString() {
		return MacAddress.formatMacAddress(bytes());
	}
}