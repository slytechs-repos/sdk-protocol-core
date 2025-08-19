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

/**
 * Base class for IP addresses (IPv4 and IPv6).
 */
public abstract class IpAddressMemory extends AddressMemory implements IpAddress {

	/**
	 * @param layout
	 */
	public IpAddressMemory(MemoryLayout layout) {
		super(layout);
	}

	/**
	 * @param layout
	 * @param arena
	 */
	public IpAddressMemory(MemoryLayout layout, Arena arena) {
		super(layout, arena);
	}

	/**
	 * @param layout
	 * @param pointer
	 */
	public IpAddressMemory(MemoryLayout layout, MemorySegment pointer) {
		super(layout, pointer);
	}

	/**
	 * @param layout
	 * @param pointer
	 * @param arena
	 */
	public IpAddressMemory(MemoryLayout layout, MemorySegment pointer, Arena arena) {
		super(layout, pointer, arena);
	}

	/**
	 * @param layout
	 * @param segment
	 * @param offset
	 */
	public IpAddressMemory(MemoryLayout layout, MemorySegment segment, long offset) {
		super(layout, segment, offset);
	}

}