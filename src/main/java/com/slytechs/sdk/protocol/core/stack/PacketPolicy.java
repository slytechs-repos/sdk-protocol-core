/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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
package com.slytechs.sdk.protocol.core.stack;

import com.slytechs.sdk.common.memory.MemoryPool;
import com.slytechs.sdk.common.memory.MemoryRefCounter;
import com.slytechs.sdk.protocol.core.PacketFactory;
import com.slytechs.sdk.protocol.core.descriptor.DescriptorType;
import com.slytechs.sdk.protocol.core.descriptor.DescriptorTypeInfo;

/**
 * The Class PacketPolicy.
 */
public final class PacketPolicy {

	/** The memory pool settings. Null means, zero-copy packet policy */
	private PacketMemoryPoolSettings memoryPoolSettings = null;

	/**
	 * The factory. Null means, use the best implementation for current packet
	 * policy depending on the capture backend.
	 */
	private PacketFactory factory = null;

		private DescriptorType descriptorType = DescriptorTypeInfo.NET;

	/**
	 * Instantiates a new packet policy.
	 */
	public PacketPolicy() {}

	/**
	 * Copy packets to a memory pool.
	 * 
	 * <p>
	 * Any received or created packets, are copied to memory allocated from this
	 * memory pool. Memory pool is pre-allocated and memory is allocated and
	 * released back to the pool for reuse. Packet's are memory reference counted,
	 * when ref count reaches zero, the memory is released back to the pool
	 * automatically.
	 * </p>
	 * 
	 * <p>
	 * When you need packets to presist more than the the scope of the current
	 * capture loop, you must select to copy the packet to the pool or copy the
	 * packet yourself. This is not a zero-copy operation, but a allows packets to
	 * stay in memory beyond the normal limited capture scope.
	 * </p>
	 *
	 * @param settings the pool settings used to setup the memory pool
	 * @return this packet policy for method chaining
	 * @see MemoryRefCounter#refCount()
	 * @see MemoryPool
	 */
	public PacketPolicy copyToMemoryPool(PacketMemoryPoolSettings settings) {
		this.memoryPoolSettings = settings == null
				? null // Reset to zero-copy policy (default)
				: settings;

		return this;
	}

	public DescriptorType getDescriptorType() {
		return descriptorType;
	}

	/**
	 * @return
	 */
	public PacketMemoryPoolSettings getMemoryPoolSettings() {
		return memoryPoolSettings;
	}

	public PacketFactory getPacketFactory() {
		return factory;
	}

	/**
	 * With packet factory.
	 *
	 * @param factory the factory
	 * @return the packet policy
	 */
	public PacketPolicy withPacketFactory(PacketFactory factory) {
		this.factory = factory == null
				? null // Reset to use per backend policy (default)
				: factory;

		return this;
	}

	public PacketPolicy zeroCopy() {
		memoryPoolSettings = null;

		return this;
	}
}
