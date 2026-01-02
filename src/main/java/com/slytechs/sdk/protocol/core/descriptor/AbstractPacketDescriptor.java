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
package com.slytechs.sdk.protocol.core.descriptor;

import java.util.Objects;

import com.slytechs.sdk.common.memory.BoundView;
import com.slytechs.sdk.common.memory.pool.PoolEntry;
import com.slytechs.sdk.common.time.TimestampUnit;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public abstract class AbstractPacketDescriptor
		extends BoundView
		implements PacketDescriptor {

	static HeaderBinding UNSUPPORTED_HEADER_BINDING = HeaderBinding.INSTANCE;

	private TimestampUnit timestampUnit;
	private final DescriptorInfo descriptorInfo;
	protected long flags = 0;

	private final PoolEntry poolEntry = new PoolEntry();

	protected AbstractPacketDescriptor(DescriptorInfo descriptorInfo) {
		this(descriptorInfo, TimestampUnit.EPOCH_MILLI);
	}

	protected AbstractPacketDescriptor(DescriptorInfo descriptorInfo, TimestampUnit timestampUnit) {
		this.timestampUnit = Objects.requireNonNull(timestampUnit, "timestampUnit");
		this.descriptorInfo = Objects.requireNonNull(descriptorInfo, "descriptorInfo");
	}

	@Override
	public final DescriptorInfo descriptorInfo() {
		return descriptorInfo;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#mapProtocol(int,
	 *      int)
	 */
	@Override
	public long mapProtocol(int protocolId, int depth) {
		return PacketDescriptor.PROTOCOL_NOT_SUPPORTED;
	}

	/**
	 * @see com.slytechs.sdk.common.memory.pool.Poolable#poolEntry()
	 */
	@Override
	public final PoolEntry poolEntry() {
		return poolEntry;
	}

	@Override
	public PacketDescriptor setTimestampUnit(TimestampUnit unit) {
		this.timestampUnit = unit;

		return this;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#timestampUnit()
	 */
	@Override
	public final TimestampUnit timestampUnit() {
		return timestampUnit;
	}
}
