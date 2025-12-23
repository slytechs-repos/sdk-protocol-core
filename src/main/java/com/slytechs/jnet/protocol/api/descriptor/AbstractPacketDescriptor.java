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
package com.slytechs.jnet.protocol.api.descriptor;

import com.slytechs.jnet.core.api.memory.ByteBuf;
import com.slytechs.jnet.core.api.time.TimestampUnit;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public abstract class AbstractPacketDescriptor
		extends ByteBuf
		implements PacketDescriptor {

	protected TimestampUnit timestampUnit;
	protected long flags = 0;
	private int l2FrameType;

	protected AbstractPacketDescriptor(TimestampUnit timestampUnit) {
		this(L2FrameType.ETHER, timestampUnit);
	}

	protected AbstractPacketDescriptor(int l2Type, TimestampUnit timestampUnit) {
		this.l2FrameType = l2Type;
		this.timestampUnit = timestampUnit;
	}

	protected AbstractPacketDescriptor() {
		this(L2FrameType.ETHER, TimestampUnit.EPOCH_MILLI);
	}

	@Override
	public void setTimestampUnit(TimestampUnit unit) {
		this.timestampUnit = unit;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#l2FrameType()
	 */
	@Override
	public int l2FrameType() {
		return l2FrameType;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#mapProtocol(int,
	 *      int)
	 */
	@Override
	public long mapProtocol(int protocolId, int depth) {
		return PacketDescriptor.PROTOCOL_NOT_FOUND;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#timestampUnit()
	 */
	@Override
	public TimestampUnit timestampUnit() {
		return timestampUnit;
	}

}
