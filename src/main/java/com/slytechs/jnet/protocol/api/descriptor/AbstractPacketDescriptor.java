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

import java.nio.ByteBuffer;

import com.slytechs.jnet.core.api.memory.ByteBuf;
import com.slytechs.jnet.core.api.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.builtin.L2FrameType;

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
	private final L2FrameType l2Type;

	protected AbstractPacketDescriptor(TimestampUnit timestampUnit) {
		this(L2FrameType.DEFAULT_L2_FRAME_TYPE, timestampUnit);
	}

	protected AbstractPacketDescriptor(L2FrameType l2Type, TimestampUnit timestampUnit) {
		this.l2Type = l2Type;
		this.timestampUnit = timestampUnit;
	}

	@Override
	public void setTimestampUnit(TimestampUnit unit) {
		this.timestampUnit = unit;
	}

	@Override
	public int l2Type() {
		return l2Type.l2TypeId();
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#l2FrameType()
	 */
	@Override
	public L2FrameType l2FrameType() {
		return l2Type;
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

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#buffer()
	 */
	@Override
	public ByteBuf buffer() {
		return this;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#byteBuffer()
	 */
	@Override
	public ByteBuffer byteBuffer() {
		return segment().asByteBuffer();
	}

}
