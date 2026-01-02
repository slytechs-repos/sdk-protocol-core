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
package com.slytechs.sdk.protocol.core.descriptor;

import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

import com.slytechs.sdk.common.time.TimestampUnit;

import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
class PcapDescriptorPackedLe extends PcapDescriptorPacked {

	private static final VarHandle TV_SEC$LE = LAYOUT$COMPACT$LE.varHandle(groupElement("timeval"), groupElement(
			"tv_sec"));
	private static final VarHandle TV_USEC$LE = LAYOUT$COMPACT$LE.varHandle(groupElement("timeval"), groupElement(
			"tv_usec"));
	private static final VarHandle CAPLEN$LE = LAYOUT$COMPACT$LE.varHandle(groupElement("caplen"));
	private static final VarHandle WIRELEN$LE = LAYOUT$COMPACT$LE.varHandle(groupElement("wirelen"));

	protected PcapDescriptorPackedLe(L2FrameInfo l2FrameInfo, TimestampUnit timestampUnit) {
		super(l2FrameInfo, timestampUnit);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#captureLength()
	 */
	@Override
	public int captureLength() {
		return (int) CAPLEN$LE.get(segment(), 0);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#order()
	 */
	@Override
	public ByteOrder order() {
		return ByteOrder.LITTLE_ENDIAN;
	}

	/**
	 * @return
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setCaptureLength(int)
	 */
	@Override
	public PcapDescriptorPackedLe setCaptureLength(int length) {
		CAPLEN$LE.set(segment(), 0, length);

		return this;
	}

	/**
	 * @return
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setTvSec(int)
	 */
	@Override
	public PcapDescriptorPackedLe setTvSec(int epochSeconds) {
		TV_SEC$LE.set(segment(), 0, epochSeconds);

		return this;
	}

	/**
	 * @return
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setTvUSec(int)
	 */
	@Override
	public PcapDescriptorPackedLe setTvUSec(int useconds) {
		TV_USEC$LE.set(segment(), 0, useconds);

		return this;
	}

	/**
	 * @return
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setWireLength(int)
	 */
	@Override
	public PcapDescriptorPackedLe setWireLength(int length) {
		WIRELEN$LE.set(segment(), 0, length);

		return this;
	}

	@Override
	public int tvSec() {
		return (int) TV_SEC$LE.get(segment(), 0);
	}

	@Override
	public int tvUSec() {
		return (int) TV_USEC$LE.get(segment(), 0);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#wireLength()
	 */
	@Override
	public int wireLength() {
		return (int) WIRELEN$LE.get(segment(), 0);
	}

	/**
	 * @see com.slytechs.sdk.common.memory.pool.Persistable#newUnbound()
	 */
	@Override
	public PacketDescriptor newUnbound() {
		return new PcapDescriptorPackedLe(l2FrameInfo(), timestampUnit());
	}
}
