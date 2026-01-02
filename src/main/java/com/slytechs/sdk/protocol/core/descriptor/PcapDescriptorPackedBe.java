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
class PcapDescriptorPackedBe extends PcapDescriptorPacked {

	private static final VarHandle TV_SEC$BE = LAYOUT$COMPACT$BE.varHandle(groupElement("timeval"), groupElement(
			"tv_sec"));
	private static final VarHandle TV_USEC$BE = LAYOUT$COMPACT$BE.varHandle(groupElement("timeval"), groupElement(
			"tv_usec"));
	private static final VarHandle CAPLEN$BE = LAYOUT$COMPACT$BE.varHandle(groupElement("caplen"));
	private static final VarHandle WIRELEN$BE = LAYOUT$COMPACT$BE.varHandle(groupElement("wirelen"));

	protected PcapDescriptorPackedBe(L2FrameInfo l2FrameInfo, TimestampUnit timestampUnit) {
		super(l2FrameInfo, timestampUnit);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#captureLength()
	 */
	@Override
	public int captureLength() {
		return (int) CAPLEN$BE.get(segment(), 0);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#order()
	 */
	@Override
	public ByteOrder order() {
		return ByteOrder.BIG_ENDIAN;
	}

	/**
	 * @return 
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setCaptureLength(int)
	 */
	@Override
	public PcapDescriptorPackedBe setCaptureLength(int length) {
		CAPLEN$BE.set(segment(), 0, length);
		
		return this;
	}

	/**
	 * @return 
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setTvSec(int)
	 */
	@Override
	public PcapDescriptorPackedBe setTvSec(int epochSeconds) {
		TV_SEC$BE.set(segment(), 0, epochSeconds);
		
		return this;
	}

	/**
	 * @return 
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setTvUSec(int)
	 */
	@Override
	public PcapDescriptorPackedBe setTvUSec(int useconds) {
		TV_USEC$BE.set(segment(), 0, useconds);
		
		return this;
	}

	/**
	 * @return 
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setWireLength(int)
	 */
	@Override
	public PcapDescriptorPackedBe setWireLength(int length) {
		WIRELEN$BE.set(segment(), 0, length);
		
		return this;
	}

	@Override
	public int tvSec() {
		return (int) TV_SEC$BE.get(segment(), 0);
	}

	@Override
	public int tvUSec() {
		return (int) TV_USEC$BE.get(segment(), 0);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#wireLength()
	 */
	@Override
	public int wireLength() {
		return (int) WIRELEN$BE.get(segment(), 0);
	}

	/**
	 * @see com.slytechs.sdk.common.memory.pool.Persistable#newUnbound()
	 */
	@Override
	public PacketDescriptor newUnbound() {
		return new PcapDescriptorPackedBe(l2FrameInfo(), timestampUnit());
	}

}
