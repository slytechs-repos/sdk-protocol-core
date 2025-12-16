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
package com.slytechs.jnet.protocol.api.descriptor;

import static com.slytechs.jnet.core.api.memory.MemoryStructure.*;

import java.lang.foreign.MemoryLayout;
import java.nio.ByteOrder;

import com.slytechs.jnet.core.api.memory.ByteBuf;
import com.slytechs.jnet.core.api.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.Header;
import com.slytechs.jnet.protocol.api.builtin.L2FrameType;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public abstract class PcapDescriptor extends AbstractPacketDescriptor implements PcapHeader {

	public static final MemoryLayout LAYOUT$NATIVE_ABI = unionLayout(
			structLayout(
					structLayout(

							U32.withName("tv_sec"),
							paddingLayout(4),
							U32.withName("tv_usec"),
							paddingLayout(4)

					).withName("timeval"),

					U32.withName("caplen"),
					U32.withName("wirelen")

			).withName("lp64"),

			structLayout(
					structLayout(

							U32.withName("tv_sec"),
							U32.withName("tv_usec")

					).withName("timeval"),

					U32.withName("caplen"),
					U32.withName("wirelen")

			).withName("llp64"),

			structLayout(
					structLayout(

							U32_LE.withName("tv_sec"),
							U32_LE.withName("tv_usec")

					).withName("timeval"),

					U32_LE.withName("caplen"),
					U32_LE.withName("wirelen")

			).withName("llp64_le"),

			structLayout(
					structLayout(

							U32_BE.withName("tv_sec"),
							U32_BE.withName("tv_usec")

					).withName("timeval"),

					U32_BE.withName("caplen"),
					U32_BE.withName("wirelen")

			).withName("llp64_be")

	).withName("pcap_pkthdr_libpcap");

	public static final MemoryLayout LAYOUT$LP64 = LAYOUT$NATIVE_ABI.select(groupElement("lp64"));

	public static final MemoryLayout LAYOUT$PADDED = LAYOUT$LP64;

	public static final MemoryLayout LAYOUT$LLP64 = LAYOUT$NATIVE_ABI.select(groupElement("llp64"));
	public static final MemoryLayout LAYOUT$COMPACT = LAYOUT$LLP64;

	public static final MemoryLayout LAYOUT$COMPACT$LE = LAYOUT$NATIVE_ABI.select(groupElement("llp64_le"));
	public static final MemoryLayout LAYOUT$COMPACT$BE = LAYOUT$NATIVE_ABI.select(groupElement("llp64_be"));

	public static PcapDescriptor of(ByteOrder order) {
		return of(order, L2FrameType.L2_FRAME_TYPE_ETHER, TimestampUnit.PCAP_MICRO);
	}

	public static PcapDescriptor of(ByteOrder order, L2FrameType l2Type, TimestampUnit timestampUnit) {
		return (order == ByteOrder.BIG_ENDIAN)
				? new PcapDescriptorBe(l2Type, timestampUnit)
				: new PcapDescriptorLe(l2Type, timestampUnit);
	}

	protected PcapDescriptor(L2FrameType l2Type, TimestampUnit timestampUnit) {
		super(l2Type, timestampUnit);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#descriptorId()
	 */
	@Override
	public int descriptorId() {
		return DescriptorType.DESCRIPTOR_TYPE_PCAP.getValue();
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#length()
	 */
	@Override
	public long length() {
		return LAYOUT$COMPACT.byteSize();
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.RxDescriptor#setTimestamp(long)
	 */
	@Override
	public void setTimestamp(long timestamp) {
		setTimestamp(timestamp, timestampUnit());
	}

	@Override
	public void setTimestamp(long timestamp, TimestampUnit unit) {
		int tv_sec = (int) unit.toEpochSecond(timestamp);
		int tv_usec = (int) unit.toPcapMicro(timestamp);

		setTvSec(tv_sec);
		setTvUSec(tv_usec);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#type()
	 */
	@Override
	public DescriptorType type() {
		return DescriptorType.DESCRIPTOR_TYPE_PCAP;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#bindProtocol(com.slytechs.jnet.core.api.memory.BindableView,
	 *      com.slytechs.jnet.protocol.api.Header, int, int)
	 */
	@Override
	public boolean bindProtocol(ByteBuf packet, Header header, int protocolId, int depth) {
		if (depth == 0) {
			L2FrameType l2Type = l2FrameType();
			if (l2Type != null && l2Type.protocolId() == protocolId) {
				long offset = 0;
				long length = l2Type.baseLength();

				return header.bindHeader(packet, protocolId, depth, offset, length);
			}
		}
		return false;
	}
}
