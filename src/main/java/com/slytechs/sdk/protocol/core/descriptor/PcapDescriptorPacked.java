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

import static com.slytechs.sdk.common.memory.MemoryStructure.*;

import java.lang.foreign.MemoryLayout;
import java.nio.ByteOrder;

import com.slytechs.sdk.common.memory.pool.PoolEntry;
import com.slytechs.sdk.common.time.TimestampUnit;
import com.slytechs.sdk.protocol.core.id.L2FrameType;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public abstract class PcapDescriptorPacked
		extends PcapDescriptor {

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

	public static PcapDescriptorPacked of(ByteOrder order) {
		return of(order, L2FrameType.ETHER, TimestampUnit.PCAP_MICRO);
	}

	public static PcapDescriptorPacked of(ByteOrder order, L2FrameType l2FrameType, TimestampUnit timestampUnit) {
		return (order == ByteOrder.BIG_ENDIAN)
				? new PcapDescriptorPackedBe(l2FrameType, timestampUnit)
				: new PcapDescriptorPackedLe(l2FrameType, timestampUnit);
	}

	protected PcapDescriptorPacked(L2FrameType l2FrameType, TimestampUnit timestampUnit) {
		super(DescriptorType.PCAP_PACKED, l2FrameType, timestampUnit);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.Descriptor#descriptorId()
	 */
	@Override
	public int descriptorId() {
		return DescriptorTypes.PCAP_PACKED;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.Descriptor#length()
	 */
	@Override
	public long length() {
		return LAYOUT$COMPACT.byteSize();
	}

	private final PoolEntry poolEntry = new PoolEntry() {

		@Override
		public void onRecycle() {
			onUnbind();
		}
	};

}
