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

import java.lang.foreign.MemoryLayout;
import java.lang.invoke.VarHandle;

import com.slytechs.sdk.common.foreign.NativeABI;
import com.slytechs.sdk.common.format.StructFormattable;
import com.slytechs.sdk.common.time.TimestampUnit;

import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * The Class PcapDescriptorPadded.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class PcapDescriptorPadded
		extends PcapDescriptor
		implements StructFormattable {

	/** The Constant LAYOUT. */
	public static final MemoryLayout LAYOUT = selectUsingABI();

	public static final long BYTE_SIZE = 24;

	/** The Constant TV_SEC. */
	private static final VarHandle TV_SEC = LAYOUT.varHandle(groupElement("timeval"), groupElement("tv_sec"));

	/** The Constant TV_USEC. */
	private static final VarHandle TV_USEC = LAYOUT.varHandle(groupElement("timeval"), groupElement("tv_usec"));

	/** The Constant CAPLEN. */
	private static final VarHandle CAPLEN = LAYOUT.varHandle(groupElement("caplen"));

	/** The Constant WIRELEN. */
	private static final VarHandle WIRELEN = LAYOUT.varHandle(groupElement("wirelen"));

	/**
	 * Select using ABI.
	 *
	 * @return the memory layout
	 */
	private static MemoryLayout selectUsingABI() {
		return switch (NativeABI.current()) {

		case LINUX64, MACOS64, SYS_V, BSD64, BSD_AARCH64 -> PcapDescriptorPacked.LAYOUT$LP64;
		case WIN64 -> PcapDescriptorPacked.LAYOUT$LLP64;

		};
	}

	/**
	 * Instantiates a new pcap hdr descriptor.
	 */
	public PcapDescriptorPadded() {
		this(L2FrameInfo.ETHER);
	}

	/**
	 * Instantiates a new pcap hdr descriptor.
	 *
	 * @param l2Type the l 2 type
	 */
	public PcapDescriptorPadded(L2FrameInfo l2FrameInfo) {
		super(DescriptorInfo.PCAP_PADDED, l2FrameInfo, TimestampUnit.PCAP_MICRO);
	}

	/**
	 * Instantiates a new pcap hdr descriptor.
	 *
	 * @param l2Type        the l 2 type
	 * @param timestampUnit the timestamp unit
	 */
	public PcapDescriptorPadded(L2FrameInfo l2FrameInfo, TimestampUnit timestampUnit) {
		super(DescriptorInfo.PCAP_PADDED, l2FrameInfo, timestampUnit);
	}

	/**
	 * Capture length.
	 *
	 * @return the int
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#captureLength()
	 */
	@Override
	public int captureLength() {
		return (int) CAPLEN.get(segment(), 0);
	}

	/**
	 * Descriptor id.
	 *
	 * @return the int
	 * @see com.slytechs.sdk.protocol.core.descriptor.Descriptor#descriptorId()
	 */
	@Override
	public int descriptorId() {
		return DescriptorType.PCAP_PADDED;
	}

	/**
	 * Length.
	 *
	 * @return the long
	 * @see com.slytechs.sdk.protocol.core.descriptor.Descriptor#length()
	 */
	@Override
	public long length() {
		return LAYOUT.byteSize();
	}

	/**
	 * Sets the capture length.
	 *
	 * @param length the new capture length
	 * @return
	 * @see com.slytechs.sdk.protocol.core.descriptor.RxCapabilities#setCaptureLength(int)
	 */
	@Override
	public PcapDescriptorPadded setCaptureLength(int length) {
		CAPLEN.set(segment(), 0, length);

		return this;
	}

	/**
	 * Sets the tv sec.
	 *
	 * @param epochSeconds the new tv sec
	 * @return
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setTvSec(int)
	 */
	@Override
	public PcapDescriptorPadded setTvSec(int epochSeconds) {
		TV_SEC.set(segment(), 0, epochSeconds);

		return this;
	}

	/**
	 * Sets the tv U sec.
	 *
	 * @param useconds the new tv U sec
	 * @return
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setTvUSec(int)
	 */
	@Override
	public PcapDescriptorPadded setTvUSec(int useconds) {
		TV_USEC.set(segment(), 0, useconds);

		return this;
	}

	/**
	 * Sets the wire length.
	 *
	 * @param length the new wire length
	 * @return
	 * @see com.slytechs.sdk.protocol.core.descriptor.RxCapabilities#setWireLength(int)
	 */
	@Override
	public PcapDescriptorPadded setWireLength(int length) {
		WIRELEN.set(segment(), 0, length);

		return this;
	}

	/**
	 * @see com.slytechs.sdk.common.memory.BoundView#toString()
	 */
	@Override
	public String toString() {
		return "PcapHeader ["
				+ "len=" + captureLength()
				+ ", timestamp=\"" + timestampUnit().toTimestamp(timestamp()) + "\""
				+ "]";
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#tvSec()
	 */
	@Override
	public int tvSec() {
		return (int) TV_SEC.get(segment(), 0);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#tvUSec()
	 */
	@Override
	public int tvUSec() {
		return (int) TV_USEC.get(segment(), 0);
	}

	/**
	 * Wire length.
	 *
	 * @return the int
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#wireLength()
	 */
	@Override
	public int wireLength() {
		return (int) WIRELEN.get(segment(), 0);
	}

	/**
	 * @see com.slytechs.sdk.common.memory.pool.Persistable#newUnbound()
	 */
	@Override
	public PacketDescriptor newUnbound() {
		return new PcapDescriptorPadded(l2FrameInfo());
	}
}
