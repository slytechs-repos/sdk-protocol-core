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

import java.lang.foreign.MemoryLayout;
import java.lang.invoke.VarHandle;

import com.slytechs.jnet.core.api.foreign.NativeABI;
import com.slytechs.jnet.core.api.format.StructFormattable;
import com.slytechs.jnet.core.api.memory.ByteBuf;
import com.slytechs.jnet.core.api.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.Header;

import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * The Class PcapHdrDescriptor.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class PcapHdrDescriptor
		extends AbstractPacketDescriptor
		implements PcapHeader, StructFormattable {

	/** The Constant LAYOUT. */
	public static final MemoryLayout LAYOUT = selectUsingABI();

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

		case LINUX64, MACOS64, SYS_V, BSD64, BSD_AARCH64 -> PcapDescriptor.LAYOUT$LP64;
		case WIN64 -> PcapDescriptor.LAYOUT$LLP64;

		};
	}

	/**
	 * Instantiates a new pcap hdr descriptor.
	 */
	public PcapHdrDescriptor() {
		this(L2FrameType.ETHER);
	}

	/**
	 * Instantiates a new pcap hdr descriptor.
	 *
	 * @param l2Type the l 2 type
	 */
	public PcapHdrDescriptor(int l2Type) {
		super(l2Type, TimestampUnit.PCAP_MICRO);
	}

	/**
	 * Instantiates a new pcap hdr descriptor.
	 *
	 * @param l2Type        the l 2 type
	 * @param timestampUnit the timestamp unit
	 */
	public PcapHdrDescriptor(int l2Type, TimestampUnit timestampUnit) {
		super(l2Type, timestampUnit);
	}

	/**
	 * Capture length.
	 *
	 * @return the int
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#captureLength()
	 */
	@Override
	public int captureLength() {
		return (int) CAPLEN.get(segment(), 0);
	}

	/**
	 * Descriptor id.
	 *
	 * @return the int
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#descriptorId()
	 */
	@Override
	public int descriptorId() {
		return DescriptorType.PCAP_HDR;
	}

	/**
	 * Length.
	 *
	 * @return the long
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#length()
	 */
	@Override
	public long length() {
		return LAYOUT.byteSize();
	}

	/**
	 * Sets the capture length.
	 *
	 * @param length the new capture length
	 * @see com.slytechs.jnet.protocol.api.descriptor.RxDescriptor#setCaptureLength(int)
	 */
	@Override
	public void setCaptureLength(int length) {
		CAPLEN.set(segment(), 0, length);
	}

	/**
	 * Sets the timestamp.
	 *
	 * @param timestamp the new timestamp
	 * @see com.slytechs.jnet.protocol.api.descriptor.RxDescriptor#setTimestamp(long)
	 */
	@Override
	public void setTimestamp(long timestamp) {
		setTimestamp(timestamp, timestampUnit());
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#setTimestamp(long,
	 *      com.slytechs.jnet.core.api.time.TimestampUnit)
	 */
	@Override
	public void setTimestamp(long timestamp, TimestampUnit unit) {
		int tv_sec = (int) unit.toEpochSecond(timestamp);
		int tv_usec = (int) unit.toPcapMicro(timestamp);

		setTvSec(tv_sec);
		setTvUSec(tv_usec);
	}

	/**
	 * Sets the tv sec.
	 *
	 * @param epochSeconds the new tv sec
	 * @see com.slytechs.jnet.protocol.api.descriptor.PcapHeader#setTvSec(int)
	 */
	@Override
	public void setTvSec(int epochSeconds) {
		TV_SEC.set(segment(), 0, epochSeconds);
	}

	/**
	 * Sets the tv U sec.
	 *
	 * @param useconds the new tv U sec
	 * @see com.slytechs.jnet.protocol.api.descriptor.PcapHeader#setTvUSec(int)
	 */
	@Override
	public void setTvUSec(int useconds) {
		TV_USEC.set(segment(), 0, useconds);
	}

	/**
	 * Sets the wire length.
	 *
	 * @param length the new wire length
	 * @see com.slytechs.jnet.protocol.api.descriptor.RxDescriptor#setWireLength(int)
	 */
	@Override
	public void setWireLength(int length) {
		WIRELEN.set(segment(), 0, length);
	}

	/**
	 * @see com.slytechs.jnet.core.api.memory.BoundView#toString()
	 */
	@Override
	public String toString() {
		return "PcapHeader ["
				+ "len=" + captureLength()
				+ ", timestamp=\"" + timestampUnit.toTimestamp(timestamp()) + "\""
				+ "]";
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PcapHeader#tvSec()
	 */
	@Override
	public int tvSec() {
		return (int) TV_SEC.get(segment(), 0);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PcapHeader#tvUSec()
	 */
	@Override
	public int tvUSec() {
		return (int) TV_USEC.get(segment(), 0);
	}

	/**
	 * Type.
	 *
	 * @return the descriptor type
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#type()
	 */
	@Override
	public DescriptorType type() {
		return DescriptorTypeInfo.PCAP_HDR;
	}

	/**
	 * Unbind pcap header segment.
	 */
	public void unbindPcapHeaderSegment() {

	}

	/**
	 * Wire length.
	 *
	 * @return the int
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#wireLength()
	 */
	@Override
	public int wireLength() {
		return (int) WIRELEN.get(segment(), 0);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#bindProtocol(com.slytechs.jnet.core.api.memory.ByteBuf,
	 *      com.slytechs.jnet.protocol.api.Header, int, int)
	 */
	@Override
	public boolean bindProtocol(ByteBuf packet, Header header, int protocolId, int depth) {
		if (depth == 0) {
			L2FrameType l2Type = L2FrameTypeInfo.of(l2FrameType());
			if (l2Type != null && l2Type.protocolId() == protocolId) {
				long offset = 0;
				long length = l2Type.baseLength();

				return header.bindHeader(packet, protocolId, depth, offset, length);
			}
		}
		return false;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#setL2Type(int)
	 */
	@Override
	public void setL2Type(int l2Type) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#setTxPort(int)
	 */
	@Override
	public PacketDescriptor setTxPort(int port) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#txPort()
	 */
	@Override
	public int txPort() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#isTxEnabled()
	 */
	@Override
	public boolean isTxEnabled() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#setTxEnabled(boolean)
	 */
	@Override
	public PacketDescriptor setTxEnabled(boolean enabled) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#setTxImmediate(boolean)
	 */
	@Override
	public PacketDescriptor setTxImmediate(boolean immediate) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#isTxImmediate()
	 */
	@Override
	public boolean isTxImmediate() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#isTxCrcRecalc()
	 */
	@Override
	public boolean isTxCrcRecalc() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#isTxTimestampSync()
	 */
	@Override
	public boolean isTxTimestampSync() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#setTxTimestampSync(boolean)
	 */
	@Override
	public NetPacketDescriptor setTxTimestampSync(boolean sync) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#setTxCrcRecalc(boolean)
	 */
	@Override
	public NetPacketDescriptor setTxCrcRecalc(boolean recalc) {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
