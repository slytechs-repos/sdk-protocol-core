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

import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

import com.slytechs.jnet.core.api.time.TimestampUnit;

import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
class PcapDescriptorBe extends PcapDescriptor {

	private static final VarHandle TV_SEC$BE = LAYOUT$COMPACT$BE.varHandle(groupElement("timeval"), groupElement(
			"tv_sec"));
	private static final VarHandle TV_USEC$BE = LAYOUT$COMPACT$BE.varHandle(groupElement("timeval"), groupElement(
			"tv_usec"));
	private static final VarHandle CAPLEN$BE = LAYOUT$COMPACT$BE.varHandle(groupElement("caplen"));
	private static final VarHandle WIRELEN$BE = LAYOUT$COMPACT$BE.varHandle(groupElement("wirelen"));

	protected PcapDescriptorBe(int l2Type, TimestampUnit timestampUnit) {
		super(l2Type, timestampUnit);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#captureLength()
	 */
	@Override
	public int captureLength() {
		return (int) CAPLEN$BE.get(segment(), 0);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#order()
	 */
	@Override
	public ByteOrder order() {
		return ByteOrder.BIG_ENDIAN;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PcapHeader#setCaptureLength(int)
	 */
	@Override
	public void setCaptureLength(int length) {
		CAPLEN$BE.set(segment(), 0, length);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PcapHeader#setTvSec(int)
	 */
	@Override
	public void setTvSec(int epochSeconds) {
		TV_SEC$BE.set(segment(), 0, epochSeconds);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PcapHeader#setTvUSec(int)
	 */
	@Override
	public void setTvUSec(int useconds) {
		TV_USEC$BE.set(segment(), 0, useconds);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PcapHeader#setWireLength(int)
	 */
	@Override
	public void setWireLength(int length) {
		WIRELEN$BE.set(segment(), 0, length);
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
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#wireLength()
	 */
	@Override
	public int wireLength() {
		return (int) WIRELEN$BE.get(segment(), 0);
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
