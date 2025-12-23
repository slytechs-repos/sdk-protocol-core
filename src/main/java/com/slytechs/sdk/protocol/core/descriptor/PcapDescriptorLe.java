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
class PcapDescriptorLe extends PcapDescriptor {

	private static final VarHandle TV_SEC$LE = LAYOUT$COMPACT$LE.varHandle(groupElement("timeval"), groupElement(
			"tv_sec"));
	private static final VarHandle TV_USEC$LE = LAYOUT$COMPACT$LE.varHandle(groupElement("timeval"), groupElement(
			"tv_usec"));
	private static final VarHandle CAPLEN$LE = LAYOUT$COMPACT$LE.varHandle(groupElement("caplen"));
	private static final VarHandle WIRELEN$LE = LAYOUT$COMPACT$LE.varHandle(groupElement("wirelen"));

	protected PcapDescriptorLe(int l2Type, TimestampUnit timestampUnit) {
		super(l2Type, timestampUnit);
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
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setCaptureLength(int)
	 */
	@Override
	public void setCaptureLength(int length) {
		CAPLEN$LE.set(segment(), 0, length);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setTvSec(int)
	 */
	@Override
	public void setTvSec(int epochSeconds) {
		TV_SEC$LE.set(segment(), 0, epochSeconds);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setTvUSec(int)
	 */
	@Override
	public void setTvUSec(int useconds) {
		TV_USEC$LE.set(segment(), 0, useconds);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PcapHeader#setWireLength(int)
	 */
	@Override
	public void setWireLength(int length) {
		WIRELEN$LE.set(segment(), 0, length);
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
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#setL2Type(int)
	 */
	@Override
	public void setL2Type(int l2Type) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#setTxPort(int)
	 */
	@Override
	public PacketDescriptor setTxPort(int port) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#txPort()
	 */
	@Override
	public int txPort() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#isTxEnabled()
	 */
	@Override
	public boolean isTxEnabled() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#setTxEnabled(boolean)
	 */
	@Override
	public PacketDescriptor setTxEnabled(boolean enabled) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#setTxImmediate(boolean)
	 */
	@Override
	public PacketDescriptor setTxImmediate(boolean immediate) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#isTxImmediate()
	 */
	@Override
	public boolean isTxImmediate() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#isTxCrcRecalc()
	 */
	@Override
	public boolean isTxCrcRecalc() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#isTxTimestampSync()
	 */
	@Override
	public boolean isTxTimestampSync() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#setTxTimestampSync(boolean)
	 */
	@Override
	public NetPacketDescriptor setTxTimestampSync(boolean sync) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#setTxCrcRecalc(boolean)
	 */
	@Override
	public NetPacketDescriptor setTxCrcRecalc(boolean recalc) {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
