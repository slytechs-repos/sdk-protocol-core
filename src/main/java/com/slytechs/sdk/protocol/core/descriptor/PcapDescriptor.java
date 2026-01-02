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

import com.slytechs.sdk.common.memory.BindableView;
import com.slytechs.sdk.common.time.TimestampUnit;
import com.slytechs.sdk.protocol.core.Header;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public abstract class PcapDescriptor extends AbstractPacketDescriptor {

	/** The Constant RX_CAPABILITIES. */
	public static final long RX_CAPABILITIES = 0;

	/** The Constant TX_CAPABILITIES. */
	public static final long TX_CAPABILITIES = 0;

	private L2FrameInfo l2FrameInfo;

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#rxCapabilitiesBitmask()
	 */
	@Override
	public long rxCapabilitiesBitmask() {
		return RX_CAPABILITIES;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#txCapabilitiesBitmask()
	 */
	@Override
	public long txCapabilitiesBitmask() {
		return TX_CAPABILITIES;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#rxCapabilities()
	 */
	@Override
	public RxCapabilities rxCapabilities() {
		return RxCapabilities.INSTANCE;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#txCapabilities()
	 */
	@Override
	public TxCapabilities txCapabilities() {
		return TxCapabilities.INSTANCE;
	}

	public PcapDescriptor(DescriptorInfo descriptorInfo, L2FrameInfo l2FrameInfo, TimestampUnit timestampUnit) {
		super(descriptorInfo, timestampUnit);

		this.l2FrameInfo = l2FrameInfo;
	}

	public PcapDescriptor(DescriptorInfo descriptorInfo, TimestampUnit timestampUnit) {
		super(descriptorInfo, timestampUnit);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#l2FrameInfo()
	 */
	@Override
	public final L2FrameInfo l2FrameInfo() {
		return l2FrameInfo;
	}

	/**
	 * @return
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#setL2FrameType(L2FrameInfo)
	 */
	@Override
	public PcapDescriptor setL2FrameType(L2FrameInfo l2FrameInfo) {
		this.l2FrameInfo = l2FrameInfo;

		return this;
	}

	public abstract int tvUSec();

	public abstract int tvSec();

	public abstract PcapDescriptor setTvSec(int epochSeconds);

	public abstract PcapDescriptor setTvUSec(int useconds);

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#timestamp()
	 */
	@Override
	public final long timestamp() {
		long timestamp = timestampUnit().ofSecond(tvSec(), tvUSec());

		return timestamp;
	}

	/**
	 * @return
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#setTimestamp(long)
	 */
	@Override
	public final PcapDescriptor setTimestamp(long timestamp) {
		setTimestamp(timestamp, timestampUnit());

		return this;
	}

	@Override
	public final PcapDescriptor setTimestamp(long timestamp, TimestampUnit unit) {
		int tv_sec = (int) unit.toEpochSecond(timestamp);
		int tv_usec = (int) unit.toPcapMicro(timestamp);

		setTvSec(tv_sec);
		setTvUSec(tv_usec);

		return this;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#bindHeader(com.slytechs.sdk.common.memory.BindableView,
	 *      com.slytechs.sdk.protocol.core.Header, int, int)
	 */
	@Override
	public final boolean bindHeader(BindableView packet, Header header, int protocolId, int depth) {
		L2FrameType l2Type = l2FrameInfo();

		// Quick path
		if (depth == 0 && l2Type.protocolId() == protocolId) {
			long offset = 0;
			long length = l2Type.minLength();

			return header.bindHeader(packet, protocolId, depth, offset, length);
		}

		// Slow path or no-op depending on user settings.
		return AbstractPacketDescriptor.UNSUPPORTED_HEADER_BINDING
				.bindHeader(packet, header, l2Type.l2FrameId(), protocolId, depth);
	}

}
