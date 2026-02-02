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
import com.slytechs.sdk.protocol.core.header.Header;
import com.slytechs.sdk.protocol.core.id.L2FrameType;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public abstract class PcapDescriptor extends AbstractPacketDescriptor {

	/** The Constant RX_CAPABILITIES. */
	public static final long RX_CAPABILITIES = 0;

	/** The Constant TX_CAPABILITIES. */
	public static final long TX_CAPABILITIES = 0;

	public static boolean isPcapDescriptor(DescriptorType target) {
		return target == DescriptorType.PCAP_PACKED || target == DescriptorType.PCAP_PADDED;
	}

	public PcapDescriptor(DescriptorType descriptorType, L2FrameType l2FrameType, TimestampUnit timestampUnit) {
		super(descriptorType, timestampUnit);
	}

	public PcapDescriptor(DescriptorType descriptorType, TimestampUnit timestampUnit) {
		super(descriptorType, timestampUnit);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#bindHeader(com.slytechs.sdk.common.memory.BindableView,
	 *      com.slytechs.sdk.protocol.core.header.Header, int, int)
	 */
	@Override
	public final boolean bindHeader(BindableView packet, Header header, int protocolId, int depth) {
		L2FrameType l2Type = l2FrameType();

		// Quick path
		if (depth == 0 && l2ProtocolId() == protocolId) {
			long offset = 0;
			long length = l2Type.minLength();

			return header.bindHeader(packet, protocolId, depth, offset, length);
		}

		// Slow path or no-op depending on user settings.
		return onDemandDissector != null && onDemandDissector
				.bindHeader(packet, header, l2Type.id(), protocolId, depth);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#rx()
	 */
	@Override
	public RxCapabilities rx() {
		return RxCapabilities.INSTANCE;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#rxCapabilitiesBitmask()
	 */
	@Override
	public long rxCapabilitiesBitmask() {
		return RX_CAPABILITIES;
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

	public abstract int tvSec();

	public abstract int tvUSec();

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#tx()
	 */
	@Override
	public TxCapabilities tx() {
		return TxCapabilities.INSTANCE;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor#txCapabilitiesBitmask()
	 */
	@Override
	public long txCapabilitiesBitmask() {
		return TX_CAPABILITIES;
	}

}
