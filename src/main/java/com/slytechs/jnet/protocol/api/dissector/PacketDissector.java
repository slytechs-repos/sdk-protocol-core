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
package com.slytechs.jnet.protocol.api.dissector;

import com.slytechs.jnet.core.api.memory.ByteBuf;
import com.slytechs.jnet.core.api.memory.Memory;
import com.slytechs.jnet.core.api.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.descriptor.DescriptorType;
import com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor;
import com.slytechs.jnet.protocol.api.pack.ProtocolPackManager;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface PacketDissector {

	/**
	 * @param type
	 * @return
	 */
	static PacketDissector dissector(DescriptorType type) {
		return switch (type) {
		case null -> null;
		default -> ProtocolPackManager.listDissectors().stream()
				.filter(plugin -> plugin.getDescriptorType() == type)
				.map(DissectorPlugin::getDissector)
				.findFirst()
				.orElse(null);
		};
	}

	/**
	 * Timestamp unit for this dissector to use for timestamp value.
	 *
	 * @return the timestamp unit
	 */
	TimestampUnit timestampUnit();

	/**
	 * Sets a new timestamp unit for the dissector to use.
	 *
	 * @param timestampUnit the new timestamp unit
	 * @return this dissector for chaining
	 */
	PacketDissector setTimestampUnit(TimestampUnit timestampUnit);

	/**
	 * Dissect a packet and store its state.
	 *
	 * @param packet    the packet buffer
	 * @param timestamp the timestamp
	 * @param caplen    the caplen
	 * @param wirelen   the wirelen
	 * @return number of bytes processed in the buffer
	 */
	int dissectPacket(ByteBuf packet, long timestamp, int caplen, int wirelen);

	/**
	 * Dissect a packet and store its state.
	 *
	 * @param packet    the packet buffer
	 * @param timestamp the timestamp
	 * @param caplen    the caplen
	 * @param wirelen   the wirelen
	 * @return number of bytes processed in the buffer
	 */
	int dissectPacket(Memory packet, long timestamp, int caplen, int wirelen);

	default int dissectPacket(ByteBuf packet, PacketDescriptor descriptor) {
		long timestamp = descriptor.timestamp(timestampUnit());
		int caplen = descriptor.captureLength();
		int wirelen = descriptor.wireLength();

		return dissectPacket(packet, timestamp, caplen, wirelen);
	}

	/**
	 * Reset the state of the dissector. Calling a recycle on a dissector will reset
	 * it state and get it ready for the next dissection.
	 */
	void recycle();

	/**
	 * Write the state of the dissection into the provided descriptor.
	 *
	 * @param descriptor the descriptor buffer
	 * @return number of byte written
	 */
	int writeDescriptor(ByteBuf descriptor);

	/**
	 * Write the state of the dissection into the provided descriptor.
	 *
	 * @param descriptor the descriptor
	 * @return number of byte written
	 */
	int writeDescriptor(PacketDescriptor descriptor);
	
	PacketDissector setL2FrameType(int type);
	int l2FrameType();
}
