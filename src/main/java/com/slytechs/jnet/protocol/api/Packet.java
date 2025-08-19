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
package com.slytechs.jnet.protocol.api;

import java.lang.foreign.MemorySegment;

import com.slytechs.jnet.protocol.api.descriptor.NetTag;
import com.slytechs.jnet.protocol.api.format.PacketFormat;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public final class Packet extends BasePacket {

	/**
	 * NetTag chain (NetTag.next) providing protocol specific meta
	 * data. For example IPF descriptors, etc.
	 */
	protected NetTag headTag;

	public Packet() {}

	public Packet(MemorySegment pointer, long length) {
		super(pointer, length);
	}

	public Packet(MemorySegment segment, long offset, long length) {
		super(segment, offset, length);
	}

	public NetTag getTags() {
		return headTag;
	}

	public void addTag(NetTag tag) {
		this.headTag = tag;
	}

	@Override
	public String toString() {
		PacketFormat format = PacketFormat.getDefault();
		if (format == null)
			return packetDescriptor.toString();

		return format.formatPacket(this);
	}
}
