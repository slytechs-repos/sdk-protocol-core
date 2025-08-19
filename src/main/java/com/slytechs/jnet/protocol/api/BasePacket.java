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

import com.slytechs.jnet.core.api.memory.Memory;
import com.slytechs.jnet.core.api.memory.MemoryProxy;
import com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class BasePacket extends MemoryProxy implements HeaderAccessor {

	/**
	 * Descriptor describing the RX and TX properties of this packet
	 */
	protected PacketDescriptor packetDescriptor;

	public BasePacket() {}

	public BasePacket(MemorySegment pointer, long length) {
		this(pointer.reinterpret(length), 0, length);
	}

	public BasePacket(MemorySegment segment, long offset, long length) {
		
		bindMemory(Memory.of(segment, offset), 0, length);

		onBindMemory();
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#captureLength()
	 */
	public final int captureLength() {
		return packetDescriptor.captureLength();
	}

	/**
	 * @param id
	 * @return
	 * @throws HeaderNotFoundException
	 * @see com.slytechs.jnet.protocol.api.HeaderAccessor#getHeader(int)
	 */
	@Override
	public final Header getHeader(int id) throws HeaderNotFoundException {
		return packetDescriptor.getHeader(id);
	}

	/**
	 * @param id
	 * @param depth
	 * @return
	 * @throws HeaderNotFoundException
	 * @see com.slytechs.jnet.protocol.api.HeaderAccessor#getHeader(int, int)
	 */
	@Override
	public final Header getHeader(int id, int depth) throws HeaderNotFoundException {
		return packetDescriptor.getHeader(id, depth);
	}

	/**
	 * @param <T>
	 * @param header
	 * @return
	 * @throws HeaderNotFoundException
	 * @see com.slytechs.jnet.protocol.api.HeaderAccessor#getHeader(com.slytechs.jnet.protocol.api.Header)
	 */
	@Override
	public final <T extends Header> T getHeader(T header) throws HeaderNotFoundException {
		return packetDescriptor.getHeader(header);
	}

	/**
	 * @param <T>
	 * @param header
	 * @param depth
	 * @return
	 * @throws HeaderNotFoundException
	 * @see com.slytechs.jnet.protocol.api.HeaderAccessor#getHeader(com.slytechs.jnet.protocol.api.Header,
	 *      int)
	 */
	@Override
	public final <T extends Header> T getHeader(T header, int depth) throws HeaderNotFoundException {
		return packetDescriptor.getHeader(header, depth);
	}

	public final PacketDescriptor getPacketDescriptor() {
		return packetDescriptor;
	}

	/**
	 * @param header
	 * @return
	 * @see com.slytechs.jnet.protocol.api.HeaderAccessor#hasHeader(com.slytechs.jnet.protocol.api.Header)
	 */
	@Override
	public final boolean hasHeader(Header header) {
		return packetDescriptor.hasHeader(header);
	}

	/**
	 * @param header
	 * @param depth
	 * @return
	 * @see com.slytechs.jnet.protocol.api.HeaderAccessor#hasHeader(com.slytechs.jnet.protocol.api.Header,
	 *      int)
	 */
	@Override
	public final boolean hasHeader(Header header, int depth) {
		return packetDescriptor.hasHeader(header, depth);
	}

	/**
	 * @param id
	 * @return
	 * @see com.slytechs.jnet.protocol.api.HeaderAccessor#isPresent(int)
	 */
	@Override
	public final boolean isPresent(int id) {
		return packetDescriptor.isPresent(id);
	}

	/**
	 * @param id
	 * @param depth
	 * @return
	 * @see com.slytechs.jnet.protocol.api.HeaderAccessor#isPresent(int, int)
	 */
	@Override
	public final boolean isPresent(int id, int depth) {
		return packetDescriptor.isPresent(id, depth);
	}

	public final void setPacketDescriptor(PacketDescriptor descriptor) {
		this.packetDescriptor = descriptor;
	}

	/**
	 * @return
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#wireLength()
	 */
	public final int wireLength() {
		return packetDescriptor.wireLength();
	}

}
