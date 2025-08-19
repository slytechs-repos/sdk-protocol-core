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

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;

import com.slytechs.jnet.core.api.memory.Memory;
import com.slytechs.jnet.core.api.memory.MemoryStructureProxy;
import com.slytechs.jnet.protocol.api.pack.ProtocolPackManager;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class Header extends MemoryStructureProxy {

	private final int protocolId;
	private long headerOffset;
	private Packet packet;

	public Header(int id, MemoryLayout layout) {
		super(layout);
		this.protocolId = id;
	}

	public Header(int id, MemoryLayout layout, Arena arena) {
		super(layout, arena);
		this.protocolId = id;
	}

	public Header(int id, MemoryLayout layout, MemorySegment pointer) {
		super(layout, pointer);
		this.protocolId = id;
	}

	public Header(int id, MemoryLayout layout, MemorySegment pointer, Arena arena) {
		super(layout, pointer, arena);
		this.protocolId = id;
	}

	public Header(int id, MemoryLayout layout, MemorySegment segment, long offset) {
		super(layout, segment, offset);
		this.protocolId = id;
	}

	public final void bindPacket(long headerOffset, Packet packet) {
		this.headerOffset = headerOffset;
		this.packet = packet;

		int packetLength = packet.captureLength();
		long memoryDataOffset = packet.activeBytesStart();

		super.bindMemory(packet, memoryDataOffset, packetLength);

		onBindPacket();
	}

	public final void unbindPacket() {
		onUnbindPacket();

		packet = null;
		headerOffset = 0; // Allows buffer bindings
		
		super.unbindMemory();
	}

	protected void onBindPacket() {}

	protected void onUnbindPacket() {}

	public Protocol getHeaderProtocol() {
		return ProtocolPackManager.lookupProtocol(getClass());
	}

	public final int getProtocolId() {
		return protocolId;
	}

	public int headerLength() {
		return (int) getMemoryLayout().byteSize();
	}

	public final long headerOffset() {
		return headerOffset;
	}

	public final Packet getBoundPacket() {
		return packet;
	}

	@Override
	public final MemorySegment asMemorySegment() {
		return asMemorySegmentAt(headerOffset());
	}

	@Override
	public final Memory asMemory() {
		return seekSegment(headerOffset());
	}

}
