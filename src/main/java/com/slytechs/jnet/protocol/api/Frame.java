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
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

import com.slytechs.jnet.core.api.memory.BoundView;

/**
 * Zero-allocation L2 frame accessor for high-speed packet capture.
 * 
 * <p>
 * Provides direct memory access to L2 frame components without allocations.
 * All methods use caller-supplied buffers to achieve 100M+ pps processing.
 * Hardware provides frame structure via configure() method.
 * </p>
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public final class Frame extends BoundView {

	// ==================== Constants ====================
	
	public static final int MAC_LENGTH = 6;
	public static final int ETHERNET_HEADER_LENGTH = 14;
	public static final int VLAN_TAG_LENGTH = 4;
	public static final int FCS_LENGTH = 4;
	
	// ==================== VarHandles ====================
	
	private static final VarHandle BYTE_HANDLE = ValueLayout.JAVA_BYTE.varHandle();
	private static final VarHandle SHORT_BE_HANDLE = ValueLayout.JAVA_SHORT_UNALIGNED
			.withOrder(ByteOrder.BIG_ENDIAN).varHandle();
	private static final VarHandle INT_BE_HANDLE = ValueLayout.JAVA_INT_UNALIGNED
			.withOrder(ByteOrder.BIG_ENDIAN).varHandle();
	
	// ==================== Fields ====================
	
	private FrameType frameType = FrameType.UNKNOWN;
	private int headerOffset = 0;
	private int headerLength = 0;
	private int dataOffset = 0;
	private int dataLength = 0;
	private boolean hasPreamble = false;
	private boolean hasFcs = false;
	private int vlanCount = 0;
	
	// ==================== Constructors ====================
	
	public Frame() {
		super();
	}
	
	public Frame(FrameType frameType) {
		this.frameType = frameType;
	}
	
	// ==================== Configuration ====================
	
	/**
	 * Configures frame structure from hardware descriptor.
	 * Zero-allocation configuration method.
	 */
	public Frame configure(FrameType type, int headerOffset, int headerLength, 
			int dataOffset, int dataLength, boolean hasPreamble, boolean hasFcs, int vlanCount) {
		this.frameType = type;
		this.headerOffset = headerOffset;
		this.headerLength = headerLength;
		this.dataOffset = dataOffset;
		this.dataLength = dataLength;
		this.hasPreamble = hasPreamble;
		this.hasFcs = hasFcs;
		this.vlanCount = vlanCount;
		return this;
	}
	
	// ==================== Zero-Allocation Accessors ====================
	
	/**
	 * Copies bytes to caller-supplied buffer.
	 * 
	 * @param offset source offset in frame
	 * @param dest destination buffer
	 * @param destOffset offset in destination
	 * @param length number of bytes
	 */
	public void getBytes(long offset, byte[] dest, int destOffset, int length) {
		checkIfBound();
		MemorySegment.copy(segment(), start() + offset,
				MemorySegment.ofArray(dest), destOffset, length);
	}
	
	/**
	 * Copies bytes to caller-supplied buffer.
	 */
	public void getBytes(long offset, byte[] dest) {
		getBytes(offset, dest, 0, dest.length);
	}
	
	/**
	 * Gets byte at offset.
	 */
	public byte getByte(long offset) {
		checkIfBound();
		return (byte) BYTE_HANDLE.get(segment(), start() + offset);
	}
	
	/**
	 * Gets 16-bit value at offset (big-endian).
	 */
	public short getShortBE(long offset) {
		checkIfBound();
		return (short) SHORT_BE_HANDLE.get(segment(), start() + offset);
	}
	
	/**
	 * Gets 16-bit unsigned value at offset (big-endian).
	 */
	public int getUnsignedShortBE(long offset) {
		return Short.toUnsignedInt(getShortBE(offset));
	}
	
	/**
	 * Gets 32-bit value at offset (big-endian).
	 */
	public int getIntBE(long offset) {
		checkIfBound();
		return (int) INT_BE_HANDLE.get(segment(), start() + offset);
	}
	
	// ==================== Frame Structure ====================
	
	public FrameType frameType() {
		return frameType;
	}
	
	public int headerOffset() {
		return headerOffset;
	}
	
	public int headerLength() {
		return headerLength;
	}
	
	public int dataOffset() {
		return dataOffset;
	}
	
	public int dataLength() {
		return dataLength;
	}
	
	public boolean hasPreamble() {
		return hasPreamble;
	}
	
	public boolean hasFcs() {
		return hasFcs;
	}
	
	public int vlanCount() {
		return vlanCount;
	}
	
	// ==================== Memory Segments ====================
	
	/**
	 * Gets header memory segment.
	 * Warning: Creates new slice object.
	 */
	public MemorySegment headerSegment() {
		checkIfBound();
		return segment().asSlice(start() + headerOffset, headerLength);
	}
	
	/**
	 * Gets data memory segment.
	 * Warning: Creates new slice object.
	 */
	public MemorySegment dataSegment() {
		checkIfBound();
		if (dataLength <= 0) return MemorySegment.NULL;
		return segment().asSlice(start() + dataOffset, dataLength);
	}
	
	// ==================== Ethernet-Specific Zero-Allocation ====================
	
	/**
	 * Copies destination MAC to supplied buffer.
	 * 
	 * @param dest 6-byte buffer
	 */
	public void getDestinationMac(byte[] dest) {
		if (frameType != FrameType.ETHERNET_II && frameType != FrameType.IEEE_802_3) {
			throw new IllegalStateException("Not an Ethernet frame");
		}
		getBytes(headerOffset, dest, 0, MAC_LENGTH);
	}
	
	/**
	 * Copies source MAC to supplied buffer.
	 * 
	 * @param dest 6-byte buffer
	 */
	public void getSourceMac(byte[] dest) {
		if (frameType != FrameType.ETHERNET_II && frameType != FrameType.IEEE_802_3) {
			throw new IllegalStateException("Not an Ethernet frame");
		}
		getBytes(headerOffset + MAC_LENGTH, dest, 0, MAC_LENGTH);
	}
	
	/**
	 * Gets EtherType/Length field.
	 */
	public int etherType() {
		if (frameType != FrameType.ETHERNET_II && frameType != FrameType.IEEE_802_3) {
			return -1;
		}
		long offset = headerOffset + 12 + (vlanCount * VLAN_TAG_LENGTH);
		return getUnsignedShortBE(offset);
	}
	
	/**
	 * Gets first VLAN ID.
	 */
	public int vlanId() {
		if (vlanCount == 0) return -1;
		int tci = getUnsignedShortBE(headerOffset + 14);
		return tci & 0x0FFF;
	}
	
	/**
	 * Gets VLAN priority (PCP).
	 */
	public int vlanPriority() {
		if (vlanCount == 0) return -1;
		int tci = getUnsignedShortBE(headerOffset + 14);
		return (tci >> 13) & 0x07;
	}
	
	/**
	 * Gets FCS value if present.
	 */
	public int fcs() {
		if (!hasFcs) return 0;
		return getIntBE(length() - FCS_LENGTH);
	}
	
	// ==================== WiFi-Specific ====================
	
	/**
	 * Gets WiFi frame control field.
	 */
	public int wifiFrameControl() {
		if (frameType != FrameType.WIFI_802_11) return -1;
		return getUnsignedShortBE(headerOffset);
	}
	
	/**
	 * Gets WiFi frame type (0-3).
	 */
	public int wifiType() {
		int fc = wifiFrameControl();
		return fc >= 0 ? (fc >> 2) & 0x03 : -1;
	}
	
	/**
	 * Gets WiFi frame subtype.
	 */
	public int wifiSubtype() {
		int fc = wifiFrameControl();
		return fc >= 0 ? (fc >> 4) & 0x0F : -1;
	}
	
	// ==================== Lifecycle ====================
	
	@Override
	public void onUnbind() {
		// Reset to default state
		frameType = FrameType.UNKNOWN;
		headerOffset = 0;
		headerLength = 0;
		dataOffset = 0;
		dataLength = 0;
		hasPreamble = false;
		hasFcs = false;
		vlanCount = 0;
	}
	
	// ==================== Types ====================
	
	public enum FrameType {
		UNKNOWN,
		ETHERNET_II,
		IEEE_802_3,
		WIFI_802_11,
		RAW
	}
}