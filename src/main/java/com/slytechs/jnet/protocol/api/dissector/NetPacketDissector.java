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
package com.slytechs.jnet.protocol.api.dissector;

import java.lang.foreign.MemoryLayout;

import com.slytechs.jnet.core.api.memory.ByteBuf;
import com.slytechs.jnet.core.api.memory.Memory;
import com.slytechs.jnet.core.api.memory.MemoryHandle.LongHandle;
import com.slytechs.jnet.core.api.memory.MemoryHandle.ShortHandle;
import com.slytechs.jnet.core.api.memory.MemoryView;
import com.slytechs.jnet.core.api.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.builtin.L2FrameType;
import com.slytechs.jnet.protocol.api.descriptor.NetPacketDescriptor;

/**
 * High-performance packet dissector for NetPacketDescriptor format.
 * 
 * <p>
 * This dissector wraps packet data with a NetPacketDescriptor, recording
 * the provided L2 frame type and metadata. It performs minimal packet inspection
 * only to detect L2 extensions (VLAN, MPLS, etc.) for better header binding.
 * The dissector writes descriptor data directly to native memory using 
 * MemoryHandles for optimal performance.
 * </p>
 * 
 * <h2>Performance Characteristics</h2>
 * <ul>
 * <li>Zero allocation during dissection</li>
 * <li>Direct memory writes using MemoryHandles</li>
 * <li>JIT-optimized native memory access</li>
 * <li>Minimal packet inspection (2-4 bytes for extension detection)</li>
 * <li>Inline bit manipulation for flags</li>
 * </ul>
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public class NetPacketDissector implements PacketDissector {

	// Import layout from NetPacketDescriptor
	private static final MemoryLayout LAYOUT = NetPacketDescriptor.LAYOUT;

	// MemoryHandles for direct descriptor writes
	private static final LongHandle TIMESTAMP = new LongHandle(LAYOUT, "timestamp");
	private static final ShortHandle CAPLEN = new ShortHandle(LAYOUT, "caplen");
	private static final ShortHandle RX_INFO = new ShortHandle(LAYOUT, "rx_info");
	private static final ShortHandle LEN = new ShortHandle(LAYOUT, "len");
	private static final ShortHandle TX_INFO = new ShortHandle(LAYOUT, "tx_info");

	// RX_INFO bit layout (updated with L2_EXTENSION flag)
	private static final int RX_PORT_SHIFT = 10;
	private static final int RX_PORT_MASK = 0x3F;          // 6 bits: 64 ports

	private static final int L2_EXTENSION_BIT = 9;         // 1 bit: has L2 extensions

	private static final int L2_FRAME_TYPE_SHIFT = 3;
	private static final int L2_FRAME_TYPE_MASK = 0x3F;    // 6 bits: 64 types

	private static final int TIMESTAMP_UNIT_SHIFT = 0;
	private static final int TIMESTAMP_UNIT_MASK = 0x7;    // 3 bits: 8 units

	// Ethernet extension type constants
	private static final int ETHER_TYPE_VLAN = 0x8100;
	private static final int ETHER_TYPE_QINQ = 0x88A8;
	private static final int ETHER_TYPE_MPLS_UC = 0x8847;
	private static final int ETHER_TYPE_MPLS_MC = 0x8848;
	private static final int IEEE_802_3_MAX_LENGTH = 1500;

	/** Current timestamp unit */
	private TimestampUnit timestampUnit = TimestampUnit.PCAP_MICRO;

	/** RX port for packets */
	private int rxPort = 0;

	/** L2 frame type to use */
	private L2FrameType l2FrameType = L2FrameType.L2_FRAME_TYPE_ETHER;

	/** Dissection state - stored as primitives for efficiency */
	private long currentTimestamp;
	private int currentCaplen;
	private int currentWirelen;
	private boolean hasL2Extensions;
	private boolean dissected = false;

	/**
	 * Creates a new NetPacketDissector with default Ethernet L2 type.
	 */
	public NetPacketDissector() {
		this(L2FrameType.L2_FRAME_TYPE_ETHER);
	}

	/**
	 * Creates a new NetPacketDissector with specified L2 frame type.
	 * 
	 * @param l2Type the L2 frame type to use
	 */
	public NetPacketDissector(L2FrameType l2Type) {
		this.l2FrameType = l2Type;
	}

	/**
	 * Creates a new NetPacketDissector with L2 type and timestamp unit.
	 * 
	 * @param l2Type the L2 frame type to use
	 * @param unit   the timestamp unit to use
	 */
	public NetPacketDissector(L2FrameType l2Type, TimestampUnit unit) {
		this.l2FrameType = l2Type;
		this.timestampUnit = unit;
	}

	@Override
	public TimestampUnit timestampUnit() {
		return timestampUnit;
	}

	@Override
	public PacketDissector setTimestampUnit(TimestampUnit timestampUnit) {
		this.timestampUnit = timestampUnit;
		return this;
	}

	@Override
	public int dissectPacket(ByteBuf packet, long timestamp, int caplen, int wirelen) {
		// Store the provided metadata
		this.currentTimestamp = timestamp;
		this.currentCaplen = caplen;
		this.currentWirelen = wirelen;
		
		// Detect L2 extensions if present
		this.hasL2Extensions = detectL2Extensions(packet, caplen);
		
		this.dissected = true;

		// Return minimal bytes examined (just for extension detection)
		return getExaminedBytes();
	}

	@Override
	public int dissectPacket(Memory packet, long timestamp, int caplen, int wirelen) {
		// Create temporary buffer view - no allocation
		ByteBuf buffer = new ByteBuf();
		buffer.bind(packet);
		return dissectPacket(buffer, timestamp, caplen, wirelen);
	}

	@Override
	public void recycle() {
		dissected = false;
		currentTimestamp = 0;
		currentCaplen = 0;
		currentWirelen = 0;
		hasL2Extensions = false;
	}

	@Override
	public int writeDescriptor(ByteBuf buffer) {
		if (!dissected) {
			return 0; // Nothing to write
		}

		// Get the buffer's view for MemoryHandle operations
		MemoryView view = buffer.view();
		
		// Calculate where to write (current position in buffer)
		long writeOffset = buffer.position();

		// Write core fields directly using MemoryHandles
		TIMESTAMP.setLong(view, writeOffset, currentTimestamp);
		CAPLEN.setShort(view, writeOffset, (short) currentCaplen);
		LEN.setShort(view, writeOffset, (short) currentWirelen);

		// Build RX_INFO with extension flag
		int rxInfo = ((rxPort & RX_PORT_MASK) << RX_PORT_SHIFT) |
		            (hasL2Extensions ? (1 << L2_EXTENSION_BIT) : 0) |
		            ((l2FrameType.l2TypeId() & L2_FRAME_TYPE_MASK) << L2_FRAME_TYPE_SHIFT) |
		            ((timestampUnit.ordinal() & TIMESTAMP_UNIT_MASK) << TIMESTAMP_UNIT_SHIFT);
		RX_INFO.setShort(view, writeOffset, (short) rxInfo);

		// TX_INFO starts at zero (no TX flags set initially)
		TX_INFO.setShort(view, writeOffset, (short) 0);

		// Advance buffer position
		buffer.adjustPosition(16);

		// Check for errors
		if (buffer.hasError()) {
			buffer.clearError();
			return 0;
		}

		return 16; // Successfully wrote 16 bytes
	}

	/**
	 * Detects L2 extensions based on frame type.
	 * 
	 * @param packet the packet buffer
	 * @param caplen captured length
	 * @return true if extensions are detected
	 */
	private boolean detectL2Extensions(ByteBuf packet, int caplen) {
		switch (l2FrameType) {
			case L2_FRAME_TYPE_ETHER:
				return detectEthernetExtensions(packet, caplen);
				
			case L2_FRAME_TYPE_IEEE80211:
				return detectWifiExtensions(packet, caplen);
				
			// Add other L2 types as needed
			default:
				return false;
		}
	}

	/**
	 * Detects Ethernet extensions (VLAN, MPLS, LLC/SNAP).
	 * 
	 * @param packet the packet buffer
	 * @param caplen captured length
	 * @return true if Ethernet extensions are detected
	 */
	private boolean detectEthernetExtensions(ByteBuf packet, int caplen) {
		if (caplen < 14) {
			return false; // Not enough data for Ethernet header
		}

		int etherType = packet.getShort(12) & 0xFFFF;
		
		return etherType == ETHER_TYPE_VLAN ||      // VLAN tag
		       etherType == ETHER_TYPE_QINQ ||       // Q-in-Q
		       etherType == ETHER_TYPE_MPLS_UC ||    // MPLS unicast
		       etherType == ETHER_TYPE_MPLS_MC ||    // MPLS multicast
		       etherType <= IEEE_802_3_MAX_LENGTH;   // LLC/SNAP (length field)
	}

	/**
	 * Detects WiFi extensions (QoS, HT Control).
	 * 
	 * @param packet the packet buffer
	 * @param caplen captured length
	 * @return true if WiFi extensions are detected
	 */
	private boolean detectWifiExtensions(ByteBuf packet, int caplen) {
		if (caplen < 2) {
			return false; // Not enough data for frame control
		}

		int fc = packet.getShort(0) & 0xFFFF;
		int type = (fc >> 2) & 0x3;
		int subtype = (fc >> 4) & 0xF;
		
		// Check for QoS data frames or HT Control field
		boolean hasQos = (type == 2 && (subtype & 0x8) != 0);
		boolean hasHtControl = ((fc & 0x8000) != 0);
		
		return hasQos || hasHtControl;
	}

	/**
	 * Gets the number of bytes examined during dissection.
	 * 
	 * @return bytes examined
	 */
	private int getExaminedBytes() {
		switch (l2FrameType) {
			case L2_FRAME_TYPE_ETHER:
				return Math.min(14, currentCaplen);  // EtherType at bytes 12-13
			case L2_FRAME_TYPE_IEEE80211:
				return Math.min(2, currentCaplen);   // Frame Control at bytes 0-1
			default:
				return 0;
		}
	}

	/**
	 * Sets the RX port number.
	 * 
	 * @param port the RX port (0-63)
	 * @return this dissector
	 * @throws IllegalArgumentException if port > 63
	 */
	public NetPacketDissector setRxPort(int port) {
		if (port > RX_PORT_MASK) {
			throw new IllegalArgumentException("RX port must be 0-63, got: " + port);
		}
		this.rxPort = port;
		return this;
	}

	/**
	 * Gets the RX port number.
	 * 
	 * @return the RX port
	 */
	public int getRxPort() {
		return rxPort;
	}

	/**
	 * Sets the L2 frame type.
	 * 
	 * @param l2Type the L2 frame type
	 * @return this dissector
	 */
	public NetPacketDissector setL2FrameType(L2FrameType l2Type) {
		this.l2FrameType = l2Type;
		return this;
	}

	/**
	 * Gets the L2 frame type.
	 * 
	 * @return the L2 frame type
	 */
	public L2FrameType getL2FrameType() {
		return l2FrameType;
	}

	/**
	 * Gets the current timestamp.
	 * 
	 * @return the timestamp from last dissection
	 */
	public long getTimestamp() {
		return currentTimestamp;
	}

	/**
	 * Gets the current capture length.
	 * 
	 * @return the capture length from last dissection
	 */
	public int getCaptureLength() {
		return currentCaplen;
	}

	/**
	 * Gets the current wire length.
	 * 
	 * @return the wire length from last dissection
	 */
	public int getWireLength() {
		return currentWirelen;
	}

	/**
	 * Checks if L2 extensions were detected.
	 * 
	 * @return true if L2 extensions were detected
	 */
	public boolean hasL2Extensions() {
		return hasL2Extensions;
	}

	/**
	 * Checks if a packet has been dissected.
	 * 
	 * @return true if a packet has been dissected
	 */
	public boolean isDissected() {
		return dissected;
	}
}