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
package com.slytechs.jnet.protocol.api.descriptor;

import static com.slytechs.jnet.core.api.memory.MemoryStructure.*;

import java.lang.foreign.MemoryLayout;

import com.slytechs.jnet.core.api.format.StructFormat;
import com.slytechs.jnet.core.api.format.StructFormattable;
import com.slytechs.jnet.core.api.memory.ByteBuf;
import com.slytechs.jnet.core.api.memory.MemoryHandle.LongHandle;
import com.slytechs.jnet.core.api.memory.MemoryHandle.ShortHandle;
import com.slytechs.jnet.core.api.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.Header;
import com.slytechs.jnet.protocol.api.builtin.L2FrameType;

import static java.lang.foreign.MemoryLayout.*;

/**
 * Minimal pcap-compatible 16-byte packet descriptor.
 * 
 * <p>
 * This descriptor provides a pcap-compatible packet header that can be written
 * directly to pcap files while encoding additional metadata in the unused
 * portions of the standard pcap record format. The descriptor maintains full
 * compatibility with tools that read pcap files - they will simply ignore the
 * extra encoded information.
 * </p>
 * 
 * <h2>Memory Layout</h2>
 * 
 * <pre>
 * Offset  Size  Field            Description
 * ------------------------------------------------------
 * 0x00    8     timestamp        Pcap timestamp (ts_sec + ts_usec/nsec)
 * 0x08    2     caplen          Captured length (pcap caplen)
 * 0x0A    2     rx_info         RX metadata (repurposed pcap space)
 * 0x0C    2     len             Wire length (pcap len)
 * 0x0E    2     tx_info         TX metadata (repurposed pcap space)
 * </pre>
 * 
 * <h2>RX_INFO Bit Layout (16 bits) - Optimized</h2>
 * 
 * <pre>
 * Bits [15-10]: RX_PORT (6 bits) - Receive port number (0-63)
 * Bits [9-3]:   L2_FRAME_TYPE (7 bits) - Layer 2 frame type (0-127)
 * Bits [2-0]:   TIMESTAMP_UNIT (3 bits) - Timestamp unit encoding (0-7)
 * </pre>
 * 
 * <h2>TX_INFO Bit Layout (16 bits)</h2>
 * 
 * <pre>
 * Bits [15-8]: TX_PORT (8 bits) - Transmit port number (0-255)
 * Bit [7]:     TX_ENABLED - Packet should be transmitted
 * Bit [6]:     TX_IMMEDIATE - Transmit immediately
 * Bit [5]:     TX_CRC_RECALC - Recalculate CRC on transmit
 * Bit [4]:     TX_TIMESTAMP_SYNC - Sync transmission with timestamp
 * Bits [3-0]:  Reserved - Future use
 * </pre>
 * 
 * <h2>Usage Example</h2>
 * 
 * <pre>{@code
 * // During capture
 * NetPacketDescriptor desc = new NetPacketDescriptor(TimestampUnit.PCAP_MICRO);
 * desc.setTimestamp(System.currentTimeMillis());
 * desc.setCaptureLength(packet.length());
 * desc.setWireLength(originalLength);
 * desc.setRxPort(interfaceNumber);
 * desc.setL2FrameType(L2FrameType.L2_FRAME_TYPE_ETHER.ordinal());
 * 
 * // Configure for retransmission
 * desc.setTxPort(5);
 * desc.setTxEnabled(true);
 * desc.setTxImmediate(true);
 * 
 * // Write to pcap file (fully compatible)
 * byte[] pcapRecord = desc.toPcapHeader();
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public class NetPacketDescriptor
		extends AbstractPacketDescriptor
		implements PacketDescriptor, StructFormattable, TransmitControl, ReceiveControl {

	/**
	 * Memory layout definition - 16 bytes, pcap compatible.
	 */
	public static final MemoryLayout LAYOUT = structLayout(
			U64.withName("timestamp"), // 0x00-0x07: pcap timestamp
			U16.withName("caplen"), // 0x08-0x09: pcap caplen
			U16.withName("rx_info"), // 0x0A-0x0B: RX metadata
			U16.withName("len"), // 0x0C-0x0D: pcap len
			U16.withName("tx_info") // 0x0E-0x0F: TX metadata
	);

	// MemoryHandles for direct memory access
	private static final LongHandle TIMESTAMP = new LongHandle(LAYOUT, "timestamp");
	private static final ShortHandle CAPLEN = new ShortHandle(LAYOUT, "caplen");
	private static final ShortHandle RX_INFO = new ShortHandle(LAYOUT, "rx_info");
	private static final ShortHandle LEN = new ShortHandle(LAYOUT, "len");
	private static final ShortHandle TX_INFO = new ShortHandle(LAYOUT, "tx_info");

	// RX_INFO bit layout (16 bits)
	private static final int RX_PORT_SHIFT = 10;
	private static final int RX_PORT_MASK = 0x3F; // 6 bits: 64 ports

	private static final int L2_EXTENSION_BIT = 9; // 1 bit: has L2 extensions

	private static final int L2_FRAME_TYPE_SHIFT = 3;
	private static final int L2_FRAME_TYPE_MASK = 0x3F; // 6 bits: 64 types (reduced from 7)

	private static final int TIMESTAMP_UNIT_SHIFT = 0;
	private static final int TIMESTAMP_UNIT_MASK = 0x7; // 3 bits: 8 units

	// TX_INFO bit layout (16 bits)
	private static final int TX_PORT_SHIFT = 8;
	private static final int TX_PORT_MASK = 0xFF; // 8 bits: 256 ports

	private static final int TX_ENABLED_BIT = 7;
	private static final int TX_IMMEDIATE_BIT = 6;
	private static final int TX_CRC_RECALC_BIT = 5;
	private static final int TX_TIMESTAMP_SYNC_BIT = 4;
	// Bits 3-0: Reserved for future use

	/**
	 * Default timestamp unit for pcap files.
	 */
	private static final TimestampUnit DEFAULT_TIMESTAMP_UNIT = TimestampUnit.PCAP_MICRO;

	/**
	 * Creates a new NetPacketDescriptor with L2 frame type and timestamp unit.
	 *
	 * @param l2Type the layer 2 frame type
	 * @param unit   the timestamp unit to use
	 */
	public NetPacketDescriptor(L2FrameType l2Type, TimestampUnit unit) {
		super(l2Type, unit);
		setL2FrameType(l2Type.l2TypeId());
		setTimestampUnit(unit);
	}

	/**
	 * Creates a new NetPacketDescriptor with specified timestamp unit.
	 *
	 * @param unit the timestamp unit to use
	 */
	public NetPacketDescriptor(TimestampUnit unit) {
		super(unit);
		setTimestampUnit(unit);
	}

	@Override
	public boolean bindProtocol(ByteBuf packet, Header header, int protocolId, int depth) {
		if (depth == 0) {
			L2FrameType l2Type = l2FrameType();
			if (l2Type != null && l2Type.protocolId() == protocolId) {
				long offset = 0;
				long length = l2Type.baseLength();

				// Check extension flag for any L2 type that supports extensions
				if (hasL2Extensions()) {
					length = calculateL2ExtendedLength(packet, l2Type);
				}

				return header.bindHeader(packet, protocolId, depth, offset, length);
			}
		}
		return false;
	}

	private int calculateEthernetExtendedLength(ByteBuf packet) {
		int length = 14; // Base Ethernet
		int etherType = packet.getShort(12) & 0xFFFF;

		// Process VLAN tags
		while (etherType == 0x8100 || etherType == 0x88A8) {
			length += 4;
			etherType = packet.getShort(length - 2) & 0xFFFF;
		}

		// Process MPLS labels
		if (etherType == 0x8847 || etherType == 0x8848) {
			while ((packet.get(length + 2) & 0x01) == 0) {
				length += 4;
			}
			length += 4; // Last label
		}

		return length;
	}

	/**
	 * Calculates the extended L2 length based on frame type and extensions.
	 * 
	 * @param packet the packet buffer
	 * @param l2Type the base L2 frame type
	 * @return the extended length including all extensions
	 */
	private int calculateL2ExtendedLength(ByteBuf packet, L2FrameType l2Type) {
		switch (l2Type) {
		case L2_FRAME_TYPE_ETHER:
			return calculateEthernetExtendedLength(packet);

		case L2_FRAME_TYPE_IEEE80211:
			return calculateWifiExtendedLength(packet);

		// Add other L2 types that support extensions

		default:
			return l2Type.baseLength(); // No extension processing
		}
	}

	private int calculateWifiExtendedLength(ByteBuf packet) {
		// Basic 802.11 frame processing
		int fc = packet.getShort(0) & 0xFFFF;
		int type = (fc >> 2) & 0x3;
		int subtype = (fc >> 4) & 0xF;

		int length = 24; // Base MAC header

		// Add QoS field if present
		if (type == 2 && (subtype & 0x8) != 0) {
			length += 2;
		}

		// Add HT Control if present
		if ((fc & 0x8000) != 0) {
			length += 4;
		}

		return length;
	}

	@Override
	public int captureLength() {
		return CAPLEN.getShort(view()) & 0xFFFF;
	}

	// ========== RX metadata accessors ==========

	@Override
	public int descriptorId() {
		return DescriptorType.DESCRIPTOR_TYPE_NET.getValue();
	}

	@Override
	public StructFormat format(StructFormat p) {
		return p.println("NetPacketDescriptor")
				.println("  timestamp: %d (%s)", timestamp(), timestampUnit())
				.println("  caplen: %d", captureLength())
				.println("  len: %d", wireLength())
				.println("  rxPort: %d", rxPort())
				.println("  l2FrameType: %d (%s)", l2Type(), l2FrameType())
				.println("  l2Extensions: %b", hasL2Extensions())
				.println("  txPort: %d", txPort())
				.println("  txEnabled: %b", isTxEnabled())
				.println("  txImmediate: %b", isTxImmediate())
				.println("  txCrcRecalc: %b", isTxCrcRecalc())
				.println("  txTimestampSync: %b", isTxTimestampSync());
	}

	/**
	 * Imports descriptor from pcap header bytes.
	 * 
	 * @param pcapHeader 16-byte pcap header
	 * @throws IllegalArgumentException if header is not 16 bytes
	 */
	public void fromPcapHeader(byte[] pcapHeader) {
		if (pcapHeader.length < 16) {
			throw new IllegalArgumentException("Pcap header must be at least 16 bytes");
		}
		segment().asSlice(view().start(), 16).asByteBuffer().put(pcapHeader, 0, 16);
	}

	/**
	 * Checks if the L2 frame has extensions that need processing.
	 * 
	 * @return true if L2 extensions are present
	 */
	@Override
	public boolean hasL2Extensions() {
		return (rxInfo() & (1 << L2_EXTENSION_BIT)) != 0;
	}

	/**
	 * Checks if CRC should be recalculated on transmit.
	 * 
	 * @return true if CRC recalculation is enabled
	 */
	@Override
	public boolean isTxCrcRecalc() {
		return (txInfo() & (1 << TX_CRC_RECALC_BIT)) != 0;
	}

	// ========== TX metadata accessors ==========

	/**
	 * Checks if transmission is enabled.
	 * 
	 * @return true if TX is enabled
	 */
	@Override
	public boolean isTxEnabled() {
		return (txInfo() & (1 << TX_ENABLED_BIT)) != 0;
	}

	/**
	 * Checks if immediate transmission is requested.
	 * 
	 * @return true if immediate TX is set
	 */
	@Override
	public boolean isTxImmediate() {
		return (txInfo() & (1 << TX_IMMEDIATE_BIT)) != 0;
	}

	/**
	 * Checks if transmission should sync with timestamp.
	 * 
	 * @return true if timestamp sync is enabled
	 */
	@Override
	public boolean isTxTimestampSync() {
		return (txInfo() & (1 << TX_TIMESTAMP_SYNC_BIT)) != 0;
	}

	@Override
	public L2FrameType l2FrameType() {
		int type = (rxInfo() >> L2_FRAME_TYPE_SHIFT) & L2_FRAME_TYPE_MASK;
		return L2FrameType.valueOf(type);
	}

	@Override
	public int l2Type() {
		return (rxInfo() >> L2_FRAME_TYPE_SHIFT) & L2_FRAME_TYPE_MASK;
	}

	@Override
	public long length() {
		return LAYOUT.byteSize();
	}

	private int rxInfo() {
		return RX_INFO.getShort(view()) & 0xFFFF;
	}

	/**
	 * Gets the receive port number.
	 * 
	 * @return the RX port number (0-63)
	 */
	@Override
	public int rxPort() {
		return (rxInfo() >> RX_PORT_SHIFT) & RX_PORT_MASK;
	}

	@Override
	public void setCaptureLength(int length) {
		CAPLEN.setShort(view(), (short) (length & 0xFFFF));
	}

	// ========== Protocol binding ==========

	/**
	 * Sets whether the L2 frame has extensions.
	 * 
	 * @param hasExtensions true if extensions are present
	 */
	public void setL2Extensions(boolean hasExtensions) {
		int info = rxInfo();
		if (hasExtensions) {
			info |= (1 << L2_EXTENSION_BIT);
		} else {
			info &= ~(1 << L2_EXTENSION_BIT);
		}
		setRxInfo(info);
	}

	// ========== Utility methods ==========

	/**
	 * Sets the Layer 2 frame type.
	 * 
	 * @param type the L2 frame type index (0-63)
	 * @throws IllegalArgumentException if type > 63
	 */
	public void setL2FrameType(int type) {
		if (type > L2_FRAME_TYPE_MASK) {
			throw new IllegalArgumentException("L2 frame type must be 0-63, got: " + type);
		}
		int info = rxInfo() & ~(L2_FRAME_TYPE_MASK << L2_FRAME_TYPE_SHIFT);
		info |= ((type & L2_FRAME_TYPE_MASK) << L2_FRAME_TYPE_SHIFT);
		setRxInfo(info);
	}

	private void setRxInfo(int info) {
		RX_INFO.setShort(view(), (short) (info & 0xFFFF));
	}

	/**
	 * Sets the receive port number.
	 * 
	 * @param port the RX port number (0-63)
	 * @throws IllegalArgumentException if port > 63
	 */
	public void setRxPort(int port) {
		if (port > RX_PORT_MASK) {
			throw new IllegalArgumentException("RX port must be 0-63, got: " + port);
		}
		int info = rxInfo() & ~(RX_PORT_MASK << RX_PORT_SHIFT);
		info |= ((port & RX_PORT_MASK) << RX_PORT_SHIFT);
		setRxInfo(info);
	}

	@Override
	public void setTimestamp(long timestamp) {
		TIMESTAMP.setLong(view(), timestamp);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#setTimestamp(long,
	 *      com.slytechs.jnet.core.api.time.TimestampUnit)
	 */
	@Override
	public void setTimestamp(long timestamp, TimestampUnit unit) {
		// Convert timestamp to current unit if needed
		if (unit != timestampUnit()) {
			timestamp = unit.convert(timestamp, timestampUnit());
		}
		setTimestamp(timestamp);
	}

	/**
	 * Sets the timestamp unit.
	 * 
	 * @param unit the timestamp unit to use
	 */
	@Override
	public void setTimestampUnit(TimestampUnit unit) {
		int info = rxInfo() & ~(TIMESTAMP_UNIT_MASK << TIMESTAMP_UNIT_SHIFT);
		info |= ((unit.ordinal() & TIMESTAMP_UNIT_MASK) << TIMESTAMP_UNIT_SHIFT);
		setRxInfo(info);
		super.setTimestampUnit(unit);
	}

	private void setTxBit(int bit, boolean value) {
		int info = txInfo();
		if (value) {
			info |= (1 << bit);
		} else {
			info &= ~(1 << bit);
		}
		setTxInfo(info);
	}

	// ========== Private helper methods ==========

	/**
	 * Sets whether to recalculate CRC on transmit.
	 * 
	 * @param recalc true to recalculate CRC
	 */
	@Override
	public TransmitControl setTxCrcRecalc(boolean recalc) {
		setTxBit(TX_CRC_RECALC_BIT, recalc);

		return this;
	}

	/**
	 * Sets whether transmission is enabled.
	 * 
	 * @param enabled true to enable transmission
	 */
	@Override
	public TransmitControl setTxEnabled(boolean enabled) {
		setTxBit(TX_ENABLED_BIT, enabled);

		return this;
	}

	/**
	 * Sets whether to transmit immediately.
	 * 
	 * @param immediate true for immediate transmission
	 */
	@Override
	public TransmitControl setTxImmediate(boolean immediate) {
		setTxBit(TX_IMMEDIATE_BIT, immediate);

		return this;
	}

	private void setTxInfo(int info) {
		TX_INFO.setShort(view(), (short) (info & 0xFFFF));
	}

	/**
	 * Sets the transmit port number.
	 * 
	 * @param port the TX port number (0-255)
	 */
	@Override
	public TransmitControl setTxPort(int port) {
		if (port > TX_PORT_MASK) {
			throw new IllegalArgumentException("TX port must be 0-255, got: " + port);
		}
		int info = txInfo() & ~(TX_PORT_MASK << TX_PORT_SHIFT);
		info |= ((port & TX_PORT_MASK) << TX_PORT_SHIFT);
		setTxInfo(info);

		return this;
	}

	/**
	 * Sets whether to sync transmission with timestamp.
	 * 
	 * @param sync true to sync with timestamp
	 */
	@Override
	public TransmitControl setTxTimestampSync(boolean sync) {
		setTxBit(TX_TIMESTAMP_SYNC_BIT, sync);

		return this;
	}

	@Override
	public void setWireLength(int length) {
		LEN.setShort(view(), (short) (length & 0xFFFF));
	}

	@Override
	public long timestamp() {
		return TIMESTAMP.getLong(view());
	}

	/**
	 * Gets the timestamp unit encoding.
	 * 
	 * @return the timestamp unit
	 */
	@Override
	public TimestampUnit timestampUnit() {
		int ordinal = (rxInfo() >> TIMESTAMP_UNIT_SHIFT) & TIMESTAMP_UNIT_MASK;
		TimestampUnit[] values = TimestampUnit.values();
		return (ordinal < values.length) ? values[ordinal] : DEFAULT_TIMESTAMP_UNIT;
	}

	/**
	 * Exports descriptor as pcap-compatible header.
	 * 
	 * @return 16-byte array containing pcap header
	 */
	public byte[] toPcapHeader() {
		byte[] header = new byte[16];
		segment().asSlice(view().start(), 16).asByteBuffer().get(header);
		return header;
	}

	@Override
	public String toString() {
		return format(new StructFormat()).toString();
	}

	private int txInfo() {
		return TX_INFO.getShort(view()) & 0xFFFF;
	}

	/**
	 * Gets the transmit port number.
	 * 
	 * @return the TX port number (0-255)
	 */
	@Override
	public int txPort() {
		return (txInfo() >> TX_PORT_SHIFT) & TX_PORT_MASK;
	}

	@Override
	public DescriptorType type() {
		return DescriptorType.DESCRIPTOR_TYPE_NET;
	}

	@Override
	public int wireLength() {
		return LEN.getShort(view()) & 0xFFFF;
	}
}