/*
 * Copyright 2005-2026 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.protocol.core.descriptor;

import static com.slytechs.sdk.common.memory.MemoryStructure.*;

import java.lang.foreign.MemoryLayout;

import com.slytechs.sdk.common.memory.BindableView;
import com.slytechs.sdk.common.memory.MemoryHandle.LongHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.ShortHandle;
import com.slytechs.sdk.common.time.TimestampUnit;
import com.slytechs.sdk.protocol.core.dissector.OnDemandPacketDissector;
import com.slytechs.sdk.protocol.core.header.Header;

import static java.lang.foreign.MemoryLayout.*;

/**
 * Type-1 packet descriptor with a compact 16-byte packed layout.
 * 
 * <p>
 * This descriptor is designed for high-performance, zero-copy capture scenarios
 * where minimal metadata is required. It stores only essential packet
 * information and basic RX/TX capabilities in a tightly packed native memory
 * structure.
 * </p>
 * 
 * <p>
 * The descriptor does <strong>not</strong> contain a full protocol dissection
 * table (unlike {@link NetPacketDescriptor}). Header binding is performed
 * on-demand via {@link OnDemandPacketDissector}.
 * </p>
 * 
 * <h2>Native Memory Layout (C-equivalent structure)</h2>
 * 
 * <pre>
 * // Packed layout, 1-byte alignment, total size = 16 bytes
 * struct type1_packet_descriptor {
 *     uint64_t timestamp;      // 8 bytes: Packet capture timestamp
 *     uint16_t caplen;         // 2 bytes: Captured length
 *     uint16_t rx_info;        // 2 bytes: RX metadata (port, timestamp unit, L2 frame type)
 *     uint16_t wirelen;        // 2 bytes: Original wire length
 *     uint16_t tx_info;        // 2 bytes: TX metadata (port, enable, immediate)
 * } __attribute__((packed, aligned(1)));
 * </pre>
 * 
 * <h3>rx_info bit field (16 bits)</h3>
 * 
 * <pre>
 * Bits  0- 7 : rx_port          (0-255)
 * Bits  8-10 : timestamp_unit   (0-7 → TimestampUnit ordinal)
 * Bits 11-15 : l2_frame_type    (0-63)
 * </pre>
 * 
 * <h3>tx_info bit field (16 bits)</h3>
 * 
 * <pre>
 * Bits  0- 7 : tx_port          (0-255)
 * Bit      8 : tx_enabled       (1 = enabled)
 * Bit      9 : tx_immediate     (1 = immediate transmit)
 * Bits 10-15 : reserved         (must be 0)
 * </pre>
 * 
 * <h2>Supported Capabilities</h2>
 * <ul>
 * <li>RX: timestamp, rx_port</li>
 * <li>TX: tx_port, tx_enable, tx_immediate</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class Type1PacketDescriptor
		extends AbstractPacketDescriptor
		implements TxCapabilities, RxCapabilities {

	/** Total descriptor size: 16 bytes, packed with 1-byte alignment */
	public static final MemoryLayout LAYOUT = structLayout(
			U64_A1.withName("timestamp"),
			U16_A1.withName("caplen"),
			U16_A1.withName("rx_info"),
			U16_A1.withName("wirelen"),
			U16_A1.withName("tx_info")).withName("type1").withByteAlignment(1);

	private static final LongHandle TIMESTAMP = new LongHandle(LAYOUT, "timestamp");
	private static final ShortHandle CAPLEN = new ShortHandle(LAYOUT, "caplen");
	private static final ShortHandle RX_INFO = new ShortHandle(LAYOUT, "rx_info");
	private static final ShortHandle WIRELEN = new ShortHandle(LAYOUT, "wirelen");
	private static final ShortHandle TX_INFO = new ShortHandle(LAYOUT, "tx_info");

	/* rx_info bit fields */
	private static final int RX_PORT_SHIFT = 0;
	private static final int RX_PORT_MASK = 0xFF; // bits 0-7
	private static final int TIMESTAMP_UNIT_SHIFT = 8;
	private static final int TIMESTAMP_UNIT_MASK = 0x07; // bits 8-10 (3 bits)
	private static final int L2_FRAME_TYPE_SHIFT = 11;
	private static final int L2_FRAME_TYPE_MASK = 0x3F; // bits 11-15 (6 bits)

	/* tx_info bit fields */
	private static final int TX_PORT_SHIFT = 0;
	private static final int TX_PORT_MASK = 0xFF; // bits 0-7
	private static final int TX_ENABLED_BIT = (1 << 8); // bit 8
	private static final int TX_IMMEDIATE_BIT = (1 << 9); // bit 9

	private static final long RX_CAPABILITIES = RxCapabilities.RX_TIMESTAMP
			| RxCapabilities.RX_PORT;

	private static final long TX_CAPABILITIES = TxCapabilities.TX_PORT
			| TxCapabilities.TX_ENABLE
			| TxCapabilities.TX_IMMEDIATE;

	/**
	 * Creates a new Type-1 descriptor using the default native timestamp unit.
	 * 
	 * <p>
	 * Equivalent to {@code new Type1PacketDescriptor(TimestampUnit.NATIVE)}.
	 * </p>
	 */
	public Type1PacketDescriptor() {
		this(DEFAULT_TIMESTAMP_UNIT);
	}

	/**
	 * Creates a new Type-1 descriptor with a specific timestamp unit.
	 * 
	 * <p>
	 * The timestamp unit is stored in the {@code rx_info} field and affects how the
	 * {@code timestamp} value should be interpreted.
	 * </p>
	 *
	 * @param timestampUnit the initial timestamp resolution/unit
	 */
	public Type1PacketDescriptor(TimestampUnit timestampUnit) {
		super(DescriptorType.TYPE1, timestampUnit);
	}

	/**
	 * Binds a header instance to the packet data on-demand.
	 * 
	 * <p>
	 * Since Type-1 descriptors do not store dissection tables, header binding is
	 * delegated to the {@link OnDemandPacketDissector}, which performs lightweight
	 * parsing only when a header is requested.
	 * </p>
	 *
	 * @param packet     the packet view containing raw data
	 * @param header     reusable header instance to bind
	 * @param protocolId protocol ID of the requested header
	 * @param depth      occurrence depth (for tunneled protocols)
	 * @return {@code true} if the header was found and bound
	 */
	@Override
	public boolean bindHeader(BindableView packet, Header header, int protocolId, int depth) {
		return OnDemandPacketDissector.bindHeader(packet, header, depth, protocolId, depth);
	}

	/**
	 * Returns the number of bytes captured from the original packet.
	 * 
	 * <p>
	 * May be less than {@link #wireLength()} if the capture was truncated.
	 * </p>
	 *
	 * @return captured length in bytes
	 */
	@Override
	public int captureLength() {
		return CAPLEN.getUnsignedShort(view());
	}

	/**
	 * Retrieves the L2 frame type stored in the descriptor.
	 * 
	 * <p>
	 * The value is extracted from bits 11-15 of the {@code rx_info} field. Valid
	 * range is 0-63. This can be used to indicate Ethernet type, VLAN
	 * encapsulation, or other link-layer specifics without full dissection.
	 * </p>
	 *
	 * @return L2 frame type value (0-63)
	 */
	@Override
	public int l2FrameId() {
		return (rxInfo() >> L2_FRAME_TYPE_SHIFT) & L2_FRAME_TYPE_MASK;
	}

	/**
	 * Retrieves the RX port index associated with this packet.
	 * 
	 * <p>
	 * Extracted from bits 0-7 of the {@code rx_info} field. Valid range: 0-255.
	 * </p>
	 *
	 * @return RX port index
	 */
	@Override
	public int rxPort() {
		return (rxInfo() >> RX_PORT_SHIFT) & RX_PORT_MASK;
	}

	/**
	 * Retrieves the timestamp unit ordinal stored in the descriptor.
	 * 
	 * <p>
	 * Extracted from bits 8-10 of the {@code rx_info} field. The returned value
	 * corresponds to the ordinal of a {@link TimestampUnit} enum constant.
	 * </p>
	 *
	 * @return timestamp unit ordinal (0-7)
	 */
	@Override
	public int timestampType() {
		return (rxInfo() >> TIMESTAMP_UNIT_SHIFT) & TIMESTAMP_UNIT_MASK;
	}

	/**
	 * Retrieves the TX port index for packet transmission.
	 * 
	 * <p>
	 * Extracted from bits 0-7 of the {@code tx_info} field. Valid range: 0-255.
	 * </p>
	 *
	 * @return TX port index
	 */
	@Override
	public int txPort() {
		return (txInfo() >> TX_PORT_SHIFT) & TX_PORT_MASK;
	}

	/**
	 * Checks whether TX offload is enabled for this packet.
	 * 
	 * <p>
	 * Returns the state of bit 8 in the {@code tx_info} field. When {@code true},
	 * the packet is marked as eligible for transmission through the TX path (e.g.,
	 * for packet replay or forwarding).
	 * </p>
	 *
	 * @return {@code true} if TX is enabled, {@code false} otherwise
	 */
	@Override
	public boolean isTxEnabled() {
		return (txInfo() & TX_ENABLED_BIT) != 0;
	}

	/**
	 * Checks whether the packet is flagged for immediate transmission.
	 * 
	 * <p>
	 * Returns the state of bit 9 in the {@code tx_info} field. When {@code true},
	 * the transmission engine should bypass any queuing or scheduling and send the
	 * packet as soon as possible.
	 * </p>
	 *
	 * @return {@code true} if immediate transmit is requested, {@code false}
	 *         otherwise
	 */
	@Override
	public boolean isTxImmediate() {
		return (txInfo() & TX_IMMEDIATE_BIT) != 0;
	}

	/**
	 * Creates a new unbound Type-1 descriptor.
	 *
	 * @return new unbound descriptor instance
	 */
	@Override
	public Type1PacketDescriptor newUnbound() {
		return new Type1PacketDescriptor();
	}

	/**
	 * Returns this descriptor instance as the RX capabilities interface.
	 *
	 * @return {@code this}
	 */
	@Override
	public RxCapabilities rx() {
		return this;
	}

	/**
	 * Returns the bitmask of supported RX capabilities for this descriptor type.
	 *
	 * @return capability bitmask
	 */
	@Override
	public long rxCapabilitiesBitmask() {
		return RX_CAPABILITIES;
	}

	/**
	 * Returns the raw 16-bit {@code rx_info} field value.
	 * 
	 * <p>
	 * This field packs rx_port, timestamp unit, and L2 frame type. Use specific
	 * getters/setters for individual fields unless raw access is required.
	 * </p>
	 *
	 * @return unsigned 16-bit rx_info value
	 */
	public int rxInfo() {
		return RX_INFO.getUnsignedShort(view());
	}

	/**
	 * Sets the captured length field.
	 *
	 * @param length number of captured bytes
	 * @return this descriptor instance for method chaining
	 */
	@Override
	public Type1PacketDescriptor setCaptureLength(int length) {
		CAPLEN.setShort(view(), (short) length);
		return this;
	}

	/**
	 * Sets the L2 frame type in the descriptor.
	 * 
	 * <p>
	 * The value is stored in bits 11-15 of the {@code rx_info} field. Values
	 * outside the 0-63 range will be masked.
	 * </p>
	 *
	 * @param l2FrameType the L2 frame type to store (0-63)
	 * @return this descriptor instance for method chaining
	 */
	@Override
	public Type1PacketDescriptor setL2FrameType(int l2FrameType) {
		int rxInfo = rxInfo();
		rxInfo &= ~(L2_FRAME_TYPE_MASK << L2_FRAME_TYPE_SHIFT);
		rxInfo |= (l2FrameType & L2_FRAME_TYPE_MASK) << L2_FRAME_TYPE_SHIFT;

		super.setL2FrameType(l2FrameType);

		return setRxInfo(rxInfo);
	}

	/**
	 * Sets the raw {@code rx_info} field value.
	 * 
	 * <p>
	 * Directly writes the 16-bit value containing packed RX metadata. Prefer
	 * individual setters for safety unless bulk initialization is needed.
	 * </p>
	 *
	 * @param rxInfo new rx_info value
	 * @return this descriptor instance for method chaining
	 */
	public Type1PacketDescriptor setRxInfo(int rxInfo) {
		RX_INFO.setShort(view(), (short) rxInfo);
		return this;
	}

	/**
	 * Sets the RX port index for this packet.
	 * 
	 * <p>
	 * Stored in bits 0-7 of the {@code rx_info} field. Values outside 0-255 are
	 * masked.
	 * </p>
	 *
	 * @param rxPort RX port index (0-255)
	 * @return this descriptor instance for method chaining
	 */
	@Override
	public Type1PacketDescriptor setRxPort(int rxPort) {
		int rxInfo = rxInfo();
		rxInfo &= ~(RX_PORT_MASK << RX_PORT_SHIFT);
		rxInfo |= (rxPort & RX_PORT_MASK) << RX_PORT_SHIFT;

		return setRxInfo(rxInfo);
	}

	/**
	 * Sets the packet capture timestamp value.
	 *
	 * @param timestamp raw timestamp in units defined by the timestamp unit
	 * @return this descriptor instance for method chaining
	 */
	@Override
	public Type1PacketDescriptor setTimestamp(long timestamp) {
		TIMESTAMP.setLong(view(), timestamp);
		return this;
	}

	/**
	 * Sets both the timestamp value and its unit.
	 *
	 * @param timestamp raw timestamp value
	 * @param unit      timestamp resolution/unit
	 * @return this descriptor instance for method chaining
	 */
	@Override
	public Type1PacketDescriptor setTimestamp(long timestamp, TimestampUnit unit) {
		TIMESTAMP.setLong(view(), timestamp);
		super.setTimestampUnit(unit);
		return this;
	}

	/**
	 * Sets the timestamp unit using its ordinal value.
	 * 
	 * <p>
	 * The ordinal is stored in bits 8-10 of the {@code rx_info} field. Values
	 * outside 0-7 will be masked.
	 * </p>
	 *
	 * @param timestampType ordinal value of the desired {@link TimestampUnit}
	 * @return this descriptor instance for method chaining
	 */
	public Type1PacketDescriptor setTimestampType(int timestampType) {
		int rxInfo = rxInfo();
		rxInfo &= ~(TIMESTAMP_UNIT_MASK << TIMESTAMP_UNIT_SHIFT);
		rxInfo |= (timestampType & TIMESTAMP_UNIT_MASK) << TIMESTAMP_UNIT_SHIFT;

		super.setTimestampUnit(TimestampUnit.valueOf(timestampType));

		return setRxInfo(rxInfo);
	}

	/**
	 * Enables or disables TX offload for this packet.
	 * 
	 * <p>
	 * Sets/clears bit 8 in the {@code tx_info} field. When enabled, the packet is
	 * eligible for transmission via the TX path.
	 * </p>
	 *
	 * @param enabled {@code true} to enable TX, {@code false} to disable
	 * @return this descriptor instance for method chaining
	 */
	@Override
	public Type1PacketDescriptor setTxEnabled(boolean enabled) {
		int txInfo = txInfo();
		if (enabled)
			txInfo |= TX_ENABLED_BIT;
		else
			txInfo &= ~TX_ENABLED_BIT;

		return setTxInfo(txInfo);
	}

	/**
	 * Controls whether the packet should be transmitted immediately.
	 * 
	 * <p>
	 * Sets/clears bit 9 in the {@code tx_info} field. Immediate transmit bypasses
	 * any queuing or scheduling delays.
	 * </p>
	 *
	 * @param immediate {@code true} for immediate TX, {@code false} for normal
	 *                  queuing
	 * @return this descriptor instance for method chaining
	 */
	@Override
	public Type1PacketDescriptor setTxImmediate(boolean immediate) {
		int txInfo = txInfo();
		if (immediate)
			txInfo |= TX_IMMEDIATE_BIT;
		else
			txInfo &= ~TX_IMMEDIATE_BIT;

		return setTxInfo(txInfo);
	}

	/**
	 * Sets the raw {@code tx_info} field value.
	 * 
	 * <p>
	 * Directly writes the 16-bit value containing packed TX metadata.
	 * </p>
	 *
	 * @param txInfo new tx_info value
	 * @return this descriptor instance for method chaining
	 */
	public Type1PacketDescriptor setTxInfo(int txInfo) {
		TX_INFO.setShort(view(), (short) txInfo);
		return this;
	}

	/**
	 * Sets the TX port index for packet transmission.
	 * 
	 * <p>
	 * Stored in bits 0-7 of the {@code tx_info} field. Values outside 0-255 are
	 * masked.
	 * </p>
	 *
	 * @param txPort TX port index (0-255)
	 * @return this descriptor instance for method chaining
	 */
	@Override
	public Type1PacketDescriptor setTxPort(int txPort) {
		int txInfo = txInfo();
		txInfo &= ~(TX_PORT_MASK << TX_PORT_SHIFT);
		txInfo |= (txPort & TX_PORT_MASK) << TX_PORT_SHIFT;

		return setTxInfo(txInfo);
	}

	/**
	 * Sets the original wire length of the packet.
	 *
	 * @param length original packet length on the wire
	 * @return this descriptor instance for method chaining
	 */
	@Override
	public Type1PacketDescriptor setWireLength(int length) {
		WIRELEN.setShort(view(), (short) length);
		return this;
	}

	/**
	 * Returns the raw packet capture timestamp.
	 *
	 * @return timestamp value in the unit stored in the descriptor
	 */
	@Override
	public long timestamp() {
		return TIMESTAMP.getLong(view());
	}

	/**
	 * Returns this descriptor instance as the TX capabilities interface.
	 *
	 * @return {@code this}
	 */
	@Override
	public TxCapabilities tx() {
		return this;
	}

	/**
	 * Returns the bitmask of supported TX capabilities for this descriptor type.
	 *
	 * @return capability bitmask
	 */
	@Override
	public long txCapabilitiesBitmask() {
		return TX_CAPABILITIES;
	}

	/**
	 * Returns the raw 16-bit {@code tx_info} field value.
	 * 
	 * <p>
	 * This field packs tx_port, tx_enabled, and tx_immediate flags.
	 * </p>
	 *
	 * @return unsigned 16-bit tx_info value
	 */
	public int txInfo() {
		return TX_INFO.getUnsignedShort(view());
	}

	/**
	 * Returns the original wire length of the packet.
	 * 
	 * <p>
	 * This may be larger than {@link #captureLength()} if truncation occurred.
	 * </p>
	 *
	 * @return wire length in bytes
	 */
	@Override
	public int wireLength() {
		return WIRELEN.getUnsignedShort(view());
	}
}