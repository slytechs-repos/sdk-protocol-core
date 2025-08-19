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
package com.slytechs.jnet.protocol.api.descriptor;

import java.lang.foreign.MemoryLayout;
import java.lang.invoke.VarHandle;

import com.slytechs.jnet.core.api.format.StructFormat;
import com.slytechs.jnet.core.api.format.StructFormattable;
import com.slytechs.jnet.core.api.memory.MemoryStructureProxy;
import com.slytechs.jnet.protocol.api.Header;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class NetPacketDescriptor
		extends MemoryStructureProxy
		implements PacketDescriptor, StructFormattable {

	public static final int MAX_RECORD_COUNT = 64;

	public static final MemoryLayout LAYOUT$COMPACT = unionLayout(
			structLayout(
					JAVA_LONG.withName("timestamp"),
					JAVA_LONG.withName("length") // If negative, [orig(i15):incl(i16):res(i32)], otherwise incl(i31)

			).withName("fast_path"),

			/**
			 * {@snippet lang = c:
			 * struct {
			 * 		int64	timestamp:56,
			 * 				descr_type:4, // 16 descr types (0 == PCAP)
			 * 				descr_len:4;  // 16-bytes * (descr_len + 1)
			 * 		int32	caplen;
			 * 		int32	wirelen;
			 * }
			 * }
			 */
			structLayout(
					JAVA_LONG.withName("timestamp_descr"), // type == 0, len == 0
					JAVA_INT.withName("caplen"),
					JAVA_INT.withName("wirelen")

			).withName("file_pcap_descr"),

			/**
			 * {@snippet lang = c:
			 * struct {
			 *      // Word0
			 * 		int64	timestamp:56,
			 * 				descr_type:4,      // 16 descr types (type == 1)
			 * 				descr_len:4;       // 16-bytes *     (len == 0)
			 * 
			 *     // Word3
			 * 		int64	length:16,         // 15:00 RX & TX
			 * 				rx_port:6          // 00:00 RX
			 * 				tx_port:6          // 00:00 TX
			 * 				tx_sync:1,
			 * 				tx_now:1,
			 * 				tx_ignore:1,
			 * 				rx_sliced:1,
			 *      // Word4
			 * 				l2_frame_type:4,   // 19:16 RX only: 0 = ETH, 1 = 802.3, 3 = WIFI
			 * 				vlan_count:2,      // 21:20
			 * 				mpls_count:3,      // 24:22
			 * 				l3_frame_type:3,   // 27:25
			 * 				l4_frame_type:4,   // 45:42
			 * 				l3_size:7,         // 41:35 (in units of 32 bits)
			 * 				l4_size:4,         // 57:54 (in units of 32 bits)
			 * 				frame_flags:5
			 * ;
			 * }
			 * }
			 */
			structLayout(
					JAVA_LONG.withName("timestamp_descr"), // type == 1, len == 0
					JAVA_INT.withName("caplen"),
					JAVA_INT.withName("wirelen")

			).withName("type1_descr"),

			/**
			 * {@snippet lang = c:
			 * struct {
			 * 		int64	timestamp:56,
			 * 				descr_type:4, // 16 descr types (0 == PCAP)
			 * 				descr_len:4;  // 16-bytes * (descr_len + 1)
			 * 		int32	length; // MSB bit == 1, orig length present, otherwise all caplen
			 * 		int32	l2_frame_type:2,
			 * 				l3_offset:7,
			 * 				l3_size,
			 * }
			 * }
			 */
			structLayout(
					JAVA_LONG.withName("timestamp"),
					JAVA_SHORT.withName("caplen"),
					JAVA_SHORT.withName("rx_flags"),
					JAVA_SHORT.withName("wirelen"),
					JAVA_SHORT.withName("tx_flags")

			).withName(""),

			structLayout(
					JAVA_LONG.withName("timestamp"),
					JAVA_SHORT.withName("caplen"),
					JAVA_SHORT.withName("rx_flags"),
					JAVA_SHORT.withName("wirelen"),
					JAVA_SHORT.withName("tx_flags"),

					JAVA_INT.withName("count"),
					JAVA_LONG.withName("bitmask"),
					sequenceLayout(MAX_RECORD_COUNT, JAVA_LONG).withName("records")

			));

	public static final MemoryLayout LAYOUT = LAYOUT$COMPACT;

	private static final VarHandle CAPLEN = LAYOUT.varHandle(groupElement("caplen"));
	private static final VarHandle WIRELEN = LAYOUT.varHandle(groupElement("wirelen"));
	private static final VarHandle BITMASK = LAYOUT.varHandle(groupElement("bitmask"));
	private static final VarHandle COUNT = LAYOUT.varHandle(groupElement("count"));
	private static final VarHandle RECORDS = LAYOUT.varHandle(groupElement("records"), sequenceElement());

	private final RecordCodec codec = new RecordCodec();

	public NetPacketDescriptor() {
		super(LAYOUT);
	}

	public long bitmask() {
		return (long) BITMASK.get(asMemorySegment(), activeBytesStart());
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.HeaderAccessor#hasHeader(com.slytechs.jnet.protocol.api.Header)
	 */
	@Override
	public boolean hasHeader(Header header) {
		return (bitmask() & (header.getProtocolId() % 64)) != 0;
	}

	@Override
	public int captureLength() {
		return (short) CAPLEN.get(asMemorySegment(), activeBytesStart());
	}

	public int count() {
		return (int) COUNT.get(asMemorySegment(), activeBytesStart());
	}

	public RecordCodec decodecRecordAt(int index) {
		long rec = recordAt(index);
		codec.decode(rec);

		return codec;
	}

	@Override
	public StructFormat format(StructFormat p) {
		int count = count();
		p = p.openln("QuickPacketDescriptor")
				.println("caplen", captureLength())
				.println("wirelen", wireLength())
				.println("count", count)
				.println("bitmask", "0x" + Long.toHexString(bitmask()))
				.printIndent()
				.openln("records[" + count() + "]");

		for (int i = 0; i < count; i++)
			p.println("record[%d]".formatted(i), decodecRecordAt(i));

		return p.closeln()
				.close();
	}

	public long recordAt(int index) {
		return (long) RECORDS.get(asMemorySegment(), activeBytesStart(), index);
	}

	public void setBitmask(long bitmask) {
		BITMASK.set(asMemorySegment(), activeBytesStart(), bitmask);
	}

	@Override
	public void setCaptureLength(int length) {
		CAPLEN.set(asMemorySegment(), activeBytesStart(), (short) (length & 0xFFFF));
	}

	public void setCount(int count) {
		COUNT.set(asMemorySegment(), activeBytesStart(), count);
	}

	public int setRecordAt(int index, int id, int offset, int length) {

		codec.id = id;
		codec.offset = offset;
		codec.size = length;

		long rec = codec.encode();
		setRecordAt(index, rec);

		return length;
	}

	public void setRecordAt(int index, long value) {
		RECORDS.set(asMemorySegment(), activeBytesStart(), index, value);
	}

	@Override
	public void setWireLength(int length) {
		WIRELEN.set(asMemorySegment(), activeBytesStart(), (short) (length & 0xFFFF));
	}

	@Override
	public String toString() {
		return format(new StructFormat()).toString();
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#type()
	 */
	@Override
	public DescriptorType type() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	@Override
	public int wireLength() {
		return (short) WIRELEN.get(asMemorySegment(), activeBytesStart());
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#id()
	 */
	@Override
	public int id() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#length()
	 */
	@Override
	public int length() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#packetFlagBitmask()
	 */
	@Override
	public long packetFlagBitmask() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#l2Offset()
	 */
	@Override
	public int l2Offset() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#l3Offset()
	 */
	@Override
	public int l3Offset() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#l4Offset()
	 */
	@Override
	public int l4Offset() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#l2Lenght()
	 */
	@Override
	public int l2Lenght() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#l3Length()
	 */
	@Override
	public int l3Length() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#l4Length()
	 */
	@Override
	public int l4Length() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#l2OffsetOuter()
	 */
	@Override
	public int l2OffsetOuter() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#l3OffsetOuter()
	 */
	@Override
	public int l3OffsetOuter() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#l2LengthOuter()
	 */
	@Override
	public int l2LengthOuter() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#l3LengthOuter()
	 */
	@Override
	public int l3LengthOuter() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#tsoSegmentSize()
	 */
	@Override
	public int tsoSegmentSize() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#hash()
	 */
	@Override
	public long hash() {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
