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
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class Type1Descriptor extends MemoryStructureProxy
		implements TxPacketDescriptor, RxPacketDescriptor, StructFormattable {

	public static final int MAX_RECORD_COUNT = 64;

	public static final MemoryLayout LAYOUT = MemoryLayout.structLayout(
			JAVA_LONG.withName("timestamp"),
			JAVA_SHORT.withName("caplen"),
			JAVA_SHORT.withName("rx_flags"),
			JAVA_SHORT.withName("wirelen"),
			JAVA_SHORT.withName("tx_flags"),

			JAVA_INT.withName("count"),
			JAVA_LONG.withName("bitmask"),
			sequenceLayout(MAX_RECORD_COUNT, JAVA_LONG).withName("records")

	);

	private static final VarHandle CAPLEN = LAYOUT.varHandle(groupElement("caplen"));
	private static final VarHandle WIRELEN = LAYOUT.varHandle(groupElement("wirelen"));
	private static final VarHandle BITMASK = LAYOUT.varHandle(groupElement("bitmask"));
	private static final VarHandle COUNT = LAYOUT.varHandle(groupElement("count"));
	private static final VarHandle RECORDS = LAYOUT.varHandle(groupElement("records"), sequenceElement());

	private final RecordCodec codec = new RecordCodec();

	public Type1Descriptor() {
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

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#isTxEnabled()
	 */
	@Override
	public boolean isTxEnabled() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#setTxEnabled(boolean)
	 */
	@Override
	public void setTxEnabled(boolean enabled) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#isTxImmediate()
	 */
	@Override
	public boolean isTxImmediate() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#setTxImmediate(boolean)
	 */
	@Override
	public void setTxImmediate(boolean immediate) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#isTxSyncTimestamp()
	 */
	@Override
	public boolean isTxSyncTimestamp() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#setTxSyncTimestamp(boolean)
	 */
	@Override
	public void setTxSyncTimestamp(boolean sync) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#txTimestamp()
	 */
	@Override
	public long txTimestamp() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#setTxTimestamp(long)
	 */
	@Override
	public void setTxTimestamp(long timestamp) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#txPort()
	 */
	@Override
	public int txPort() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#setTxPort(int)
	 */
	@Override
	public void setTxPort(int port) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#txOffsetInjection()
	 */
	@Override
	public int txOffsetInjection() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#setTxOffsetInjection(int)
	 */
	@Override
	public void setTxOffsetInjection(int offset) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#txIpChecksumAtOffset()
	 */
	@Override
	public int txIpChecksumAtOffset() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#setTxIpChecksumAtOffset(int)
	 */
	@Override
	public void setTxIpChecksumAtOffset(int offset) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#txL4ChecksumAtOffset()
	 */
	@Override
	public int txL4ChecksumAtOffset() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.TxPacketDescriptor#setTxL4ChecksumAtOffset(int)
	 */
	@Override
	public void setTxL4ChecksumAtOffset(int offset) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.RxPacketDescriptor#isIpChecksumGood()
	 */
	@Override
	public boolean isIpChecksumGood() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.RxPacketDescriptor#isL4ChecksumGood()
	 */
	@Override
	public boolean isL4ChecksumGood() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.RxPacketDescriptor#timestamp()
	 */
	@Override
	public long timestamp() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.RxPacketDescriptor#isFcsPresent()
	 */
	@Override
	public boolean isFcsPresent() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.RxPacketDescriptor#rxPort()
	 */
	@Override
	public int rxPort() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.RxPacketDescriptor#setRxPort(int)
	 */
	@Override
	public void setRxPort(int portNumber) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#l2Length()
	 */
	@Override
	public int l2Length() {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
