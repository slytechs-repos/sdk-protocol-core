/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
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

import java.nio.ByteBuffer;

import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.platform.api.util.time.Timestamp;
import com.slytechs.jnet.platform.api.util.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.core.PacketDescriptorType;
import com.slytechs.jnet.protocol.api.descriptor.impl.PcapDescriptorLayout;

/**
 * The pcap packet header descriptor is a structure that is used to describe a
 * packet that has been captured by the pcap library.
 */
public final class PcapDescriptor extends PacketDescriptor {

	/** The Constant ID. */
	public static final int ID = PacketDescriptorType.DESCRIPTOR_TYPE_PCAP;

	/** The Constant PCAP_DESCRIPTOR_LENGTH. */
	public final static int PCAP_DESCRIPTOR_LENGTH = 24;

	/** The Constant EMPTY_HEADER_ARRAY. */
	private static final long[] EMPTY_HEADER_ARRAY = new long[0];

	/**
	 * Instantiates a new pcap descriptor.
	 */
	public PcapDescriptor() {
		super(PacketDescriptorType.PCAP);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#captureLength()
	 */
	@Override
	public int captureLength() {
		return PcapDescriptorLayout.CAPLEN.getUnsignedShort(buffer());
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.common.HeaderLookup#listHeaders()
	 */
	@Override
	public long[] listHeaders() {
		return EMPTY_HEADER_ARRAY;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#timestamp()
	 */
	@Override
	public long timestamp() {
		return PcapDescriptorLayout.TIMESTAMP.getLong(buffer());
	}

	/**
	 * Builds the detailed string.
	 *
	 * @param b      the b
	 * @param detail the detail
	 * @return the string builder
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#buildDetailedString(java.lang.StringBuilder,
	 *      com.slytechs.jnet.platform.api.util.format.jnetruntime.util.Detail)
	 */
	@Override
	public StringBuilder buildDetailedString(StringBuilder b, Detail detail) {
		new Timestamp(TimestampUnit.EPOCH_MILLI.convert(timestamp(), TimestampUnit.PCAP_MICRO))
				.buildString(b, detail);
		b.append(" caplen=");
		b.append(captureLength());
		b.append(" wirelen=");
		b.append(wireLength());

		return b;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#wireLength()
	 */
	@Override
	public int wireLength() {
		return PcapDescriptorLayout.WIRELEN.getUnsignedShort(buffer());
	}

	/**
	 * @see com.slytechs.jnet.platform.api.common.binding.jnetruntime.MemoryBinding#cloneTo(java.nio.ByteBuffer)
	 */
	@Override
	public PcapDescriptor cloneTo(ByteBuffer dst) {
		return (PcapDescriptor) super.cloneTo(dst);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.common.HeaderLookup#isHeaderExtensionSupported()
	 */
	@Override
	public boolean isHeaderExtensionSupported() {
		return false;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#byteSize()
	 */
	@Override
	public int byteSize() {
		return PCAP_DESCRIPTOR_LENGTH;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.common.HeaderLookup#lookupHeaderExtension(int, int,
	 *      int, int, com.slytechs.jnet.protocol.api.descriptor.HeaderDescriptor)
	 */
	@Override
	public boolean lookupHeaderExtension(int headerId, int extId, int depth, int recordIndexHint,
			HeaderDescriptor descriptor) {
		return false;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.common.HeaderLookup#lookupHeader(int, int,
	 *      com.slytechs.jnet.protocol.api.descriptor.HeaderDescriptor)
	 */
	@Override
	public boolean lookupHeader(int id, int depth, HeaderDescriptor descriptor) {
		return false;
	}

	public PcapDescriptor initDescriptor(long timestamp, int captureLength, int wireLength) {
		PcapDescriptorLayout.TIMESTAMP.setLong(timestamp, buffer());
		PcapDescriptorLayout.CAPLEN.setInt(captureLength, buffer());
		PcapDescriptorLayout.WIRELEN.setLong(wireLength, buffer());

		return this;
	}
}
