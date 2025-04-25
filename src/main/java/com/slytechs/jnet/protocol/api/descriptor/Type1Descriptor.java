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

import static com.slytechs.jnet.protocol.api.core.CoreId.*;
import static com.slytechs.jnet.protocol.api.core.L2FrameType.*;
import static com.slytechs.jnet.protocol.api.core.L3FrameType.*;
import static com.slytechs.jnet.protocol.api.core.L4FrameType.*;
import static com.slytechs.jnet.protocol.api.core.LayerConstants.*;
import static com.slytechs.jnet.protocol.api.descriptor.impl.Type1DescriptorLayout.*;

import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.platform.api.util.time.Timestamp;
import com.slytechs.jnet.protocol.api.core.L2FrameType;
import com.slytechs.jnet.protocol.api.core.L3FrameType;
import com.slytechs.jnet.protocol.api.core.L4FrameType;
import com.slytechs.jnet.protocol.api.core.PacketDescriptorType;
import com.slytechs.jnet.protocol.api.descriptor.impl.Type1DescriptorLayout;

/**
 * The Class Type1Descriptor.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 */
public class Type1Descriptor extends PacketDescriptor {

	/** Length in bytes of type1 descriptor. */
	public static final int LENGTH = DescriptorConstants.DESC_TYPE1_BYTE_SIZE;

	/**
	 * Instantiates a new type 1 descriptor.
	 */
	public Type1Descriptor() {
		super(PacketDescriptorType.TYPE1);
	}

	/**
	 * Checks if is header extension supported.
	 *
	 * @return true, if is header extension supported
	 * @see com.slytechs.jnet.protocol.api.common.HeaderLookup#isHeaderExtensionSupported()
	 */
	@Override
	public boolean isHeaderExtensionSupported() {
		return false;
	}

	/**
	 * List headers.
	 *
	 * @return the long[]
	 * @see com.slytechs.jnet.protocol.api.common.HeaderLookup#listHeaders()
	 */
	@Override
	public long[] listHeaders() {
		throw new UnsupportedOperationException("not implemented yet");
	}

	public int vlanCount() {
		return Type1DescriptorLayout.VLAN_COUNT.getInt(buffer());
	}

	public int mplsCount() {
		return Type1DescriptorLayout.MPLS_COUNT.getInt(buffer());
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.common.HeaderLookup#lookupHeader(int,
	 *      int, com.slytechs.jnet.protocol.api.descriptor.HeaderDescriptor)
	 */
	@Override
	public boolean lookupHeader(int id, int depth, HeaderDescriptor descriptor) {
		if (id == CORE_ID_VLAN) {
			if (depth < vlanCount()) {
				int offset = L2_HEADER_LEN_ETHER + depth * L2_HEADER_LEN_VLAN;

				return descriptor.assign(id, depth, offset, L2_HEADER_LEN_VLAN, type());
			}

			return false;
		}

		if (id == CORE_ID_MPLS) {
			if (depth < mplsCount()) {
				int offset = L2_HEADER_LEN_ETHER + depth * L2_HEADER_LEN_MPLS;

				return descriptor.assign(id, depth, offset, L2_HEADER_LEN_MPLS, type());
			}

			return false;
		}

		/*
		 * With Type1 besides VLAN and MPLS there is no depth
		 */
		if (depth != 0)
			return false;

		return switch (id) {

		case CORE_ID_ETHER -> l2(L2_FRAME_TYPE_ETHER, id, 0, L2_HEADER_LEN_ETHER, descriptor);
		case CORE_ID_LLC -> l2(L2_FRAME_TYPE_LLC, id, L2_HEADER_LEN_ETHER, L2_HEADER_LEN_LLC, descriptor);
		case CORE_ID_SNAP -> l2(L2_FRAME_TYPE_SNAP, id, L2_HEADER_LEN_ETHER + L2_HEADER_LEN_LLC,
				L2_HEADER_LEN_SNAP, descriptor);

		case CORE_ID_IPv4 -> l3(L3_FRAME_TYPE_IPv4, id, descriptor);
		case CORE_ID_IPv6 -> l3(L3_FRAME_TYPE_IPv6, id, descriptor);
		case CORE_ID_IPX -> l3(L3_FRAME_TYPE_IPX, id, descriptor);

		case CORE_ID_TCP -> l4(L4_FRAME_TYPE_TCP, id, descriptor);
		case CORE_ID_UDP -> l4(L4_FRAME_TYPE_UDP, id, descriptor);
		case CORE_ID_ICMPv4 -> l4(L4_FRAME_TYPE_ICMP, id, descriptor);
		case CORE_ID_GRE -> l4(L4_FRAME_TYPE_GRE, id, descriptor);
		case CORE_ID_SCTP -> l4(L4_FRAME_TYPE_SCTP, id, descriptor);

		default -> false;
		};
	}

	private boolean l4(int l4, int id, HeaderDescriptor descriptor) {
		if (l4 == l4FrameType())
			return descriptor.assign(id, 0, l4Offset(), l4SizeBytes(), type());

		return false;
	}

	private boolean l3(int l3, int id, HeaderDescriptor descriptor) {
		if (l3 == l3FrameType())
			return descriptor.assign(id, 0, l3Offset(), l3SizeBytes(), type());

		return false;
	}

	private boolean l2(int l2, int id, int offset, int length, HeaderDescriptor descriptor) {
		if (l2 == l2FrameType())
			return descriptor.assign(id, 0, offset, length, type());

		return false;
	}

	/**
	 * Byte size.
	 *
	 * @return the int
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#byteSize()
	 */
	@Override
	public int byteSize() {
		return LENGTH;
	}

	/**
	 * Timestamp.
	 *
	 * @return the long
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#timestamp()
	 */
	@Override
	public long timestamp() {
		return TIMESTAMP.getLong(buffer());
	}

	/**
	 * Capture length.
	 *
	 * @return the int
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#captureLength()
	 */
	@Override
	public int captureLength() {
		return Type1DescriptorLayout.CAPLEN.getUnsignedShort(buffer());
	}

	/**
	 * Wire length.
	 *
	 * @return the int
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#wireLength()
	 */
	@Override
	public int wireLength() {
		return WIRELEN.getUnsignedShort(buffer());
	}

	@Override
	public int l2FrameType() {
		return L2_FRAME_TYPE.getUnsignedShort(buffer());
	}

	public L3FrameType l3FrameTypeAsContant() {
		return L3FrameType.valueOfL3FrameType(l3FrameType());
	}

	public int l3FrameType() {
		return L3_FRAME_TYPE.getUnsignedShort(buffer());
	}

	public int l3Offset() {
		return L3_OFFSET.getUnsignedShort(buffer());
	}

	public int l3Size() {
		return L3_SIZE.getUnsignedShort(buffer());
	}

	public int l3SizeBytes() {
		return l3Size() << 2;
	}

	public int l4FrameType() {
		return L4_FRAME_TYPE.getUnsignedShort(buffer());
	}

	public int l4Offset() {
		return l3Offset() + l3SizeBytes();
	}

	public int l4Size() {
		return L4_SIZE.getUnsignedShort(buffer());
	}

	public int l4SizeBytes() {
		return l4Size() << 2;
	}

	/**
	 * Builds the detailed string.
	 *
	 * @param toAppendTo the b
	 * @param detail     the detail
	 * @return the string builder
	 * @see com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor#buildDetailedString(java.lang.StringBuilder,
	 *      com.slytechs.jnet.platform.api.util.format.jnetruntime.util.Detail)
	 */
	@Override
	protected StringBuilder buildDetailedString(StringBuilder toAppendTo, Detail detail) {
		if (detail == Detail.SUMMARY) {
			toAppendTo
					.append("cap=%d".formatted(captureLength()))
					.append(", ts=\"%s\"%n".formatted(new Timestamp(timestamp(), timestampUnit())));

		} else if (detail == Detail.MEDIUM) {
			toAppendTo
					.append("cap=%d".formatted(captureLength()))
					.append(", wire=%d".formatted(wireLength()))
					.append(", l3=%s".formatted(L3FrameType.valueOfL3FrameType(l3FrameType())))
					.append(", ts=\"%s\"%n".formatted(new Timestamp(timestamp(), timestampUnit())));

		} else { // Detail.HIGH
			toAppendTo
					.append("  timestap=\"%s\"%n".formatted(new Timestamp(timestamp(), timestampUnit())))

					.append("  captureLength=%d%n".formatted(captureLength()))
					.append("  l2FrameType=%d (%s)%n".formatted(l2FrameType(), L2FrameType.valueOfL2FrameType(
							l2FrameType())))
					.append("  l3Offset=%d%n".formatted(l3Offset()))
					.append("  l3Size=%d (%d*4=%d)%n".formatted(l3Size(), l3Size(), l3SizeBytes()))

					.append("  wireLength=%d%n".formatted(wireLength()))
					.append("  vlanCount=%d%n".formatted(vlanCount()))
					.append("  mplsCount=%d%n".formatted(mplsCount()))
					.append("  l3FrameType=%d (%s)%n".formatted(l3FrameType(), L3FrameType.valueOfL3FrameType(
							l3FrameType())))
					.append("  l4FrameType=%d (%s)%n".formatted(l4FrameType(), L4FrameType.valueOfL4FrameType(
							l4FrameType())))
					.append("  l4Size=%d (%d*4=%d)%n".formatted(l4Size(), l4Size(), l4SizeBytes()));

		}

		return toAppendTo;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.common.HeaderLookup#lookupHeaderExtension(int,
	 *      int, int, int,
	 *      com.slytechs.jnet.protocol.api.descriptor.HeaderDescriptor)
	 */
	@Override
	public boolean lookupHeaderExtension(int headerId, int extId, int depth, int recordIndexHint,
			HeaderDescriptor descriptor) {
		return false;
	}

}
