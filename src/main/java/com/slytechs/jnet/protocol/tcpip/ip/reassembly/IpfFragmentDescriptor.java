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
package com.slytechs.jnet.protocol.tcpip.ip.reassembly;

import static com.slytechs.jnet.protocol.api.descriptor.DescriptorConstants.*;

import java.nio.ByteBuffer;

import com.slytechs.jnet.platform.api.util.HexStrings;
import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.protocol.api.core.L3FrameType;
import com.slytechs.jnet.protocol.tcpip.ip.IpType;
import com.slytechs.jnet.protocol.tcpip.ip.impl.IpfFragmentLayout;

/**
 * Ip fragmentation descriptor. A fragmentation descriptor provides information
 * about tracking and reassembly of IP fragments.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class IpfFragmentDescriptor extends IpfDescriptor {

	/**
	 * Instantiates a new ipf descriptor.
	 */
	public IpfFragmentDescriptor() {
		super(IpfDescriptorType.IPF_FRAG);
	}

	/**
	 * Instantiates a new ipf fragment.
	 *
	 * @param descBuf the desc buf
	 */
	public IpfFragmentDescriptor(ByteBuffer descBuf) {
		super(IpfDescriptorType.IPF_FRAG);
		bind(descBuf);
	}

	/**
	 * Ip type.
	 *
	 * @return the int
	 */
	public int ipType() {
		return IpfFragmentLayout.IP_TYPE.getByte(buffer());
	}

	/**
	 * Ip type as L 3 frame type.
	 *
	 * @return the l 3 frame type
	 */
	public L3FrameType ipTypeAsL3FrameType() {
		return L3FrameType.valueOfL3FrameType(ipType());
	}

	/**
	 * Checks if is ip 4.
	 *
	 * @return true, if is ip 4
	 */
	public boolean isIp4() {
		return !IpfFragmentLayout.IP_TYPE.getBit(buffer());
	}

	/**
	 * Checks if is ip 6.
	 *
	 * @return true, if is ip 6
	 */
	public boolean isIp6() {
		return IpfFragmentLayout.IP_TYPE.getBit(buffer());
	}

	/**
	 * Checks if is frag.
	 *
	 * @return true, if is frag
	 */
	public boolean isFrag() {
		return IpfFragmentLayout.IP_IS_FRAG.getBit(buffer());
	}

	/**
	 * Checks if is last frag.
	 *
	 * @return true, if is last frag
	 */
	public boolean isLastFrag() {
		return IpfFragmentLayout.IP_IS_LAST.getBit(buffer());
	}

	/**
	 * Checks if this fragment is overlapping some portion of data that has already
	 * been seen or reassembled. Duplicate packets do not count toward this flag,
	 * because exact duplicates are tracked separately {@link #isDuplicate()}.
	 *
	 * @return true, if this fragment overlapped a previous one
	 */
	public boolean isOverlap() {
		return IpfFragmentLayout.IP_IS_OVERLAP.getBit(buffer());
	}

	/**
	 * Checks if this fragment is exact duplicate of another fragment that has
	 * already been seen or reassembled. Only exact fragment duplicates are recorded
	 * here as any previous fragments that overlap previously seen fragment data,
	 * but are not exactly of the same fragment offset and size, are tracked
	 * separately by {@link #isOverlap()} flag.
	 *
	 * @return true, if is duplicate
	 */
	public boolean isDuplicate() {
		return IpfFragmentLayout.IP_IS_OVERLAP.getBit(buffer());
	}

	/**
	 * Header offset.
	 *
	 * @return the int
	 */
	public int headerOffset() {
		return IpfFragmentLayout.IP_HDR_OFFSET.getByte(buffer());
	}

	/**
	 * Header and required options length.
	 *
	 * @return the int
	 */
	public int headerAndRequiredOptionsLength() {
		return IpfFragmentLayout.IP_HDR_LEN.getByte(buffer());
	}

	/**
	 * Next header.
	 *
	 * @return the int
	 */
	public int nextHeader() {
		return IpfFragmentLayout.IP_NEXT.getByte(buffer());
	}

	/**
	 * Next header as ip type.
	 *
	 * @return the ip type
	 */
	public IpType nextHeaderAsIpType() {
		return IpType.valueOfIpType(nextHeader());
	}

	/**
	 * Frag offset.
	 *
	 * @return the int
	 */
	public int fragOffset() {
		return IpfFragmentLayout.FIELD_FRAG_OFFSET.getUnsignedShort(buffer());
	}

	/**
	 * Identifier.
	 *
	 * @return the int
	 */
	public int identifier() {
		return IpfFragmentLayout.FIELD_IDENTIFIER.getUnsignedShort(buffer());
	}

	/**
	 * Data offset.
	 *
	 * @return the int
	 */
	public int dataOffset() {
		return IpfFragmentLayout.FRAG_DATA_OFFSET.getUnsignedShort(buffer());
	}

	/**
	 * Data length.
	 *
	 * @return the int
	 */
	public int dataLength() {
		return IpfFragmentLayout.FRAG_DATA_LEN.getUnsignedShort(buffer());
	}

	/**
	 * Ip src.
	 *
	 * @return the byte[]
	 */
	public byte[] ipSrc() {
		if (ipType() == L3FrameType.L3_FRAME_TYPE_IPv4)
			return IpfFragmentLayout.KEY_IPv4_SRC.getByteArray(buffer());
		else
			return IpfFragmentLayout.KEY_IPv6_SRC.getByteArray(buffer());
	}

	/**
	 * Ip src as string.
	 *
	 * @return the string
	 */
	public String ipSrcAsString() {
		return HexStrings.toIpString(ipSrc());
	}

	/**
	 * Ip dst.
	 *
	 * @return the byte[]
	 */
	public byte[] ipDst() {
		if (ipType() == L3FrameType.L3_FRAME_TYPE_IPv4)
			return IpfFragmentLayout.KEY_IPv4_DST.getByteArray(buffer());
		else
			return IpfFragmentLayout.KEY_IPv6_DST.getByteArray(buffer());
	}

	/**
	 * Key buffer.
	 *
	 * @return the byte buffer
	 */
	public ByteBuffer keyBuffer() {
		if (ipType() == L3FrameType.L3_FRAME_TYPE_IPv4)
			return buffer().slice(DESC_IPF_FRAG_KEY, DESC_IPF_FRAG_IPv4_KEY_BYTE_SIZE);
		else
			return buffer().slice(DESC_IPF_FRAG_KEY, DESC_IPF_FRAG_IPv6_KEY_BYTE_SIZE);
	}

	/**
	 * Ip dst as string.
	 *
	 * @return the string
	 */
	public String ipDstAsString() {
		return HexStrings.toIpString(ipDst());
	}

	/**
	 * Builds the detailed string.
	 *
	 * @param toAppendTo the b
	 * @param detail     the detail
	 * @return the string builder
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#buildDetailedString(java.lang.StringBuilder,
	 *      com.slytechs.jnet.platform.api.util.format.jnetruntime.util.Detail)
	 */
	@Override
	protected StringBuilder buildDetailedString(StringBuilder toAppendTo, Detail detail) {
		if (detail == Detail.SUMMARY) {
			toAppendTo
					.append("ipType=%s".formatted(ipTypeAsL3FrameType()))
					.append(" %5d-%-5d (%4d bytes)".formatted(
							fragOffset(),
							fragOffset() + dataLength() - 1,
							dataLength()));

		} else if (detail == Detail.MEDIUM) {
			toAppendTo
					.append("ipType=%s".formatted(ipTypeAsL3FrameType()));

		} else { // Detail.HIGH
			toAppendTo

					.append("  ipType=%s (%d)%n".formatted(ipTypeAsL3FrameType(), ipType()))
					.append("  isFrag=%s%n".formatted(isFrag()))
					.append("  isLastFrag=%s%n".formatted(isLastFrag()))
					.append("  headerOffset=%d%n".formatted(headerOffset()))
					.append("  headerLength=%d%n".formatted(headerAndRequiredOptionsLength()))
					.append("  fragOffset=%d%n".formatted(fragOffset()))
					.append("  dataOffset=%s%n".formatted(dataOffset()))
					.append("  dataLength=%s%n".formatted(dataLength()))
					.append("  key.identifier=%s%n".formatted(identifier()))
					.append("  key.nextHeader=%s (%d)%n".formatted(nextHeaderAsIpType(), nextHeader()))
					.append("  key.source=%s%n".formatted(ipSrcAsString()))
					.append("  key.destination=%s%n".formatted(ipDstAsString()))

			;

		}
		return toAppendTo;
	}
}
