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
package com.slytechs.jnet.protocol.tcpip.ethernet;

import java.nio.ByteBuffer;

import com.slytechs.jnet.platform.api.util.HexStrings;
import com.slytechs.jnet.platform.api.util.hash.Checksums;
import com.slytechs.jnet.protocol.api.common.Header;
import com.slytechs.jnet.protocol.api.core.CoreId;
import com.slytechs.jnet.protocol.api.descriptor.DescriptorConstants;
import com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor;
import com.slytechs.jnet.protocol.api.meta.Meta;
import com.slytechs.jnet.protocol.api.meta.Meta.MetaType;
import com.slytechs.jnet.protocol.api.meta.MetaResource;

/**
 * Ethernet II protocol header.
 * 
 * <p>
 * The IEEE 802.3 standard defines the fundamental frame format that is
 * necessary for all MAC implementations. However, several optional formats are
 * also used to expand the protocol's basic capabilities. An Ethernet frame
 * begins with the Preamble and SFD, which operate at the physical layer.
 * Following this, the Ethernet header includes both the Source and Destination
 * MAC addresses, after which the frame payload is located. Finally, the CRC
 * field is included to detect errors. We will now examine each field of the
 * basic frame format in detail.
 * </p>
 *
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
@MetaResource("ethernet-meta.json")
public final class Ethernet extends Header {

	/** Core protocol pack assigned header ID. */
	public static final int ID = CoreId.CORE_ID_ETHER;

	/** The Constant ETHER_FIELD_DST_MASK64. */
	private static final long ETHER_FIELD_DST_MASK64 = 0xFFFF_FFFFFFFFl;

	/** The Constant ETHER_FIELD_SRC_MASK64. */
	private static final long ETHER_FIELD_SRC_MASK64 = 0xFFFF_FFFFFFFFl;

	/**
	 * A flag which specifies if CRC field at the end of EtherII frame has been
	 * captured. Depends on capture configuration and hardware used.
	 */
	private boolean crcFlag;

	/**
	 * A flag which specifies if preamble preceding the EtherII frame has been
	 * captured. Depends on capture configuration and hardware used.
	 */
	private boolean preambleFlag;

	/**
	 * The ethernet frame buffer spanning all of ethernet data (preamble + header +
	 * data + CRC).
	 */
	private ByteBuffer frameBuffer;

	/**
	 * A flag which indicates if caplen < wirelen or packet was truncated and not
	 * all data captured.
	 */
	private boolean isTruncated;

	/**
	 * Instantiates a new ethernet header.
	 */
	public Ethernet() {
		super(ID);
	}

	/**
	 * Recalculate payload length based on dissector flags which indicates if
	 * preamble or CRC fields are present.
	 *
	 * @param packet     the packet
	 * @param descriptor the descriptor
	 * @param offset     the offset
	 * @param length     the length
	 * @return the int
	 * @see com.slytechs.jnet.protocol.api.common.Header#calcPayloadLength(java.nio.ByteBuffer,
	 *      com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor, int, int)
	 */
	@Override
	protected int calcPayloadLength(ByteBuffer packet, PacketDescriptor descriptor, int offset, int length) {
		int captureLength = descriptor.captureLength();
		int wireLength = descriptor.wireLength();
		this.isTruncated = (captureLength < wireLength);

		int flags = descriptor.flags();
		this.preambleFlag = (flags & DescriptorConstants.DESC_PKT_FLAG_PREAMBLE) > 0;
		this.crcFlag = (flags & DescriptorConstants.DESC_PKT_FLAG_CRC) > 0 && !isTruncated;

		/*
		 * Preserve the frameBuffer so we can access these outside fields and/or used to
		 * recalculate this frames CRC
		 */
		frameBuffer = packet.slice();

		int payloadLength = captureLength - (offset + length);
		if (preambleFlag)
			payloadLength -= EtherConstants.ETHER_FIELD_LEN_PREAMBLE;

		if (crcFlag)
			payloadLength -= EtherConstants.ETHER_FIELD_LEN_CRC;

		return payloadLength;
	}

	/**
	 * Computes the frame's CRC value based on {@link #dst()}, {@link #src()},
	 * {@link #type()} and {@code Payload} data fields.
	 *
	 * @return the long
	 */
	public long computeFrameCrc() {
		if (isTruncated)
			return 0; // Do not have all of the data to make the calculation

		frameBuffer
				.clear()
				.limit(headerOffset() + headerLength() + payloadLength())
				.position(headerOffset());

		return Checksums.crc32(buffer());
	}

	/**
	 * CRC is 4 Byte field. This field contains a 32-bits hash code of data, which
	 * is generated over the Destination Address, Source Address, Length, and Data
	 * field. If the checksum computed by destination is not the same as sent
	 * checksum value, data received is corrupted.
	 *
	 * @return the unsinged 32-bit CRC field value if captured, otherwise a 0
	 */
	public long crc() {
		if (!isCrcPresent())
			return 0;

		return Integer.toUnsignedLong(
				frameBuffer.getInt(payloadLength()));
	}

	/**
	 * This is a 6-Byte field that contains the MAC address of the machine for which
	 * data is destined. The method allocates a new array to store the Mac address.
	 *
	 * @return MAC address
	 * @see HexStrings#toMacString(byte[])
	 */
	@Meta(offset = 0, length = 6)
	public byte[] dst() {
		return dst(new byte[EtherConstants.ETHER_FIELD_DST_LEN], 0);
	}

	/**
	 * This is a 6-Byte field that contains the MAC address of the machine for which
	 * data is destined.
	 *
	 * @param dst the destination array where the MAC address will to written to
	 * @return MAC address
	 * @see HexStrings#toMacString(byte[])
	 */
	public byte[] dst(byte[] dst) {
		return dst(dst, 0);
	}

	/**
	 * This is a 6-Byte field that contains the MAC address of the machine for which
	 * data is destined.
	 *
	 * @param dst    the destination array where the MAC address will to written to
	 * @param offset the offset into the destination array for storing the MAC
	 *               address
	 * @return MAC address
	 * @see HexStrings#toMacString(byte[])
	 */
	public byte[] dst(byte[] dst, int offset) {
		buffer().get(EtherConstants.ETHER_FIELD_DST, dst, offset, EtherConstants.ETHER_FIELD_DST_LEN);

		return dst;
	}

	@Meta(MetaType.ATTRIBUTE)
	public long dstAsLong() {
		return MacAddress.getAsLong(0, buffer());
	}

	/**
	 * This is a 6-Byte field that contains the MAC address of the machine for which
	 * data is destined.
	 *
	 * @return MAC address model
	 */
	public MacAddress dstGetAsAddress() {
		return new MacAddress(dst());
	}

	/**
	 * This is a 6-Byte field that contains the MAC address of the machine for which
	 * data is destined.
	 *
	 * @return MAC address stored in the first 6 LSB bytes of the long primitive
	 */
	public int dstGetAsLong() {
		return buffer().getInt(EtherConstants.ETHER_FIELD_DST);
	}

	@Meta(value = MetaType.ATTRIBUTE, abbr = "g")
	public int dstGloballyUniqueAddress() {
		return buffer().get(0) >> 1;
	}

	@Meta(value = MetaType.ATTRIBUTE, abbr = "u")
	public int dstIndividualAddress() {
		return buffer().get(0) >> 0;
	}

	/**
	 * Checks if is crc field has been captured.
	 *
	 * @return true, if is crc present
	 */
	public boolean isCrcPresent() {
		return crcFlag;
	}

	@Meta(MetaType.ATTRIBUTE)
	public boolean isDstGBitSet() {
		return dstGloballyUniqueAddress() != 0;
	}

	@Meta(MetaType.ATTRIBUTE)
	public boolean isDstUBitSet() {
		return dstIndividualAddress() != 0;
	}

	/**
	 * Checks if is preamble data present. Most captures do not include preamble
	 * data, which is a specific pattern of bits as specified part of IEEE Ethernet
	 * specification. However some hardware does and when set, the preamble is
	 * included as part of the packet and ethernet header start after the preable.
	 *
	 * @return true, if is preamble present
	 */
	public boolean isPreamblePresent() {
		return preambleFlag;
	}

	/**
	 * On unbind.
	 *
	 * @see com.slytechs.jnet.protocol.api.common.Header#onUnbind()
	 */
	@Override
	protected void onUnbind() {
		frameBuffer = null;
	}

	/**
	 * Ethernet frame starts with a 7-Bytes Preamble.
	 *
	 * @return the array containing preamble values or null if preamble was not
	 *         captured
	 */
	public byte[] preamble() {
		return preamble(new byte[EtherConstants.ETHER_FIELD_LEN_PREAMBLE]);
	}

	/**
	 * Ethernet frame starts with a 7-Bytes Preamble.
	 *
	 * @param dst the array where to copy the preamble bytes to
	 * @return the array containing preamble values or null if preamble was not
	 *         captured
	 */
	public byte[] preamble(byte[] dst) {
		return preamble(dst, 0);
	}

	/**
	 * Ethernet frame starts with a 7-Bytes Preamble.
	 *
	 * @param dst    the array where to copy the preamble bytes to
	 * @param offset offset into the dst array
	 * @return the array containing preamble values or null if preamble was not
	 *         captured
	 */
	public byte[] preamble(byte[] dst, int offset) {
		if (!isPreamblePresent())
			return null;

		buffer().get(0, dst, EtherConstants.ETHER_FIELD_PREAMBLE, EtherConstants.ETHER_FIELD_LEN_PREAMBLE);

		return dst;
	}

	/**
	 * This is a 6-Byte field that contains the MAC address of the source machine.
	 * As Source Address is always an individual address (Unicast), the least
	 * significant bit of the first byte is always 0.
	 *
	 * @return MAC address
	 */
	@Meta(offset = 6, length = 6)
	public byte[] src() {
		return src(new byte[EtherConstants.ETHER_FIELD_SRC_LEN], 0);
	}

	/**
	 * This is a 6-Byte field that contains the MAC address of the source machine.
	 * As Source Address is always an individual address (Unicast), the least
	 * significant bit of the first byte is always 0.
	 *
	 * @param dst the destination array where the MAC address will to written to
	 * @return MAC address
	 */
	public byte[] src(byte[] dst) {
		return src(dst, 0);
	}

	/**
	 * This is a 6-Byte field that contains the MAC address of the source machine.
	 * As Source Address is always an individual address (Unicast), the least
	 * significant bit of the first byte is always 0.
	 *
	 * @param dst    the destination array where the MAC address will to written to
	 * @param offset the offset into the destination array for storing the MAC
	 *               address
	 * @return MAC address
	 */
	public byte[] src(byte[] dst, int offset) {
		buffer().get(EtherConstants.ETHER_FIELD_SRC, dst, offset, EtherConstants.ETHER_FIELD_SRC_LEN);

		return dst;
	}

	@Meta(MetaType.ATTRIBUTE)
	public long srcAsLong() {
		return MacAddress.getAsLong(6, buffer());
	}

	/**
	 * This is a 6-Byte field that contains the MAC address of the source machine.
	 * As Source Address is always an individual address (Unicast), the least
	 * significant bit of the first byte is always 0.
	 *
	 * @return MAC address stored in the first 6 LSB bytes of the long primitive
	 */
	public long srcGetAsLong() {
		return buffer().getLong(EtherConstants.ETHER_FIELD_SRC) & ETHER_FIELD_SRC_MASK64;
	}

	/**
	 * This is a 6-Byte field that contains the MAC address of the source machine.
	 * As Source Address is always an individual address (Unicast), the least
	 * significant bit of the first byte is always 0.
	 *
	 * @return MAC address model
	 */
	public MacAddress srcGetAsMacAddress() {
		return new MacAddress(src());
	}

	/**
	 * The EtherType field in the Ethernet frame header identifies the protocol
	 * carried in the payload of the frame. For example, a value of 0x0800 indicates
	 * that the payload is an IP packet, while a value of 0x0806 indicates that the
	 * payload is an ARP (Address Resolution Protocol) packet. .
	 *
	 * @return ether type constant
	 */
	@Meta(formatter = Meta.Formatter.HEX_LOWERCASE_0x, offset = 12, length = 2)
	public int type() {
		return Short.toUnsignedInt(buffer().getShort(EtherConstants.ETHER_FIELD_TYPE));
	}

	/**
	 * The EtherType field in the Ethernet frame header identifies the protocol
	 * carried in the payload of the frame. For example, a value of 0x0800 indicates
	 * that the payload is an IP packet, while a value of 0x0806 indicates that the
	 * payload is an ARP (Address Resolution Protocol) packet. .
	 *
	 * @return ether type enum constant
	 */
	public EtherType typeGetAsEtherType() {
		return EtherType.valueOfEtherType(type());
	}

}
