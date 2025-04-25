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
package com.slytechs.jnet.protocol.api.common;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

import com.slytechs.jnet.platform.api.common.binding.MemoryBinding;
import com.slytechs.jnet.platform.api.util.HexStrings;
import com.slytechs.jnet.platform.api.util.ToHexdump;
import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.platform.api.util.format.Stringable;
import com.slytechs.jnet.platform.api.util.time.HasTimestamp;
import com.slytechs.jnet.platform.api.util.time.Timestamp;
import com.slytechs.jnet.platform.api.util.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.core.CoreId;
import com.slytechs.jnet.protocol.api.core.PacketDescriptorType;
import com.slytechs.jnet.protocol.api.descriptor.Descriptor;
import com.slytechs.jnet.protocol.api.descriptor.DescriptorType;
import com.slytechs.jnet.protocol.api.descriptor.HeaderDescriptor;
import com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor;
import com.slytechs.jnet.protocol.api.descriptor.Type2Descriptor;
import com.slytechs.jnet.protocol.api.descriptor.impl.CompactDescriptor;
import com.slytechs.jnet.protocol.api.meta.Meta;
import com.slytechs.jnet.protocol.api.meta.Meta.MetaType;
import com.slytechs.jnet.protocol.api.meta.MetaResource;
import com.slytechs.jnet.protocol.api.meta.PacketFormat;
import com.slytechs.jnet.protocol.api.pack.PackId;

/**
 * Main packet class which encapsulates raw packet data and retains reference to
 * descriptor information. A packet is designed to work with certain packet
 * descriptors which allow this packet object to perform protocol header lookups
 * for different headers
 * 
 * <p>
 * Descriptors held by this packet, are daisy chained for very efficient
 * insertion of new descriptors. Descriptors are a way network hardware and low
 * level libraries provide information about network packets. For example, when
 * IP fragment reassembly or tracking is enabled, additional IPF related
 * descriptors are attached to header packet.
 * </p>
 *
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
@MetaResource("packet-meta.json")
public final class Packet
		extends MemoryBinding
		implements HasHeader, Cloneable, Stringable, ToHexdump, HasTimestamp {

	/** The Constant MAX_PACKET_LENGTH. */
	public static final int MAX_PACKET_LENGTH = 1538;

	/** The descriptor. */
	private PacketDescriptor descriptor;

	/** The lookup. */
	private final HeaderLookup lookup;

	/** The formatter. */
	private PacketFormat formatter;

	/**
	 * Instantiates a new packet.
	 */
	public Packet() {
		this(new Type2Descriptor());
	}

	/**
	 * Instantiates a new packet.
	 *
	 * @param packet the packet
	 */
	public Packet(ByteBuffer packet) {
		this(new Type2Descriptor());

		bind(packet);
	}

	/**
	 * Instantiates a new packet.
	 *
	 * @param packet     the packet
	 * @param descriptor the descriptor.
	 */
	public Packet(ByteBuffer packet, PacketDescriptor descriptor) {
		this(descriptor);

		bind(packet);
	}

	/**
	 * Instantiates a new packet.
	 *
	 * @param packet the packet
	 * @param type   the type
	 */
	public Packet(ByteBuffer packet, PacketDescriptorType type) {
		this(type);

		bind(packet);
	}

	/**
	 * Instantiates a new packet with a specific descriptor.
	 *
	 * @param descriptor the descriptor
	 */
	public Packet(PacketDescriptor descriptor) {
		this.descriptor = descriptor;
		this.lookup = descriptor;
	}

	/**
	 * Instantiates a new packet with a specific descriptor.
	 *
	 * @param type the type
	 */
	public Packet(PacketDescriptorType type) {
		this.descriptor = type.newDescriptor();
		this.lookup = descriptor;
	}

	/**
	 * Bind frame header.
	 *
	 * @param frame the frame
	 */
	private void bindFrameHeader(Frame frame) {
		var hd = frame.getHeaderDescriptor();
		hd.assign(CoreId.CORE_ID_FRAME, 0, 0, captureLength(), descriptor.type());

		bindHeader(frame);
		frame.bindDescriptor(descriptor);
	}

	private <T extends Header> boolean bindHeader(T header) {
		ByteBuffer buffer = buffer();

		header.bindHeaderToPacket(buffer, descriptor);
		header.bindOptionsToPacket(buffer, descriptor);

		header.setFormatter(formatter);

		return true;
	}

	/**
	 * Bind payload header.
	 *
	 * @param payload the payload
	 */
	private void bindPayloadHeader(Payload payload) {
		var headers = lookup.listHeaders();

		if (headers.length == 0) {
			var hd = payload.getHeaderDescriptor();
			hd.assign(CoreId.CORE_ID_PAYLOAD, 0, 0, captureLength(), descriptor.type());

			bindHeader(payload);

		} else {

			var lastHeader = headers[headers.length - 1];
			int offset = PackId.decodeRecordOffset(lastHeader)
					+ PackId.decodeRecordSize(lastHeader);
			int length = captureLength() - offset;

			var hd = payload.getHeaderDescriptor();
			hd.assign(CoreId.CORE_ID_PAYLOAD, 0, offset, length, descriptor.type());

			bindHeader(payload);
		}
	}

	/**
	 * Capture length.
	 *
	 * @return the int
	 */
	@Meta(MetaType.ATTRIBUTE)
	public int captureLength() {
		return descriptor.captureLength();
	}

	/**
	 * Clone.
	 *
	 * @return the packet
	 * @see com.slytechs.jnet.platform.api.common.binding.jnetruntime.MemoryBinding#clone()
	 */
	@Override
	public Packet clone() {
		Packet clone = (Packet) super.clone();

		return clone;
	}

	/**
	 * Clone to.
	 *
	 * @param dst the dst
	 * @return the packet
	 */
	@Override
	public Packet cloneTo(ByteBuffer dst) {
		PacketDescriptor cloneDsc = (PacketDescriptor) descriptor.cloneTo(dst);
		Packet clone = (Packet) super.cloneTo(dst);
		clone.descriptor = cloneDsc;

		return clone;
	}

	/**
	 * Close.
	 *
	 * @see java.lang.AutoCloseable#close()
	 */
	public void close() {
		unbind();
	}

	/**
	 * Descriptor.
	 *
	 * @param <D> the generic type
	 * @return the d
	 */
	@SuppressWarnings("unchecked")
	public <D extends PacketDescriptor> D descriptor() {
		return (D) descriptor;
	}

	/**
	 * Descriptor.
	 *
	 * @param <D>  the generic type
	 * @param type the descriptor type
	 * @return the d
	 */
	@SuppressWarnings("unchecked")
	public <D extends Descriptor> D descriptor(DescriptorType<?> type) {
		return (D) descriptor.peekDescriptor(type);
	}

	/**
	 * Gets the header.
	 *
	 * @param <T>    the generic type
	 * @param header the header
	 * @param depth  the depth
	 * @return the header
	 * @throws HeaderNotFound the header not found
	 * @see com.slytechs.jnet.protocol.api.common.HasHeader#getHeader(com.slytechs.jnet.protocol.api.common.Header)
	 */
	@Override
	public <T extends Header> T getHeader(T header, int depth) throws HeaderNotFound {
		T newHeader = peekHeader(header, depth);
		if (newHeader == null)
			throw new HeaderNotFound(header.headerName());

		return newHeader;
	}

	/**
	 * Checks for header.
	 *
	 * @param headerId the header id
	 * @param depth    the depth
	 * @return true, if successful
	 */
	@Override
	public final boolean hasHeader(int headerId, int depth) {
		return lookupHeader(headerId, depth, HeaderDescriptor.EMPTY);
	}

	/**
	 * Checks if any payload data is available or if all of the packet bytes are
	 * consumed by known headers. Payload starts on the next byte passed the last
	 * header and ends at packet length.
	 *
	 * @return true, if successful
	 */
	public boolean hasPayload() {
		return payloadLength() > 0;
	}

	/**
	 * Checks if the packet is truncated. If {@code caplen < wirelen} there were
	 * fewer bytes captured than there were original seen on the network.
	 *
	 * @return true, if is truncated
	 */
	public boolean isTruncated() {
		return descriptor.captureLength() < descriptor.wireLength();
	}

	/**
	 * Lookup header.
	 *
	 * @param id    the id
	 * @param depth the depth
	 * @return the long
	 */
	private final boolean lookupHeader(int id, int depth, HeaderDescriptor headerDescriptor) {
		return lookup.lookupHeader(id, 0, headerDescriptor);
	}

	/**
	 * Payload length.
	 *
	 * @return the int
	 */
	public int payloadLength() {
		var headers = lookup.listHeaders();

		if (headers.length == 0)
			return captureLength();

		var lastHeader = headers[headers.length - 1];
		int offset = CompactDescriptor.decodeOffset(lastHeader)
				+ CompactDescriptor.decodeLength(lastHeader);
		int length = captureLength() - offset;

		return length;
	}

	/**
	 * Peek header.
	 *
	 * @param <T>    the generic type
	 * @param header the header
	 * @param depth  the depth
	 * @return the t
	 * @see com.slytechs.jnet.protocol.api.common.HasHeader#peekHeader(com.slytechs.jnet.protocol.api.common.Header,
	 *      int)
	 */
	@Override
	public <T extends Header> T peekHeader(T header, int depth) {
		Objects.requireNonNull(header, "header"); // User error

		try {
			header.unbind();

			int id = header.id();

			if ((id == CoreId.CORE_ID_FRAME) && (header instanceof Frame frame)) {
				bindFrameHeader(frame);

			} else if (id == CoreId.CORE_ID_PAYLOAD && (header instanceof Payload payload)) {
				bindPayloadHeader(payload);

			} else if (lookupHeader(id, depth, header.getHeaderDescriptor()))
				bindHeader(header); // HeaderDescriptor is filled in
			else
				return null;

			return header;

			/*
			 * Any exceptions inside here are illegal and a bug. The code inside is designed
			 * to handle all errors without throwing ANY exceptions.
			 */
		} catch (Throwable e) {
			throw new IllegalStateException("Unexpected error in %s"
					.formatted(toString(Detail.MEDIUM, null)), e);
		}
	}

	/**
	 * Sets the descriptor.
	 *
	 * @param descriptor the descriptor
	 * @return the packet
	 */
	public Packet setDescriptor(PacketDescriptor descriptor) {
		this.descriptor = descriptor;

		return this;
	}

	/**
	 * Sets the formatter.
	 *
	 * @param formatter the new formatter
	 */
	public void setFormatter(PacketFormat formatter) {
		this.formatter = formatter;
	}

	/**
	 * Gets the currently assigned packet formatter.
	 *
	 * @return the formatter if assigned, otherwise null
	 */
	public PacketFormat getFormatter() {
		return this.formatter;
	}

	/**
	 * Timestamp.
	 *
	 * @return the long
	 */
	@Override
	public final long timestamp() {
		return descriptor.timestamp();
	}

	/**
	 * Timestamp unit.
	 *
	 * @return the timestamp unit
	 */
	@Override
	public final TimestampUnit timestampUnit() {
		return descriptor.timestampUnit();
	}

	/**
	 * To string.
	 *
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return toString(Detail.HIGH, formatter);
	}

	/**
	 * To string.
	 *
	 * @param detail the detail
	 * @return the string
	 */
	@Override
	public String toString(Detail detail) {
		return toString(detail, formatter);
	}

	/**
	 * To string.
	 *
	 * @param detail    the detail
	 * @param formatter the formatter
	 * @return the string
	 */
	public String toString(Detail detail, PacketFormat formatter) {
		if (formatter != null)
			return formatter.format(this, detail);

		String ifWirelenIsDifferent = (captureLength() != wireLength())
				? "/%d".formatted(wireLength())
				: "";

		return switch (detail) {
		case SUMMARY -> "Packet [#%2d: length=%4d%s, timestamp=%s]"
				.formatted(
						descriptor().frameNo(),
						captureLength(),
						ifWirelenIsDifferent,
						new Timestamp(timestamp(), timestampUnit()));

		case MEDIUM -> "Packet [#%2d: length=%4d, wireLength=%4d, timestamp=%s]"
				.formatted(
						descriptor().frameNo(),
						captureLength(),
						wireLength(),
						new Timestamp(timestamp(), timestampUnit()));

		case HIGH -> "Packet [#%2d: length=%4d, wireLength=%4d, timestamp=%s%n%s]"
				.formatted(
						descriptor().frameNo(),
						captureLength(),
						wireLength(),
						new Timestamp(timestamp(), timestampUnit()),
						HexStrings.toHexTextDump(buffer().slice(0, 16)));

		case DEBUG -> "Packet [#%d: length=%4d, wireLength=%4d, %s]"
				.formatted(
						descriptor().frameNo(),
						captureLength(),
						wireLength(),
						Arrays.asList(descriptor.toDescriptorArray())
//						descriptor.peekDescriptor(IpfDescriptorType.IPF_FRAG)

			);
		case OFF -> "";
		default -> throw new IllegalArgumentException("Unexpected value: " + detail);
		};
	}

	/**
	 * Wire length.
	 *
	 * @return the int
	 */
	public int wireLength() {
		return descriptor.wireLength();
	}

	/**
	 * @see com.slytechs.jnet.platform.api.util.format.Printable#printTo(java.lang.Appendable,
	 *      com.slytechs.jnet.platform.api.util.format.Detail)
	 */
	@Override
	public void printTo(Appendable out, Detail detail) throws IOException {
		if (formatter != null) {
			var sb = new StringBuilder();

			formatter.formatPacket(this, sb, detail);
			out.append(sb.toString());

			return;
		}

		String ifWirelenIsDifferent = (captureLength() != wireLength())
				? "/%d".formatted(wireLength())
				: "";

		String str = switch (detail) {
		case SUMMARY -> "Packet [#%2d: length=%4d%s, timestamp=%s]"
				.formatted(
						descriptor().frameNo(),
						captureLength(),
						ifWirelenIsDifferent,
						new Timestamp(timestamp(), timestampUnit()));

		case MEDIUM -> "Packet [#%2d: length=%4d, wireLength=%4d, timestamp=%s]"
				.formatted(
						descriptor().frameNo(),
						captureLength(),
						wireLength(),
						new Timestamp(timestamp(), timestampUnit()));

		case HIGH -> "Packet [#%2d: length=%4d, wireLength=%4d, timestamp=%s%n%s]"
				.formatted(
						descriptor().frameNo(),
						captureLength(),
						wireLength(),
						new Timestamp(timestamp(), timestampUnit()),
						HexStrings.toHexTextDump(buffer().slice(0, 16)));

		case DEBUG -> "Packet [#%d: length=%4d, wireLength=%4d, %s]"
				.formatted(
						descriptor().frameNo(),
						captureLength(),
						wireLength(),
						Arrays.asList(descriptor.toDescriptorArray())
//						descriptor.peekDescriptor(IpfDescriptorType.IPF_FRAG)

			);
		case OFF -> "";
		default -> throw new IllegalArgumentException("Unexpected value: " + detail);
		};

		out.append(str);
	}

}
