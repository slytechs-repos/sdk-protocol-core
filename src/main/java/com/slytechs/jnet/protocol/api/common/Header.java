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
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import com.slytechs.jnet.platform.api.common.binding.MemoryBinding;
import com.slytechs.jnet.platform.api.util.HexStrings;
import com.slytechs.jnet.platform.api.util.ToHexdump;
import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.platform.api.util.format.Stringable;
import com.slytechs.jnet.protocol.api.descriptor.HeaderDescriptor;
import com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor;
import com.slytechs.jnet.protocol.api.meta.Meta;
import com.slytechs.jnet.protocol.api.meta.Meta.MetaType;
import com.slytechs.jnet.protocol.api.meta.PacketFormat;
import com.slytechs.jnet.protocol.api.pack.HasPackId;

/**
 * A "reusable" protocol header that can be bound and unbound to data in memory.
 *
 * @author Sly Technologies
 * @author repos@slytechs.com
 */
@Meta
public abstract class Header extends MemoryBinding implements Stringable, ToHexdump, HasPackId {

	private final HeaderDescriptor headerDescriptor = new HeaderDescriptor();

	/** The lock factory. */
	private static Supplier<Lock> LOCK_FACTORY = ReentrantLock::new;

	/** The numerical protocol header id assigned at "pack" level. */
	protected final int id;

	/** A multipurpose lock, lazily allocated if needed. */
	private volatile Lock lock; // Lazy & concurrent allocation

	/** Some important header attributes. */
	private int headerOffset, headerLength, payloadLength;

	/**
	 * A pretty pring formatted, if will be used to generated {@code toString()}
	 * output.
	 */
	private PacketFormat formatter;

	private PacketDescriptor descriptor;

	/**
	 * Instantiates a new header.
	 *
	 * @param id the id
	 */
	protected Header(int id) {
		this.id = id;
	}

	/**
	 * Instantiates a new header.
	 *
	 * @param id   the id
	 * @param lock the lock
	 */
	protected Header(int id, Lock lock) {
		this.id = id;
		this.lock = lock;
	}

	/**
	 * Bind header extensions and options, but only if HeaderExtension is a
	 * subclass, otherwise do nothing.
	 *
	 * @param packet     the source buffer or typically the buffer containing the
	 *                   source packet
	 * @param descriptor the extension header lookup
	 * @param meta       the meta data, such as descriptor/lookup specific data
	 *                   which aids in extension header lookup
	 */
	public void bindOptionsToPacket(ByteBuffer packet, PacketDescriptor descriptor) {
		// Do nothing by default
	}

	/**
	 * Gets the usable packet descriptor.
	 *
	 * @return the packet descriptor
	 */
	protected PacketDescriptor descriptor() {
		return descriptor;
	}

	/**
	 * Bind header to packet.
	 *
	 * @param packet     the packet
	 * @param descriptor TODO
	 * @param offset     the offset
	 * @param length     the length
	 */
	public final void bindHeaderToPacket(ByteBuffer packet, PacketDescriptor descriptor) {
		this.headerOffset = headerDescriptor.getOffset();
		this.headerLength = headerDescriptor.getLength();
		this.payloadLength = calcPayloadLength(packet, descriptor, this.headerOffset, this.headerLength);
		this.descriptor = descriptor;

		super.bind(packet.slice(this.headerOffset, this.headerLength));
	}

	public final void bindHeaderToPacket(ByteBuffer packet, PacketDescriptor descriptor, int offset, int length) {
		this.headerOffset = offset;
		this.headerLength = length;
		this.payloadLength = calcPayloadLength(packet, descriptor, offset, length);
		this.descriptor = descriptor;

		super.bind(packet.slice(offset, length));
	}

	/**
	 * Recalculates the protocol payload on a per header basis if needed.
	 *
	 * @param packet     the packet buffer
	 * @param descriptor the packet descriptor
	 * @param offset     the offset calculated by the dissector
	 * @param length     the length calculated by the dissector
	 * @return new protocol header payload length if different from dissector
	 *         calculated one
	 */
	protected int calcPayloadLength(ByteBuffer packet, PacketDescriptor descriptor, int offset, int length) {
		return descriptor.captureLength() - (offset + length);
	}

	/**
	 * Gets a header specific lock for synchronizing access to header fields. The
	 * lock is initialized lazily and only when requested, otherwise the lock field
	 * remains uninitialized.
	 *
	 * @return the lock
	 */
	public final Lock getLock() {
		if (this.lock == null) { // Lazy allocate
			Lock lock = LOCK_FACTORY.get(); // get on local thread context (allows multiple threads)

			while (this.lock == null) // No lock volatile initialization, only 1 thread wins
				this.lock = lock;
		}

		return this.lock;
	}

	/**
	 * The protocol header's unique numerical ID assigned at the pack level.
	 *
	 * @return the id
	 */
	@Override
	@Meta(MetaType.ATTRIBUTE)
	public final int id() {
		return id;
	}

	/**
	 * The header length.
	 *
	 * @return length in bytes
	 */
	@Meta(name = "length", value = MetaType.ATTRIBUTE)
	public final int headerLength() {
		return headerLength;
	}

	/**
	 * Name of this protocol header. If a specific header is not assigned, the
	 * method defaults to acquiring a name from the sub-class classname.
	 *
	 * @return the string
	 */
	@Meta(name = "name", value = MetaType.ATTRIBUTE)
	public String headerName() {
		return getClass().getSimpleName();
	}

	/**
	 * Offset of the beginning of this header from the start of the packet.
	 *
	 * @return offset in bytes
	 */
	@Meta(name = "offset", value = MetaType.ATTRIBUTE)
	public final int headerOffset() {
		return headerOffset;
	}

	/**
	 * On unbind.
	 *
	 * @see com.slytechs.jnet.platform.api.common.binding.jnetruntime.MemoryBinding#onUnbind()
	 */
	@Override
	protected void onUnbind() {
		headerOffset = headerLength = payloadLength = 0;
		descriptor = null;
	}

	/**
	 * Calculated payload data length for this protocol.
	 *
	 * @return length in bytes
	 */
	@Meta(MetaType.ATTRIBUTE)
	public int payloadLength() {
		return payloadLength;
	}

	/**
	 * Offset to the start of the payload for this specific protocol from the start
	 * of the packet.
	 *
	 * @return offset in bytes
	 */
	@Meta(MetaType.ATTRIBUTE)
	public int payloadOffset() {
		return headerOffset + headerLength;
	}

	/**
	 * Sets a new data formatter for this protocol header to use in generating
	 * {@link #toString()} method output. If the formatter is not set, the
	 * {@link #toString()} method defaults to minimum header state information such
	 * as offset, length, etc...
	 *
	 * @param formatter the new formatter
	 */
	public void setFormatter(PacketFormat formatter) {
		this.formatter = formatter;
	}

	/**
	 * Generates a simple string representing the state of this header or uses the
	 * formatter if set.
	 *
	 * @return the generated string from the fields of this header
	 * @see java.lang.Object#toString()
	 */
	@Override
	public final String toString() {
		return toString(Detail.DEFAULT);
	}

	/**
	 * Generates a simple string representing the state of this header or uses the
	 * formatter if set.
	 *
	 * @param detail generates the header string at specified detail level
	 * @return the generated string from the fields of this header
	 * @see java.lang.Object#toString()
	 */
	@Override
	public final String toString(Detail detail) {
		return toString(detail, formatter);
	}

	/**
	 * Generates a simple string representing the state of this header or uses the
	 * supplied formatter if not null.
	 *
	 * @param detail    generates the header string at specified detail level
	 * @param formatter the packet formatter, or if null default to builtin
	 *                  formatting
	 * @return the generated string from the fields of this header
	 * @see java.lang.Object#toString()
	 */
	public final String toString(Detail detail, PacketFormat formatter) {
		if (formatter != null)
			return formatter.format(this, detail);

		return printToString(detail);
	}

	/**
	 * Header descriptor.
	 *
	 * @return the header descriptor
	 */
	public HeaderDescriptor getHeaderDescriptor() {
		return headerDescriptor;
	}

	/**
	 * @see com.slytechs.jnet.platform.api.util.format.Printable#printTo(java.lang.Appendable,
	 *      com.slytechs.jnet.platform.api.util.format.Detail)
	 */
	@Override
	public void printTo(Appendable out, Detail detail) throws IOException {
		if (formatter != null) {
			out.append(formatter.format(this, detail));

			return;
		}

		int offset = headerOffset();
		int length = headerLength();

		String str = switch (detail) {
		case OFF -> "";
		case SUMMARY -> headerName();

		case MEDIUM -> "%s [offset=%d, length=%d]"
				.formatted(headerName(), offset, length);

		case HIGH -> "%s [offset=%d, length=%d]%n%s".formatted(
				headerName(),
				offset,
				length,
				HexStrings.toHexTextDump(
						buffer(),
						i -> "%04X: ".formatted(i + offset)));

		case HEXDUMP, DEBUG -> "%s [offset=%d, length=%d, payload=%d, id=%04X]"
				.formatted(headerName(), offset, length, payloadLength(), id());
		};

		out.append(str);
	}

}
