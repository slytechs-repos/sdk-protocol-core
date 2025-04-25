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
package com.slytechs.jnet.protocol.api.meta;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.protocol.api.common.Frame;
import com.slytechs.jnet.protocol.api.common.HasIndexedRecord;
import com.slytechs.jnet.protocol.api.common.HasOption;
import com.slytechs.jnet.protocol.api.common.Header;
import com.slytechs.jnet.protocol.api.common.HeaderFactory;
import com.slytechs.jnet.protocol.api.common.HeaderNotFound;
import com.slytechs.jnet.protocol.api.common.Packet;
import com.slytechs.jnet.protocol.api.meta.impl.GlobalContext;
import com.slytechs.jnet.protocol.api.meta.impl.MapMetaContext;
import com.slytechs.jnet.protocol.api.meta.impl.MetaElement;
import com.slytechs.jnet.protocol.api.meta.impl.ReflectedClass;
import com.slytechs.jnet.protocol.api.meta.impl.MetaContext.MetaMapped;
import com.slytechs.jnet.protocol.api.pack.PackId;
import com.slytechs.jnet.protocol.api.pack.ProtocolPackTable;

/**
 * The Class MetaPacket.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 */
public final class MetaPacket
		extends MetaElement
		implements Iterable<MetaHeader>, MetaMapped {

	private static final Logger LOGGER = Logger.getLogger(MetaPacket.class.getPackageName());

	@Meta(name = "*** Exception")
	private static class InternarErrorHeaderStub extends Header {

		private final String errorMessage;
		private final String headerName;
		private String cause;

		protected InternarErrorHeaderStub(String headerName, String errorMessage, Throwable cause) {
			super(-1);
			this.headerName = headerName;
			this.errorMessage = errorMessage;
			this.cause = (cause == null) ? "<not specified>" : cause.getMessage();
		}

		@Meta
		public String header() {
			return headerName;
		}

		@Meta
		public String error() {
			return errorMessage;
		}

		@Meta
		public String cause() {
			return cause == null ? "" : cause;
		}
	}

	/** The header factory. */
	private final HeaderFactory headerFactory = HeaderFactory.newInstance();

	/** The packet. */
	private final Packet packet;

	/** The headers. */
	private final List<MetaHeader> headers = new ArrayList<>();

	/** The last header. */
	private final MetaHeader lastHeader;

	/**
	 * Instantiates a new meta packet.
	 *
	 * @param packet the packet
	 */
	public MetaPacket(Packet packet) {
		this(new MapMetaContext("packet", 1), packet);
	}

	/**
	 * Instantiates a new meta packet.
	 *
	 * @param ctx    the ctx
	 * @param packet the packet
	 */
	public MetaPacket(MetaDomain ctx, Packet packet) {
		super(ctx, GlobalContext.compute(Packet.class, ReflectedClass::parse));
		this.packet = packet;

		String lastHeaderName = "";
		try {
			headers.add(new MetaHeader(ctx, this, packet.getHeader(new Frame(), 0)));

			int lastId = 0;
			HasIndexedRecord<? extends Header> lastHeaderRecord = null;
			int recordIndex = 0;
			HasOption<? super Header> lastHeaderOption = null;

			long[] compactArray = packet.descriptor().listHeaders();
			for (long cp : compactArray) {
				try {
					int id = PackId.decodeRecordId(cp);
					int packId = PackId.decodePackId(id);
					boolean isOption = (packId == ProtocolPackTable.PACK_ID_OPTIONS);
					if (isOption && (lastHeaderOption == null) && (lastHeaderRecord == null)) {
						throw new IllegalStateException(
								"Option header id[0x%X] error: parent %s header must implement OptionsHeader class"
										.formatted(id, lastHeaderName));
					}

					final Header header;
					if (isOption) {
						
						if (lastHeaderOption != null) {
							header = headerFactory.getExtension(lastId, id);
							lastHeaderOption.getOption(header, 0);

						} else {
							header = lastHeaderRecord.getRecord(recordIndex++);
						}

						lastHeaderName = header.headerName();

					} else {
						header = headerFactory.get(id);
						lastHeaderName = header.headerName();
						lastId = id;
						recordIndex = 0;
						lastHeaderOption = null;
						lastHeaderRecord = null;
						if (header instanceof HasOption<?> ext)
							lastHeaderOption = (HasOption<? super Header>) ext;

						else if (header instanceof HasIndexedRecord<?> ext)
							lastHeaderRecord = ext;

						packet.getHeader(header, 0);
					}

					lastHeaderName = header.toString(Detail.MEDIUM, null);

					MetaHeader metaHdr = new MetaHeader(ctx, this, header);
					headers.add(metaHdr);

				} catch (RuntimeException e) {
					MetaHeader errorHeaders = new MetaHeader(
							ctx,
							this,
							new InternarErrorHeaderStub(lastHeaderName, e.getMessage(), e.getCause()));
					headers.add(errorHeaders);

					LOGGER.log(Level.FINER, "runtime error", e);
				}
			}

			this.lastHeader = headers.get(headers.size() - 1);

//			if (packet.hasPayload())
//				headers.add(new MetaHeader(ctx, this, packet.getHeader(new Payload(), 0)));
		} catch (HeaderNotFound e) {
			LOGGER.fine(e::getMessage);
			throw new IllegalStateException(lastHeaderName, e);
		}
	}

	/**
	 * Gets the target.
	 *
	 * @return the target
	 */
	public Object getTarget() {
		return packet;
	}

	/**
	 * Iterator.
	 *
	 * @return the iterator
	 * @see java.lang.Iterable#iterator()
	 */
	@Override
	public Iterator<MetaHeader> iterator() {
		return listHeaders().iterator();
	}

	/**
	 * List headers.
	 *
	 * @return the list
	 */
	public List<MetaHeader> listHeaders() {
		return headers;
	}

	/**
	 * Gets the header.
	 *
	 * @param name the name
	 * @return the header
	 */
	public MetaHeader getHeader(String name) {
		return headers.stream()
				.filter(h -> h.name().equals(name))
				.findAny()
				.orElse(null);
	}

	/**
	 * Find header.
	 *
	 * @param name the name
	 * @return the optional
	 */
	public Optional<MetaHeader> findHeader(String name) {
		if (name.equals("last"))
			return Optional.of(lastHeader);

		return headers.stream()
//				.peek(h -> System.out.println("findHeader:: " + h.name()))
				.filter(h -> h.name().equals(name))
				.findAny();
	}

	/**
	 * Gets the.
	 *
	 * @param <K> the key type
	 * @param <V> the value type
	 * @param key the key
	 * @return the v
	 * @see com.slytechs.jnet.protocol.api.meta.impl.MetaContext.MetaMapped#get(java.lang.Object)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public <K, V> V get(K key) {
		String name = (String) key;
		return (V) headers.stream()
				.filter(h -> h.name().equals(name))
				.findAny()
				.orElse(null);
	}

	/**
	 * Size.
	 *
	 * @return the int
	 * @see com.slytechs.jnet.protocol.api.meta.impl.MetaContext.MetaMapped#size()
	 */
	@Override
	public int size() {
		return headers.size();
	}

	/**
	 * To string.
	 *
	 * @return the string
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "MetaPacket [%s]"
				.formatted(headers.stream()
						.map(MetaHeader::name)
						.collect(Collectors.joining(", ")));
	}

	/**
	 * Capture length.
	 *
	 * @return the int
	 */
	public int captureLength() {
		return packet.captureLength();
	}

	/**
	 * Wire length.
	 *
	 * @return the int
	 */
	public int wireLength() {
		return packet.wireLength();
	}

	/**
	 * Buffer.
	 *
	 * @return the byte buffer
	 */
	public ByteBuffer buffer() {
		return packet.buffer();
	}

	/**
	 * Find key.
	 *
	 * @param <K> the key type
	 * @param <V> the value type
	 * @param key the key
	 * @return the optional
	 * @see com.slytechs.jnet.protocol.api.meta.MetaDomain#findKey(java.lang.Object)
	 */
	@Override
	public <K, V> Optional<V> findKey(K key) {
		String m = key.toString();
		return listHeaders().stream()
				.filter(h -> h.name().matches(m))
				.map(h -> (V) h)
				.findAny();
	}

	/**
	 * Find domain.
	 *
	 * @param name the name
	 * @return the meta domain
	 * @see com.slytechs.jnet.protocol.api.meta.MetaDomain#findDomain(java.lang.String)
	 */
	@Override
	public MetaDomain findDomain(String name) {
		return listHeaders().stream()
				.filter(h -> h.name().matches(name))
				.findAny()
				.orElse(null);
	}
}
