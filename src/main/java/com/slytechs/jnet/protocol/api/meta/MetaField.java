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

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.protocol.api.meta.MetaValue.ValueResolver;
import com.slytechs.jnet.protocol.api.meta.impl.DisplaysInfo;
import com.slytechs.jnet.protocol.api.meta.impl.MetaElement;
import com.slytechs.jnet.protocol.api.meta.impl.MetaInfo;
import com.slytechs.jnet.protocol.api.meta.impl.ReflectedMember;
import com.slytechs.jnet.protocol.api.meta.impl.ResolversInfo;

/**
 * The Class MetaField.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 */
public final class MetaField extends MetaElement {
	private static final Logger logger = LoggerFactory.getLogger(MetaField.class);

	/** The header. */
	private final MetaHeader header;

	/** The member. */
	private final ReflectedMember member;

	/** The resolvers. */
	private final ValueResolver[] resolvers;

	/** The target. */
	private final Object target;

	/**
	 * Instantiates a new meta field.
	 *
	 * @param header     the header
	 * @param memberInfo the member info
	 */
	MetaField(MetaHeader header, ReflectedMember memberInfo) {
		super(header, memberInfo);
		this.target = header.getTarget();
		this.header = header;
		this.member = memberInfo;
		memberInfo.getMetaType(MetaInfo.class).metaType();
		var resolversInfo = memberInfo.getMetaType(ResolversInfo.class);

		if (resolversInfo != null) {
			this.resolvers = resolversInfo.resolvers();

			for (int i = 0; i < resolvers.length; i++) {
				var resolver = resolvers[i];
				if (resolver == null) {
					logger.warn("empty meta value resolver for field [{}.{}]",
							header.name(),
							memberInfo.name());

					resolvers[i] = ValueResolver.DEFAULT_RESOLVER;
				}
			}
		} else
			this.resolvers = new ValueResolver[0];
	}

	/**
	 * Gets the parent header.
	 *
	 * @return the parent header
	 */
	public MetaHeader getParentHeader() {
		return header;
	}

	/**
	 * List sub fields.
	 *
	 * @return the list
	 */
	public List<MetaField> listSubFields() {
		return Collections.emptyList();
	}

	/**
	 * Gets the.
	 *
	 * @param <V> the value type
	 * @return the v
	 */
	public <V> V get() {
		return member.getValue(target);
	}

	/**
	 * Sets the.
	 *
	 * @param <V>      the value type
	 * @param newValue the new value
	 */
	public <V> void set(V newValue) {
		member.setValue(target, newValue);
	}

	/**
	 * String value.
	 *
	 * @return the string
	 */
	public String stringValue() {
		return get();
	}

	/**
	 * Gets the formatted.
	 *
	 * @return the formatted
	 */
	public String getFormatted() {
		Object value = member.getValue(target);
		MetaInfo meta = getMeta(MetaInfo.class);

		return meta.formatter().format(value);
	}

	/**
	 * Gets the resolved.
	 *
	 * @param resolverIndex the resolver index
	 * @return the resolved
	 */
	public String getResolved(int resolverIndex) {
		if (resolverIndex >= resolvers.length)
			return "";

		return resolvers[resolverIndex].resolveValue(this, get());
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
		if (name().equals(key))
			return Optional.of((V) this);

		return Optional.empty();
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
		return null;
	}

	/**
	 * @param detail
	 * @return
	 */
	public boolean isDisplayable(Detail detail) {
		DisplaysInfo displays = getMeta(DisplaysInfo.class);

		return displays != null && displays.select(detail) != null;
	}

	/**
	 * Read number from header.
	 *
	 * @param type  the type
	 * @param index the index
	 * @return the number
	 */
	public Number readNumberFromHeader(Class<?> type, int index) {
		var buf = getParentHeader().buffer();

		if (type == byte.class)
			return Byte.toUnsignedInt(buf.get(index));

		if (type == short.class)
			return Short.toUnsignedInt(buf.getShort(index));

		if (type == int.class)
			return Integer.toUnsignedLong(buf.getInt(index));

		if (type == long.class)
			return buf.getLong(index);

		return get();
	}
}
