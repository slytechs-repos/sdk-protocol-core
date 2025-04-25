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

import java.util.Arrays;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.slytechs.jnet.platform.api.util.HexStrings;
import com.slytechs.jnet.platform.api.util.collection.IntArrayList;
import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.protocol.api.common.Header;
import com.slytechs.jnet.protocol.api.common.Packet;
import com.slytechs.jnet.protocol.api.meta.impl.DisplaysInfo;
import com.slytechs.jnet.protocol.api.meta.impl.GlobalContext;
import com.slytechs.jnet.protocol.api.meta.impl.MapMetaContext;
import com.slytechs.jnet.protocol.api.meta.impl.MetaElement;
import com.slytechs.jnet.protocol.api.meta.impl.MetaInfo;
import com.slytechs.jnet.protocol.api.meta.impl.MetaPath;

/**
 * The Class PacketFormat.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public final class PacketFormat extends MetaFormat {

	private static final Logger LOGGER = Logger.getLogger(MetaPacket.class.getPackageName());

	/** The Constant DEFAULT_LINE_FORMAT. */
	private static final String DEFAULT_LINE_FORMAT = "%20s = %-30s";
	private static final String DEFAULT_MULTILINE_FORMAT = "%20s   %-30s";

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = -729988509291767979L;

	private static boolean arrayContains(String[] array, String value) {
		for (int i = 0; i < array.length; i++)
			if (array[i].equals(value))
				return true;

		return false;
	}

	/** The field line. */
	private final String fieldLineFormatString;

	private final String fieldMultilineFormatString;

	/**
	 * Instantiates a new packet format.
	 */
	public PacketFormat() {
		this(Detail.DEFAULT);
	}

	/**
	 * Instantiates a new packet format.
	 *
	 * @param detail the detail
	 */
	public PacketFormat(Detail detail) {
		this(new MapMetaContext("packetFormat", 1), detail);
	}

	/**
	 * Instantiates a new packet format.
	 *
	 * @param domain the domain
	 * @param detail the detail
	 */
	public PacketFormat(MetaDomain domain, Detail detail) {
		super(domain, detail);

		this.fieldLineFormatString = DEFAULT_LINE_FORMAT;
		this.fieldMultilineFormatString = DEFAULT_MULTILINE_FORMAT;

//		this.fieldLine = domain.searchFor(null, HEADER_LINE_FORMAT_ATTRIBUTE, String.class)
//				.orElse(DEFAULT_LINE_FORMAT);
	}

	/**
	 * Convert to meta if possible.
	 *
	 * @param obj the obj
	 * @return the object
	 * @see com.slytechs.jnet.protocol.api.meta.MetaFormat#convertToMetaIfPossible(java.lang.Object)
	 */
	@Override
	protected Object convertToMetaIfPossible(Object obj) {
		if (obj instanceof Header header)
			return new MetaHeader(getContext(), header);

		if (obj instanceof Packet packet)
			return new MetaPacket(getContext(), packet);

		return obj;
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
		return Optional.empty();
	}

	/**
	 * Format field.
	 *
	 * @param field      the field
	 * @param toAppendTo the to append to
	 * @param detail     the detail
	 * @return the string builder
	 */
	public StringBuilder formatField(MetaField field, StringBuilder toAppendTo, Detail detail) {
		var display = field.getMeta(DisplaysInfo.class).select(detail);
		if (display == null) // Not visible
			return toAppendTo;

		String fieldName = field.name();

		var meta = field.getMeta(MetaInfo.class);
		var label = display.label(meta);
		var displayFormat = display.value();
		var valueArgs = buildDisplayArgs(field.getParentHeader(), field, displayFormat);
		var argLengths = new IntArrayList();

		try {
			if (label.equals("HEXDUMP")) {
				toAppendTo.append("\n");
				return formatHexdump(field, toAppendTo);
			}

			displayFormat = super.rewriteFormatString(displayFormat, argLengths);

		System.out.printf("formatField::%s displayFormat=%s, args=%s%n", 
				field.name(), 
//				display.value(),
				displayFormat,
				Arrays.asList(valueArgs));

			var labelComponent = label;
			var valueComponent = displayFormat.formatted(valueArgs);
			var line = fieldLineFormatString.formatted(labelComponent, valueComponent);

			toAppendTo.append(line);

//			formatFieldMultiline(display.multiline(), toAppendTo);

			return toAppendTo;
		} catch (Throwable e) {
			LOGGER.log(Level.FINE, "Meta (resource) error", e);
			throw new IllegalStateException("Field '%s.%s': %s [printf=%s, args=%s]"
					.formatted(field.getParentHeader().name(), field.name(), e
							.getMessage(), displayFormat, Arrays.asList(valueArgs)), e);
		}
	}

	private StringBuilder formatFieldMultiline(
			String label,
			MetaField field,
			String[] multiline,
			StringBuilder toAppendTo) {

		for (int i = 1; i < multiline.length; i++) {
			String displayFormat = multiline[i];
			Object[] valueArgs = null;
			var argLengths = new IntArrayList();

			try {

				valueArgs = buildDisplayArgs(field.getParentHeader(), field, displayFormat);
				displayFormat = super.rewriteFormatString(displayFormat, argLengths);

				var valueComponent = displayFormat.formatted(valueArgs);
				var line = fieldMultilineFormatString.formatted("", valueComponent);

				formatLeft(label, toAppendTo);
				toAppendTo.append(line);

				toAppendTo.append("\n");
			} catch (Throwable e) {
				LOGGER.log(Level.FINE, "Meta (resource) error", e);
				e.printStackTrace();
				throw new IllegalStateException("Field '%s.%s': %s [fmt=%s, args=%s]"
						.formatted(field.getParentHeader().name(), field.name(), e
								.getMessage(), displayFormat, Arrays.asList(valueArgs)));
			}
		}

		return toAppendTo;

	}

	public StringBuilder formatHeader(Header header, StringBuilder toAppendTo, Detail detail) {
		return formatHeader(new MetaHeader(this, header), toAppendTo, detail);
	}

	/**
	 * Format header.
	 *
	 * @param header     the header
	 * @param toAppendTo the to append to
	 * @param detail     the detail
	 * @return the string builder
	 */
	public StringBuilder formatHeader(MetaHeader header, StringBuilder toAppendTo, Detail detail) {
		var headerDisplay = header.getMeta(DisplaysInfo.class).select(detail);
		if (headerDisplay == null) // Not visible
			return toAppendTo;

		var meta = header.getMeta(MetaInfo.class);
		var fields = header.listFields();
		var label = headerDisplay.label(meta);

		var hide = headerDisplay.hide();

		if (!headerDisplay.value().isBlank()) {
			formatLeft(label, toAppendTo)
					.append("  + ");

			formatSummary(header, toAppendTo, detail);

			if (headerDisplay.isMultiline()) {
				formatHeaderMultiline(label, "  ", header, headerDisplay.multiline(), toAppendTo);
			}
		}

//		formatLeft(label, toAppendTo).append("\n");

		for (MetaField field : fields) {
			if (!field.isDisplayable(detail) || arrayContains(hide, field.name()))
				continue;

			var fieldDisplay = field.getMeta(DisplaysInfo.class).select(detail);

			if (!fieldDisplay.value().isEmpty()) {
				formatLeft(label, toAppendTo);
				formatField(field, toAppendTo, detail);
				toAppendTo.append("\n");
			}

			if (fieldDisplay.isMultiline()) {
				formatFieldMultiline(label, field, fieldDisplay.multiline(), toAppendTo);
			}

		}
		formatLeft(label, toAppendTo).append("\n");

		return toAppendTo;
	}

	private StringBuilder formatHeaderMultiline(
			String label,
			String prefix,
			MetaHeader header,
			String[] multiline,
			StringBuilder toAppendTo) {

		int i;
		for (i = 1; i < multiline.length; i++) {
			String displayFormat = multiline[i];
			Object[] valueArgs = null;
			var argLengths = new IntArrayList();

			try {

				valueArgs = buildDisplayArgs(header, header, displayFormat);
				displayFormat = super.rewriteFormatString(displayFormat, argLengths);

				valueArgs = rewriteArgsCenterAlign(valueArgs, argLengths);

				var valueComponent = displayFormat.formatted(valueArgs);

				formatLeft(label, toAppendTo);
				toAppendTo
						.append(prefix)
						.append(valueComponent);

				toAppendTo.append("\n");
			} catch (Throwable e) {
				LOGGER.log(Level.FINE, "Meta (resource) error", e);
				e.printStackTrace();
				throw new IllegalStateException("Field '%s::meta[%d]': %s [fmt=%s, args=%s]"
						.formatted(header.name(), i, e
								.getMessage(), displayFormat, Arrays.asList(valueArgs)));
			}
		}

		return toAppendTo;

	}

	/**
	 * Format hexdump.
	 *
	 * @param array       the array
	 * @param labelOffset the label offset
	 * @param toAppendTo  the to append to
	 * @return the string builder
	 */
	private StringBuilder formatHexdump(byte[] array, int labelOffset, StringBuilder toAppendTo) {
		return HexStrings.toHexTextDump(
				toAppendTo,
				array,
				HexStrings.DEFAULT_HEXDUMP_PREFIX);
	}

	/**
	 * Format hexdump.
	 *
	 * @param header the header
	 * @return the string
	 */
	public String formatHexdump(Header header) {
		return formatHexdump(new MetaHeader(this, header));

	}

	/**
	 * Format hexdump.
	 *
	 * @param field the field
	 * @return the string
	 */
	public String formatHexdump(MetaField field) {
		return formatHexdump(field, new StringBuilder()).toString();
	}

	/**
	 * Format hexdump.
	 *
	 * @param field      the field
	 * @param toAppendTo the to append to
	 * @return the string builder
	 */
	public StringBuilder formatHexdump(MetaField field, StringBuilder toAppendTo) {
		var offsetField = field.searchForField(new MetaPath("offset"))
				.orElse(null);
		int offset = offsetField.get();
		byte[] array = field.get();

		return formatHexdump(array, offset, toAppendTo);
	}

	/**
	 * Format hexdump.
	 *
	 * @param header the header
	 * @return the string
	 */
	public String formatHexdump(MetaHeader header) {
		return formatHexdump(header, new StringBuilder()).toString();
	}

	/**
	 * Format hexdump.
	 *
	 * @param header     the header
	 * @param toAppendTo the to append to
	 * @return the string builder
	 */
	public StringBuilder formatHexdump(MetaHeader header, StringBuilder toAppendTo) {
		int offset = header.offset();
		byte[] array = new byte[header.length()];
		header.buffer().get(0, array);

		return formatHexdump(array, offset, toAppendTo);
	}

	/**
	 * Format hexdump.
	 *
	 * @param packet the packet
	 * @return the string
	 */
	public String formatHexdump(MetaPacket packet) {
		return formatHexdump(packet, new StringBuilder()).toString();
	}

	/**
	 * Format hexdump.
	 *
	 * @param packet     the packet
	 * @param toAppendTo the to append to
	 * @return the string builder
	 */
	public StringBuilder formatHexdump(MetaPacket packet, StringBuilder toAppendTo) {
		int offset = 0;
		byte[] array = new byte[packet.captureLength()];
		packet.buffer().get(0, array);

		return formatHexdump(array, offset, toAppendTo);
	}

	/**
	 * Format hexdump.
	 *
	 * @param packet the packet
	 * @return the string
	 */
	public String formatHexdump(Packet packet) {
		return formatHexdump(new MetaPacket(this, packet));
	}

	/**
	 * Format left.
	 *
	 * @param label      the label
	 * @param toAppendTo the to append to
	 * @return the string builder
	 */
	private StringBuilder formatLeft(String label, StringBuilder toAppendTo) {
		return toAppendTo
				.append("%-10s".formatted(label + ":"));
	}

	/**
	 * Format meta.
	 *
	 * @param element    the element
	 * @param toAppendTo the to append to
	 * @param detail     the detail
	 * @return the string builder
	 * @see com.slytechs.jnet.protocol.api.meta.MetaFormat#formatMeta(com.slytechs.jnet.protocol.api.meta.impl.MetaElement,
	 *      java.lang.StringBuilder, Detail)
	 */
	@Override
	public StringBuilder formatMeta(MetaElement element, StringBuilder toAppendTo, Detail detail) {

		if (element instanceof MetaPacket packet)
			return formatPacket(packet, toAppendTo, detail);

		if (element instanceof MetaHeader header)
			return formatHeader(header, toAppendTo, detail);

		if (element instanceof MetaField field)
			return formatField(field, toAppendTo, detail);

		throw new IllegalArgumentException("Unsupported Meta object [%s]"
				.formatted(element.getClass().getSimpleName()));
	}

	/**
	 * Format packet.
	 *
	 * @param packet     the packet
	 * @param toAppendTo the to append to
	 * @param detail     the detail
	 * @return the string builder
	 */
	public StringBuilder formatPacket(MetaPacket packet, StringBuilder toAppendTo, Detail detail) {
		var display = packet.getMeta(DisplaysInfo.class).select(detail);
		if (display == null) // Not visible
			return toAppendTo;

		String label = display.label(packet.getMeta(MetaInfo.class));

		formatLeft(label, toAppendTo)
				.append("  ");
		formatSummary(packet, toAppendTo, detail);

		var headers = packet.listHeaders();

		for (MetaHeader header : headers)
			formatHeader(header, toAppendTo, detail);

		return toAppendTo;
	}

	/**
	 * Format packet.
	 *
	 * @param packet     the packet
	 * @param toAppendTo the to append to
	 * @param detail     the detail
	 * @return the string builder
	 */
	public StringBuilder formatPacket(Packet packet, StringBuilder toAppendTo, Detail detail) {
		return formatPacket(new MetaPacket(this, packet), toAppendTo, detail);
	}

	/**
	 * Format summary.
	 *
	 * @param element    the element
	 * @param toAppendTo the to append to
	 * @param detail     the detail
	 * @return the string builder
	 */
	private StringBuilder formatSummary(MetaElement element, StringBuilder toAppendTo, Detail detail) {
		var display = element.getMeta(DisplaysInfo.class).select(detail);
		if (display == null)
			return toAppendTo;

		var displayFormat = display.value();
		if (displayFormat.isBlank())
			return toAppendTo;

		var args = super.buildDisplayArgs(element, element, displayFormat);
		var argLengths = new IntArrayList();
		displayFormat = super.rewriteFormatString(displayFormat, argLengths);

		try {
			var summaryLine = displayFormat.formatted(args);

			toAppendTo
					.append(summaryLine)
					.append("\n");

			return toAppendTo;
		} catch (Throwable e) {
			String message = "%s [\"%s\"]".formatted(element.name(), e.getMessage());
			String warning = ("%s%n"
					+ "display.original =[%s]%n"
					+ "display.rewritten=[%s]%n"
					+ "display.arguments=%s")
					.formatted(message, display.value(), displayFormat, Arrays.asList(args));

			toAppendTo.append(">>>%s<<<%n".formatted(message));

			LOGGER.log(Level.WARNING, warning);
			LOGGER.log(Level.FINE, "format conversion error for meta element summary [%s]"
					.formatted(element.name()), e);

			return toAppendTo;
		}
	}

	/**
	 * Name.
	 *
	 * @return the string
	 * @see com.slytechs.jnet.protocol.api.meta.MetaDomain#name()
	 */
	@Override
	public String name() {
		return "";
	}

	/**
	 * Parent.
	 *
	 * @return the meta domain
	 * @see com.slytechs.jnet.protocol.api.meta.MetaDomain#parent()
	 */
	@Override
	public MetaDomain parent() {
		return GlobalContext.get();
	}

}
