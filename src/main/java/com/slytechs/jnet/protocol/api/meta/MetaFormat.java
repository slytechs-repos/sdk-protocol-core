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

import java.text.FieldPosition;
import java.text.Format;
import java.text.ParsePosition;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.slytechs.jnet.platform.api.util.WeakNamedCache;
import com.slytechs.jnet.platform.api.util.collection.IntList;
import com.slytechs.jnet.platform.api.util.format.BitFormat;
import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.protocol.api.meta.impl.DisplayUtil;
import com.slytechs.jnet.protocol.api.meta.impl.MetaElement;
import com.slytechs.jnet.protocol.api.meta.impl.MetaInfo;
import com.slytechs.jnet.protocol.api.meta.impl.MetaPath;

/**
 * Base class for all meta object formats.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public abstract class MetaFormat extends Format implements MetaDomain {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = -4307770938567017464L;

	/**
	 * Cache the JSON resource table so we don't have to read in the resource file
	 * for every packet. Use a WEAK reference cache so that when not in-recent-use
	 * the table entries expire and get garbage collected.
	 */
	private static final WeakNamedCache<String, String> WEAK_DISPLAY_SWITCH_CACHE = new WeakNamedCache<>();

	/** The context. */
	private final MetaDomain context;

	/** The detail. */
	private final Detail detail;

	/**
	 * Instantiates a new meta format.
	 *
	 * @param context the context
	 * @param detail  the detail
	 */
	protected MetaFormat(MetaDomain context, Detail detail) {
		this.context = context;
		this.detail = detail;

	}

	/**
	 * Format.
	 *
	 * @param obj    the obj
	 * @param detail the detail
	 * @return the string
	 */
	public final String format(Object obj, Detail detail) {
		return format(obj, new StringBuilder(), detail).toString();
	}

	/**
	 * Format.
	 *
	 * @param obj        the obj
	 * @param toAppendTo the to append to
	 * @param detail     the detail
	 * @return the string builder
	 */
	public final StringBuilder format(Object obj, StringBuilder toAppendTo, Detail detail) {
		obj = convertToMetaIfPossible(obj);

		if (!(obj instanceof MetaElement element))
			throw new IllegalArgumentException("Only Meta elements supported by MetaFormat");

		StringBuilder b = formatMeta(element, toAppendTo, detail);

		return b;
	}

	/**
	 * Format.
	 *
	 * @param obj        the obj
	 * @param toAppendTo the to append to
	 * @param pos        the pos
	 * @return the string buffer
	 * @see java.text.Format#format(java.lang.Object, java.lang.StringBuffer,
	 *      java.text.FieldPosition)
	 */
	@Override
	public final StringBuffer format(Object obj, StringBuffer toAppendTo, FieldPosition pos) {
		obj = convertToMetaIfPossible(obj);

		if (!(obj instanceof MetaElement element))
			throw new IllegalArgumentException("Only Meta elements supported by MetaFormat");

		StringBuilder b = formatMeta(element, new StringBuilder(), getDetail());

		return toAppendTo.append(b);
	}

	/**
	 * Parses the object.
	 *
	 * @param source the source
	 * @param pos    the pos
	 * @return the object
	 * @see java.text.Format#parseObject(java.lang.String, java.text.ParsePosition)
	 */
	@Override
	public Object parseObject(String source, ParsePosition pos) {
		throw new UnsupportedOperationException("Meta object is not parsable [\"%s\"]"
				.formatted(source));
	}

	/**
	 * Convert to meta if possible.
	 *
	 * @param obj the obj
	 * @return the object
	 */
	protected abstract Object convertToMetaIfPossible(Object obj);

	/**
	 * Format meta.
	 *
	 * @param element    the element
	 * @param toAppendTo the to append to
	 * @param detail     the detail
	 * @return the string builder
	 */
	public abstract StringBuilder formatMeta(MetaElement element, StringBuilder toAppendTo, Detail detail);

	/**
	 * Gets the context.
	 *
	 * @return the context
	 */
	public final MetaDomain getContext() {
		return context;
	}

	/**
	 * Gets the detail.
	 *
	 * @return the detail
	 */
	public final Detail getDetail() {
		return detail;
	}

	/** The Constant DISPLAY_ATTRIBUTE_PATTERN. */
	private static final Pattern DISPLAY_ATTRIBUTE_PATTERN = Pattern.compile("%\\{"
			+ "(header\\[[\\d:]+\\]|[\\w.?/\\\\]*)"
			+ ":?([VFRO]?[12345]*)"
			+ "(\\$([\\w\\s\\.]+))?"
			+ "(\\$(.))?"
			+ "(\\[(.*)\\])?"
			+ "\\}");

	/** The Constant DISPLAY_ATTRIBUTE_PATTERN. */
	private static final Pattern VAR_PATTERN = Pattern.compile(""
			+ "[\\s\\|](\\$(\\d*)([\\w\\-][\\d\\w]*))"
			+ "");
	private static final Pattern VAR_REPLACEMENT_PATTERN = Pattern.compile(""
			+ "(\\s*\\$(\\d*)[\\w\\-][\\d\\w]*\\s*)"
			+ "|"
			+ DISPLAY_ATTRIBUTE_PATTERN
			+ "");

	/**
	 * Rewrite display args.
	 *
	 * @param summaryFormat the summary format
	 * @return the string
	 */
	protected String rewriteFormatString(String summaryFormat, IntList argLengths) {

		return VAR_REPLACEMENT_PATTERN
				.matcher(summaryFormat)
				.replaceAll(r -> {
					if (r.group(1) != null) {
						int argLen = (r.group(2) == null) || r.group(2).isBlank()
								? r.group(1).length()
								: Integer.parseInt(r.group(2));
						argLengths.addInt(argLen);

						return "%%%ds".formatted(argLen);

					} else {
						argLengths.addInt(-1);

						return "%";
					}
				});
	}

	protected Object[] rewriteArgsCenterAlign(Object[] src, IntList argLengths) {
		Object[] dst = src;

		for (int i = 0; i < src.length; i++) {
			int fmtLen = argLengths.getInt(i);
			if (fmtLen == -1)
				continue;

			String arg = ((String) src[i]);
			int argLen = arg.length();
			int pad = (fmtLen - argLen) / 2;

			Object centered; // format with padding
			if (pad == 0)
				centered = arg;
			else {
				String fmt = "%%%ds%%s%%%ds".formatted(pad, pad);
				centered = fmt.formatted("", arg, "");
			}

			dst[i] = centered;
		}

		return dst;
	}

	private final static String VAR_CENTER_CHAR = "-";

	private static String normalizeSwitchFormatString(MetaElement element, String format) {
		if (format != null
				&& format.contains("@")
				&& element instanceof MetaField field
				&& field.getParentHeader() instanceof MetaHeader header) {
			String classPath = header.getTarget().getClass().getPackageName();
			
			format = format.replaceFirst("@", "@" + classPath + ".");
			
			return format;

		} else {
			return format;
		}
	}

	/**
	 * Builds the display args.
	 *
	 * @param domain     the domain
	 * @param element    the element
	 * @param formatLine the summary format
	 * @return the object[]
	 */
	protected Object[] buildDisplayArgs(MetaDomain domain, MetaElement element, String formatLine) {
		Matcher varMatcher = VAR_PATTERN.matcher(formatLine);
		Matcher matcher = DISPLAY_ATTRIBUTE_PATTERN.matcher(formatLine);

		var list = new ArrayList<>();

		String name = element.name();

		while (true) {

			if (varMatcher.find() && element instanceof MetaHeader hdr) {
				String varName = varMatcher.group(3);
				Optional<String> varValue;
				if (varName.equals(VAR_CENTER_CHAR))
					varValue = Optional.of(" ");
				else
					varValue = hdr.findVariable(varName);

				list.add(varValue.orElse(varName));

				continue;
			}

			if (!matcher.find())
				break;

			var fieldName = matcher.group(1);
			var valueFormat = matcher.group(2);
			var bitsFormat = matcher.group(4);
			var bitsOffChar = matcher.group(6);
			var switchFormat = matcher.group(8);

			switchFormat = normalizeSwitchFormatString(element, switchFormat);

			MetaField selected = null;
			if (element instanceof MetaField field)
				selected = field;

			if (fieldName != null && fieldName.startsWith("header")) {
				selected = (MetaField) element;

			} else if (fieldName != null && !fieldName.isBlank())
				selected = new MetaPath(fieldName)
						.searchForField(domain)
						.orElse(null);
			else if (element instanceof MetaField field) {
				fieldName = field.name();
				selected = field;
			}

			if (fieldName == null || fieldName.isBlank())
				continue;

			if (bitsFormat != null) {
				Number num = readValue(selected, fieldName);

				list.add(formatBitsValue(num, bitsFormat, bitsOffChar));
				continue;
			}

			if (switchFormat != null) {
				Object val = readValue(selected, fieldName);

				list.add(formatSwitchValue(val, switchFormat));
				continue;
			}

			if (valueFormat != null)
				valueFormat.toUpperCase();

			/* Unresolved fields are just passed through */
			if (selected == null) {
				list.add("{%s}".formatted(fieldName));
				continue;
			}

			Object arg = switch (valueFormat) {
			case "V" -> selected.get();
			case "F" -> selected.getFormatted();
			case "R" -> selected.getResolved(0);
			case "R1" -> selected.getResolved(0);
			case "R2" -> selected.getResolved(1);
			case "R3" -> selected.getResolved(2);
			case "R4" -> selected.getResolved(3);
			case "R5" -> selected.getResolved(4);
			case "O" -> element.getMeta(MetaInfo.class).ordinal();
			default -> selected.get();
			};

			if (arg == null)
				arg = selected.getFormatted();

			list.add(arg);
		}

		return list.toArray();
	}

	private static final Pattern RANGE_PATTERN = Pattern.compile(""
			+ "^(packet|header|field)\\[(\\d+)(:(\\d+)?|(byte|short|int|long)?)?\\]"
			+ "");

	@SuppressWarnings("unchecked")
	private <T> T readValue(MetaField selected, String fieldName) {

		try {
			Matcher matcher = RANGE_PATTERN.matcher(fieldName);

			if (matcher.find()) {
				int index = Integer.parseInt(matcher.group(2));
				int len = 1;

				if (matcher.group(4) != null) {
					len = Integer.parseInt(matcher.group(4));

				} else if (matcher.group(5) != null) {
					String type = matcher.group(5);

					return (T) switch (type) {
					case "byte" -> selected.readNumberFromHeader(byte.class, index);
					case "short" -> selected.readNumberFromHeader(short.class, index);
					case "int" -> selected.readNumberFromHeader(int.class, index);
					case "long" -> selected.readNumberFromHeader(long.class, index);

					default -> selected.get();
					};
				}

				return (T) switch (len) {
				case 1 -> selected.readNumberFromHeader(byte.class, index);
				case 2 -> selected.readNumberFromHeader(short.class, index);
				case 4 -> selected.readNumberFromHeader(int.class, index);
				case 8 -> selected.readNumberFromHeader(long.class, index);

				default -> selected.get();
				};
			}

			return selected.get();
		} catch (IllegalArgumentException | Error e2) {
			throw e2;
		}
	}

	private String formatBitsValue(Number num, String bitsFormat, String bitsOffChar) {
		if (bitsOffChar == null)
			return new BitFormat(bitsFormat)
					.format(num.longValue());
		else
			return new BitFormat(bitsFormat, bitsOffChar.charAt(0))
					.format(num.longValue());

	}

	private String formatSwitchValue(Object value, String sw) {
		String[] split = sw.split(",");
		String defValue = "";

		for (String c : split) {
			c = c.strip();

			/*
			 * Check for default case or @include table syntax where the table is imported
			 * from resource or Enum table class.
			 */
			int index = c.indexOf('=');
			if (index == -1) {

				/* Include table operator */
				if (c.startsWith("@")) {
					String m = matchSwitchValueFromFile(value, c.substring(1));
					if (m == null)
						continue;

					return m;
				}

				/* Use single value with no assign, as default case */
				defValue = c;
				continue;
			}

			String key = c.substring(0, index);
			String label = c.substring(index + 1);

			/* Allow '_' chars in numerical values */
			if (Character.isDigit(key.charAt(0))) {
				key = key.replaceAll("_", "");

				/*
				 * Normalize numerical values based on RADIX, a single digit is always a decimal
				 */
				if (key.length() > 1 && key.charAt(0) == '0') {
					key = switch (key.charAt(1)) {
					case 'x' -> Long.toString(Long.parseLong(key.substring(2), 16)); // ie. 0x12349FDSD
					case 'b' -> Long.toString(Long.parseLong(key.substring(2), 2)); // ie. 0b011010101
					default -> {
						if (key.charAt(0) == '0') // Check for Octal ie. 01234567
							yield Long.toString(Long.parseLong(key.substring(1), 8));

						yield key;
					}
					};
				}
			}

			if (key.equals(value.toString()))
				return label;
		}

		return defValue;
	}

	private String matchSwitchValueFromFile(Object value, String name) {
		Map<String, String> table;
		if (name.endsWith(".class"))
			table = WEAK_DISPLAY_SWITCH_CACHE.computeIfAbsent(name, DisplayUtil::loadEnumTable);

		else if (name.endsWith(".json"))
			table = WEAK_DISPLAY_SWITCH_CACHE.computeIfAbsent(name, DisplayUtil::loadResourceTable);
		else
			return null;

		return table.get(value.toString());
	}
}
