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
package com.slytechs.jnet.protocol.api.meta.impl;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.IntSupplier;
import java.util.regex.Pattern;

import com.slytechs.jnet.platform.api.util.IsAbbr;
import com.slytechs.jnet.platform.api.util.IsDescription;
import com.slytechs.jnet.platform.api.util.Reflections;
import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.platform.api.util.json.Json;
import com.slytechs.jnet.platform.api.util.json.JsonException;
import com.slytechs.jnet.platform.api.util.json.JsonObject;
import com.slytechs.jnet.protocol.api.meta.Display;
import com.slytechs.jnet.protocol.api.meta.Displays;
import com.slytechs.jnet.protocol.api.meta.MetaException;
import com.slytechs.jnet.protocol.api.meta.MetaFormat;

/**
 * The Class DisplayUtil.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 */
public final class DisplayUtil {

	/**
	 * The Replacing.
	 */
	private record Replacing(Pattern pattern, String replacement) {

		/**
		 * Instantiates a new replacing.
		 *
		 * @param pattern     the pattern
		 * @param replacement the replacement
		 */
		Replacing(String pattern, String replacement) {
			this(Pattern.compile(pattern), replacement);
		}

		/**
		 * Replace all.
		 *
		 * @param str the str
		 * @return the string
		 */
		public String replaceAll(String str) {
			return pattern.matcher(str).replaceAll(replacement());
		}
	}

	/** The Constant DISPLAY_FMT_REPLACEMENTS. */
	private static final Replacing[] DISPLAY_FMT_REPLACEMENTS = {
			new Replacing("\\$([\\d,.+-]*)F", "%2&#36;$1"),
			new Replacing("\\$([\\d,.+-]*)R1", "%3&#36;$1"),
			new Replacing("\\$([\\d,.+-]*)R2", "%4&#36;$1"),
			new Replacing("\\$([\\d,.+-]*)R3", "%5&#36;$1"),
			new Replacing("\\$([\\d,.+-]*)R4", "%6&#36;$1"),
			new Replacing("\\$([\\d,.+-]*)R", "%3&#36;$1"),
			new Replacing("\\$([\\d,.+-]*)([xX])", "0x%1&#36;$1$2"),
			new Replacing("\\$([\\d,.+-]*)([a-zA-Z])", "%1&#36;$1$2"),

			new Replacing("&#36;", "\\$"), // Restore escaped '$' character
	};

	/**
	 * Rewrite display format.
	 *
	 * @param fmt the fmt
	 * @return the string
	 */
	public static String rewriteDisplayFormat(String fmt) {
		String str = rewriteDisplayFormat0(fmt);
		return str;
	}

	/**
	 * Rewrite display format 0.
	 *
	 * @param fmt the fmt
	 * @return the string
	 */
	public static String rewriteDisplayFormat0(String fmt) {

		for (Replacing replacing : DISPLAY_FMT_REPLACEMENTS)
			fmt = replacing.replaceAll(fmt);

		return fmt;
	}

	/**
	 * Checks if is detail.
	 *
	 * @param details the details
	 * @param detail  the detail
	 * @return true, if is detail
	 */
	public static boolean isDetail(Detail[] details, Detail detail) {
		for (Detail d : details) {
			if (d == detail)
				return true;
		}

		return details.length == 0;
	}

	/**
	 * Select display.
	 *
	 * @param multiple the multiple
	 * @param single   the single
	 * @param detail   the detail
	 * @return the optional
	 */
	public static Optional<Display> selectDisplay(Displays multiple, Display single, Detail detail) {

		if (multiple != null) {
			Display[] da = multiple.value();
			if (da.length == 0)
				return Optional.empty();

			for (Display display : da) {
				if (display.detail() == detail)
					return Optional.ofNullable(display);
			}

			return Optional.empty();
		}

		return Optional.empty();
	}

	/**
	 * Instantiates a new display util.
	 */
	private DisplayUtil() {
	}

	/**
	 * Bitshift int left.
	 *
	 * @param v     the v
	 * @param shift the shift
	 * @return the string
	 */
	public static String bitshiftIntLeft(Object v, int shift) {
		if (!(v instanceof Number n))
			return String.valueOf(v);

		long l = (n.longValue() << shift);

		return Long.toString(l);
	}

	/**
	 * Load enum table.
	 *
	 * @param enumClassName the enum class name
	 * @return the map
	 */
	public static Map<String, String> loadEnumTable(String enumClassName) {
		String[] split = enumClassName.split(":");

		Module module = (split.length == 2) ? Reflections.loadModule(split[0]) : MetaFormat.class.getModule();
		String className = (split.length == 2) ? split[1] : split[0];

		className = className.replaceFirst("\\.class", "");

		if (className.indexOf('.') == -1)
			className = "com.slytechs.jnet.protocol.tcpip.constants." + className;

		try {
			Class<?> cl = Reflections.loadClass(module, className);
			if (!cl.isEnum())
				throw new MetaException("Class with table must by Enum type [%s]"
						.formatted(enumClassName));

			if (!IntSupplier.class.isAssignableFrom(cl))
				throw new MetaException("Class with table must implement IntSupplier interface [%s]"
						.formatted(enumClassName));

			Enum<?>[] constants = (Enum<?>[]) cl.getEnumConstants();
			Map<String, String> map = new HashMap<>();

			for (Enum<?> e : constants) {
				String key;
				if (e instanceof IntSupplier intSup)
					key = "" + intSup.getAsInt();
				else
					key = "" + e.ordinal();

				String value;
				if (e instanceof IsDescription isDesc)
					value = isDesc.description();
				else if (e instanceof IsAbbr isAbbr)
					value = isAbbr.abbr();
				else
					value = e.name();

				map.put(key, value);
			}

			return map;

		} catch (ClassNotFoundException e) {
			throw new MetaException("Class with table not found [%s]"
					.formatted(enumClassName));
		}
	}

	/**
	 * Load resource table.
	 *
	 * @param jsonResourceName the json resource name
	 * @return the map
	 */
	public static Map<String, String> loadResourceTable(String jsonResourceName) {
		var ins = DisplayUtil.class.getResourceAsStream("/" + jsonResourceName);
		if (ins == null)
			throw new MetaException("Resource file with table not found [%s]"
					.formatted(jsonResourceName));

		JsonObject obj;
		try (var reader = Json.createReader(ins)) {
			obj = reader.readObject();
		} catch (JsonException e) {
			throw new IllegalStateException("unexpected error while reading resource " + jsonResourceName, e);
		}

		Map<String, String> map = new HashMap<>();
		obj.keyOrderedList()
				.stream()
				.forEach(k -> map.put(k, obj.getString(k)));

		return map;
	}
}
