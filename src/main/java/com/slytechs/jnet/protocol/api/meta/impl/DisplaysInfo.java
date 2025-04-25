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

import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Member;
import java.util.Arrays;
import java.util.function.Function;
import java.util.function.Predicate;

import com.slytechs.jnet.platform.api.util.Enums;
import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.platform.api.util.json.JsonObject;
import com.slytechs.jnet.platform.api.util.json.JsonObjectBuilder;
import com.slytechs.jnet.platform.api.util.json.JsonValue;
import com.slytechs.jnet.platform.api.util.json.JsonValue.ValueType;
import com.slytechs.jnet.protocol.api.meta.Display;
import com.slytechs.jnet.protocol.api.meta.Displays;

/**
 * The DisplaysInfo.
 *
 * @param displays a array of displays, one per detail level
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public record DisplaysInfo(DisplayInfo[] displays) implements MetaInfoType {

	/** Empty static array containing nothing but nulls in each row. */
	private static final Predicate<DisplayInfo[]> IS_EMPTY = new Predicate<>() {
		private static final DisplayInfo[] EMPTY_ARRAY = new DisplayInfo[Detail.values().length];

		/**
		 * @see java.util.function.Predicate#test(java.lang.Object)
		 */
		@Override
		public boolean test(DisplayInfo[] d) {
			return Arrays.equals(d, EMPTY_ARRAY);
		}
	};

	/**
	 * Parses the.
	 *
	 * @param element      the element
	 * @param name         the name
	 * @param jsonDefaults the json defaults
	 * @return the displays info
	 */
	public static DisplaysInfo parse(AnnotatedElement element, String name, JsonObject jsonDefaults) {
		JsonValue jsonDisplays = null;
		if (jsonDefaults != null)
			jsonDisplays = jsonDefaults.get("display");

		Function<Detail, DisplayInfo> defaultDisplay = (element instanceof Member)
				? DisplayInfo::defaultFieldDisplay
				: DisplayInfo::defaultHeaderDisplay;

		DisplayInfo[] displays = new DisplayInfo[Detail.values().length];

		/* Load json meta resource definitions */
		if (jsonDisplays != null)
			parseJson(jsonDisplays, displays, defaultDisplay);

		/* Now let annotations on method/field override the json defaults */
		parseAnnotationAndOverride(element, displays);

		/* If no displays settings specified, initialize all levels to defaults */
		if (IS_EMPTY.test(displays)) {
			for (Detail detail : Detail.values())
				displays[detail.ordinal()] = defaultDisplay.apply(detail);
		}

		return new DisplaysInfo(displays);
	}

	/**
	 * Parses the json.
	 *
	 * @param jsonValue      the json value
	 * @param displays       the displays
	 * @param defaultDisplay the default display
	 */
	private static void parseJson(JsonValue jsonValue, DisplayInfo[] displays,
			Function<Detail, DisplayInfo> defaultDisplay) {
		if (jsonValue == null)
			return;

		JsonObject defaultJson = null;

		if (jsonValue != null) {

			if (jsonValue.getValueType() == ValueType.OBJECT) {
				JsonObject jsonDisplays = (JsonObject) jsonValue;

				for (String key : jsonDisplays.keyOrderedList()) {
					if (key.equals("HIDE"))
						continue;
					
					if (key.equals("DEFAULT")) {
						defaultJson = getJsonDisplay(jsonDisplays);
						continue;
					}

					Detail detail = Enums.getEnum(Detail.class, key);
					JsonObject jsonDisplay = getJsonDisplay(jsonDisplays.get(key));
					DisplayInfo display = DisplayInfo.parseJson(jsonDisplay, detail, defaultDisplay);
					displays[detail.ordinal()] = display;
				}
			} else if (jsonValue.getValueType() == ValueType.STRING)
				defaultJson = getJsonDisplay(jsonValue);

			/* Apply defaults to missing details */
			if (defaultJson != null) {
				for (Detail detail : Detail.values()) {
					if (displays[detail.ordinal()] != null)
						continue;

					DisplayInfo display = DisplayInfo.parseJson(defaultJson, detail, defaultDisplay);
					displays[detail.ordinal()] = display;
				}
			}
		}
	}

	/**
	 * Gets the json display.
	 *
	 * @param value the value
	 * @return the json display
	 */
	private static JsonObject getJsonDisplay(JsonValue value) {
		if (value.getValueType() == ValueType.OBJECT)
			return (JsonObject) value;

		if (value.getValueType() == ValueType.STRING)
			return new JsonObjectBuilder()
					.add("value", value)
					.build();

		throw new IllegalArgumentException("invalid json data type for key [%s: \"%s\"]"
				.formatted(value));
	}

	/**
	 * Parses the annotation and override.
	 *
	 * @param element  the element
	 * @param displays the displays
	 */
	private static void parseAnnotationAndOverride(AnnotatedElement element,
			DisplayInfo[] displays) {
		Displays multiple = element.getAnnotation(Displays.class);
		Display single = element.getAnnotation(Display.class);

		if ((multiple == null) && (single == null))
			return;

		if (multiple != null) {
			Display[] displayAnnotations = multiple.value();

			for (Display display : displayAnnotations) {
				Detail detail = display.detail();

				displays[detail.ordinal()] = DisplayInfo.parseAnnotation(display, detail);
			}
		} else {
			Detail detail = single.detail();

			displays[detail.ordinal()] = DisplayInfo.parseAnnotation(single, detail);
		}

		return;
	}

	/**
	 * Select.
	 *
	 * @param detail the detail
	 * @return the display info
	 */
	public DisplayInfo select(Detail detail) {
		return displays[detail.ordinal()];
	}

}
