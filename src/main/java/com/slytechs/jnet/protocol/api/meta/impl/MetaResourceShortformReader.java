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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.platform.api.util.json.JsonArray;
import com.slytechs.jnet.platform.api.util.json.JsonArrayBuilder;
import com.slytechs.jnet.platform.api.util.json.JsonException;
import com.slytechs.jnet.platform.api.util.json.JsonObject;
import com.slytechs.jnet.platform.api.util.json.JsonObjectBuilder;
import com.slytechs.jnet.platform.api.util.json.JsonString;
import com.slytechs.jnet.platform.api.util.json.JsonValue;
import com.slytechs.jnet.protocol.api.meta.MetaValue.ValueResolver.ValueResolverType;

/**
 * The Class MetaResourceShortformReader.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 */
public class MetaResourceShortformReader extends MetaResourceReader {

	private int ordinalInc;
	private int ordinal;

	/**
	 * Instantiates a new meta resource shortform reader.
	 *
	 * @param resourceName the resource name
	 * @throws JsonException the json exception
	 */
	public MetaResourceShortformReader(String resourceName) throws JsonException {
		super(resourceName);
	}

	/**
	 * Process.
	 *
	 * @param sourceJsonObj the source json obj
	 * @return the json object
	 * @see com.slytechs.jnet.protocol.api.meta.impl.MetaResourceReader#process(com.slytechs.jnet.jnetruntime.internal.json.JsonObject)
	 */
	@Override
	protected JsonObject process(JsonObject sourceJsonObj) {

		if (sourceJsonObj.isPresent("meta") || sourceJsonObj.isPresent("display"))
			return sourceJsonObj;

		return inflateShortform(sourceJsonObj);
	}

	private JsonObject inflateShortform(JsonObject sobj) {
		var topBuilder = new JsonObjectBuilder();
		var fieldsBuilder = new JsonObjectBuilder();

		for (final String key : sobj.keyOrderedList()) {

			final Detail[] detailArray = findDetail(key); // Ex. HIGH,SUMMARY,MEDIUM - comma sep
			if (detailArray == null) {
				/* Inflate header checks and prevents duplicate header declarations */
				inflateHeader(topBuilder, key, sobj.get(key));

			} else {
				for (Detail detail : detailArray) {
					inflateFieldsGroup(fieldsBuilder, detail, sobj.getJsonObject(key));
				}

			}
		}

		topBuilder.add("field", fieldsBuilder.build());

		return topBuilder.build();
	}

	/**
	 * @param fieldsBuilder
	 * @param object
	 * @param jsDetailGroup
	 */
	private void inflateFieldsGroup(JsonObjectBuilder fieldsBuilder, Detail detail, JsonObject jsDetailGroup) {

		if (detail == null) {
			for (Detail d : Detail.values()) {
				if (d == Detail.OFF)
					continue;

				inflateFieldsGroup(fieldsBuilder, d, jsDetailGroup);
			}

			return;
		}

		for (String key : jsDetailGroup.keyOrderedList()) {
			JsonValue jsValue = jsDetailGroup.get(key);
			inflateFieldDeclaration(fieldsBuilder, detail, key, parseDisplayString(key, jsValue), jsValue);
		}

	}

	private String parseDisplayString(String field, JsonValue jsValue) {
		if (jsValue instanceof JsonString jsString)
			return jsString.getString();

		if (jsValue instanceof JsonArray jsArray) {
			return jsArray.getString(0);

		} else if (jsValue instanceof JsonObject jsObj) {
			List<String> keys = jsObj.keyOrderedList();
			if (keys.size() != 1)
				throw new IllegalArgumentException("%s: Unsupported display string Json type %s, missing display string"
						.formatted(field, jsValue.getValueType()));

			return keys.get(0);
		}

		throw new IllegalArgumentException("%s: Unsupported display string Json type %s"
				.formatted(field, jsValue.getValueType()));
	}

	private void inflateFieldDeclaration(
			JsonObjectBuilder fieldsBuilder,
			Detail detail,
			String metaString,
			String displayString,
			JsonValue fieldDisplay) {

		String fieldName = stripName(metaString);
		JsonObjectBuilder jsFieldBuilder = JsonObjectBuilder
				.wrapOrElseNewInstance(fieldsBuilder.getJsonObject(fieldName));

		if (jsFieldBuilder.getJsonObject("meta") == null) {
			JsonObject jsMetaObj = inflateFieldMeta(metaString);

			jsFieldBuilder.add("meta", jsMetaObj);
		}

		List<ValueResolverType> resolverList = getResolversOrListFromDisplay(jsFieldBuilder, displayString);

		JsonObjectBuilder jsDisplayBuilder = JsonObjectBuilder
				.wrapOrElseNewInstance(jsFieldBuilder.getJsonObject("display"));

		JsonArray jsMultiArr = null;

		if (fieldDisplay instanceof JsonArray jsArray) {
			jsMultiArr = jsArray;
			displayString = jsArray.getString(0);

		} else if (fieldDisplay instanceof JsonObject jsObj) {
			List<String> keys = jsObj.keyOrderedList();
			jsMultiArr = (JsonArray) jsObj.get(keys.get(0));
		}

		String label = stripLabel(metaString);
		inflateDisplay(jsDisplayBuilder, detail, label, displayString, resolverList, jsMultiArr);
		jsFieldBuilder.add("display", jsDisplayBuilder.build());

		fieldsBuilder.add(fieldName, jsFieldBuilder.build());
	}

	private List<ValueResolverType> getResolversOrListFromDisplay(JsonObjectBuilder jsFieldBuilder,
			String displayString) {
		List<ValueResolverType> resolverList = null;
		if (jsFieldBuilder.getJsonArray("resolver") == null) {
			resolverList = listResolvers(displayString);

			if (!resolverList.isEmpty())
				jsFieldBuilder.add("resolver", inflateResolvers(resolverList));

		} else {
			resolverList = new ArrayList<>();
			for (JsonValue str : jsFieldBuilder.getJsonArray("resolver")) {
				String resolverName = ((JsonString) str).getString();

				resolverList.add(ValueResolverType.valueOf(resolverName));
			}
		}

		return resolverList;
	}

	/**
	 * Sets the ordinal attributes in the form "100+10" and so on.
	 *
	 * @param metaString the new ordinal attributes
	 * @return
	 */
	private String setOrdinalAttributes(String metaString) {
		this.ordinal = 10;
		this.ordinalInc = 10;

		String[] split = metaString.split(";");

		for (String c : split) {
			if (Character.isDigit(c.charAt(0))) {
				split = c.split("\\+");

				ordinal = Integer.parseInt(split[0]);
				if (split.length == 2)
					ordinalInc = Integer.parseInt(split[1]);

				break;
			}
		}

		metaString = metaString.replaceFirst(";[\\d\\+]+", "");

		return metaString;
	}

	/**
	 * Builds the meta.
	 *
	 * @param value      the value
	 * @param jsonObject
	 * @return the json object
	 */
	private void inflateHeader(JsonObjectBuilder top, String metaString, JsonValue jsHeader) {

		if (top.getJsonObject("meta") != null)
			throw new IllegalStateException("header meta resource already defined [%s]"
					.formatted(metaString));

		var displayBuilder = new JsonObjectBuilder();

		metaString = setOrdinalAttributes(metaString);
		top.add("meta", inflateHeaderMeta(metaString));

		String label = stripLabel(metaString);

		if (jsHeader instanceof JsonString jsStringHeader) {

			String displayValue = jsStringHeader.getString();
			inflateDisplay(displayBuilder, null, label, displayValue, Collections.emptyList(), null);

		} else if (jsHeader instanceof JsonObject jsObjHeader) {

			if (jsObjHeader.isPresent("HIDE")) {
				var jsonArr = jsObjHeader.getJsonArray("HIDE");
				displayBuilder.add("HIDE", jsonArr);
			}

			for (String key : jsObjHeader.keyOrderedList()) {
				if (key.equals("HIDE"))
					continue;

				Detail[] detailArray = findDetail(key);
				if (detailArray == null)
					continue;

				final String displayValue;
				JsonArray jsArray = null;
				if (jsObjHeader.isArray(key)) {
					String[] array = jsObjHeader.getJsonArray(key).toStringArray();
					if (array.length > 0) {
						displayValue = array[0];
						array = Arrays.copyOfRange(array, 1, array.length);

					} else {
						displayValue = "";
					}

					jsArray = jsObjHeader.getJsonArray(key);

				} else {
					displayValue = jsObjHeader.getString(key);
				}

				for (Detail detail : detailArray) {
					inflateDisplay(displayBuilder, detail, label, displayValue, Collections.emptyList(), jsArray);
				}
			}

		} else
			throw new IllegalStateException("expecting json object for display");

		top.add("display", displayBuilder.build());
	}

	/**
	 * @param displayBuilder
	 * @param detail
	 * @param displayValue
	 * @param jsMultiArr
	 */
	private void inflateDisplay(JsonObjectBuilder displayBuilder, Detail detail, String label,
			String displayValue,
			List<ValueResolverType> resolverList,
			JsonArray jsMultiArr) {

		if (detail == null) {
			for (Detail d : Detail.values()) {
				if (d == Detail.OFF)
					continue;

				inflateDisplay(displayBuilder, d, label, displayValue, resolverList, jsMultiArr);
			}

			return;
		}

		assert detail != null;

		JsonObjectBuilder detailBuilder = new JsonObjectBuilder();

		detailBuilder.add("label", label);
		detailBuilder.add("detail", detail.name());
		detailBuilder.add("value", inflateDisplayFormat(displayValue, resolverList));
		detailBuilder.add("multiline", jsMultiArr);

		displayBuilder.add(detail.name(), detailBuilder.build());
	}

	private JsonArray inflateResolvers(List<ValueResolverType> resolverList) {
		if (resolverList.isEmpty())
			return null;

		var resolverBuilder = new JsonArrayBuilder();

		for (ValueResolverType valueResolverType : resolverList) {
			resolverBuilder.add(valueResolverType.name());
		}

		return resolverBuilder.build();
	}

	private String fieldName(String metaValue) {
		String c[] = metaValue.split(";");

		return c[0];
	}

	private JsonObject inflateHeaderMeta(String metaValue) {
		String c[] = metaValue.split(";");

		var metaBuilder = new JsonObjectBuilder();
		// We have 'name;abbr' pair
		if (c.length == 2)
			metaBuilder.add("abbr", c[1]);

		// We have 'name' attribute
		if (c.length >= 1)
			metaBuilder.add("name", c[0]);

		return metaBuilder.build();
	}

	private JsonObject inflateFieldMeta(String metaValue) {
		String c[] = metaValue.split(";");

		var metaBuilder = new JsonObjectBuilder();
		// We have 'name;abbr' pair
		if (c.length == 2)
			metaBuilder.add("abbr", c[1]);

		// We have 'name' attribute
		if (c.length >= 1)
			metaBuilder.add("name", c[0]);

		metaBuilder.add("ordinal", ordinal);
		ordinal += ordinalInc;

		return metaBuilder.build();
	}

	private String stripLabel(String line) {
		String c[] = line.split(";");

		return c[c.length - 1];
	}

	private String stripName(String line) {
		String c[] = line.split(";");

		return c[0];
	}

	private static final Pattern RESOLVER_EMBED = Pattern.compile("%\\{:(\\w+)\\}");

	private String inflateDisplayFormat(String line, List<ValueResolverType> resolverList) {

		for (int i = 0; i < resolverList.size(); i++) {
			ValueResolverType rt = resolverList.get(i);

			line = line.replaceAll(":%s".formatted(rt), ":R%d".formatted(i + 1));
		}

		return line;
	}

	private List<ValueResolverType> listResolvers(String line) {
		var matcher = RESOLVER_EMBED.matcher(line);
		var list = new ArrayList<ValueResolverType>();

		while (matcher.find()) {
			String candidate = matcher.group(1);
			if (candidate == null)
				continue;

			ValueResolverType valueResolverType = findResolver(candidate);
			if (valueResolverType == null)
				continue;

			if (!list.contains(valueResolverType)) {
				list.add(valueResolverType);
			}
		}

		return list;
	}

	private Detail[] findDetail(String possibleDetailName) {
		try {
			String[] c = possibleDetailName.split(",");
			List<Detail> detailList = new ArrayList<>();

			for (String detailName : c) {
				detailList.add(Detail.valueOf(detailName));
			}

			return detailList.toArray(Detail[]::new);
		} catch (Throwable e) {
			return null;
		}
	}

	private ValueResolverType findResolver(String resolverName) {
		try {
			return ValueResolverType.valueOf(resolverName);
		} catch (Throwable e) {
			return null;
		}
	}
}
