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
import java.util.Map;

import com.slytechs.jnet.platform.api.util.json.JsonArray;
import com.slytechs.jnet.platform.api.util.json.JsonArrayBuilder;
import com.slytechs.jnet.platform.api.util.json.JsonObject;
import com.slytechs.jnet.platform.api.util.json.JsonValue;
import com.slytechs.jnet.platform.api.util.json.JsonValue.ValueType;
import com.slytechs.jnet.protocol.api.meta.MetaValue.ValueResolver;
import com.slytechs.jnet.protocol.api.meta.Resolver;
import com.slytechs.jnet.protocol.api.meta.Resolvers;
import com.slytechs.jnet.protocol.api.meta.spi.ValueResolverService;

/**
 * The ResolversInfo.
 *
 * @param resolvers a list of value resolvers
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public record ResolversInfo(ValueResolver... resolvers) implements MetaInfoType {

	/**
	 * Parses the.
	 *
	 * @param element      the element
	 * @param name         the name
	 * @param jsonDefaults the json defaults
	 * @return the resolvers info
	 */
	public static ResolversInfo parse(AnnotatedElement element, String name, JsonObject jsonDefaults) {
		JsonValue jsonValue = null;
		if (jsonDefaults != null)
			jsonValue = jsonDefaults.get("resolver");

		if (jsonValue != null)
			return parseJson(jsonValue);

		return parseAnnotations(element);
	}

	/**
	 * Parses the annotations.
	 *
	 * @param element the element
	 * @return the resolvers info
	 */
	private static ResolversInfo parseAnnotations(AnnotatedElement element) {
		Resolvers multiple = element.getAnnotation(Resolvers.class);
		Resolver single = element.getAnnotation(Resolver.class);
		
		var resolversMap = ValueResolverService.cached().getResolvers();

		if (multiple != null) {
			Resolver[] resolversAnnotation = multiple.value();
			ValueResolver[] resolvers = new ValueResolver[resolversAnnotation.length];

			for (int i = 0; i < resolversAnnotation.length; i++)
				resolvers[i] = resolversMap.get(resolversAnnotation[i].value());

			return new ResolversInfo(resolvers);

		} else if (single != null)
			return new ResolversInfo(resolversMap.get(single.value()));

		return new ResolversInfo();
	}

	/**
	 * Parses the json.
	 *
	 * @param jsonValue the json value
	 * @return the resolvers info
	 */
	private static ResolversInfo parseJson(JsonValue jsonValue) {

		JsonArray jsonArray;
		if (jsonValue.getValueType() == ValueType.ARRAY) {
			jsonArray = (JsonArray) jsonValue;
		} else {
			jsonArray = new JsonArrayBuilder()
					.add(jsonValue)
					.build();
		}

		ValueResolver[] resolvers = new ValueResolver[jsonArray.size()];
		Map<String, ValueResolver> serviceResolvers = ValueResolverService.cached().getResolvers();

		for (int i = 0; i < jsonArray.size(); i++) {
			var resolverName = jsonArray.getString(i);
			var resolver = serviceResolvers.get(resolverName);
			resolvers[i] = resolver;
			
//			System.out.printf("resolver=%s, inst=%s%n", resolverName, resolver);
		}
		
//		for (int i = 0; i < jsonArray.size(); i++) {
//			resolvers[i] = Resolver.ResolverType
//					.valueOf(jsonArray.getString(i))
//					.getResolver();
//		}

		return new ResolversInfo(resolvers);

	}
}
