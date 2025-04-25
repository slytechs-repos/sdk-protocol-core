/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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

import java.io.IOException;
import java.io.Reader;
import java.util.List;
import java.util.Map;

import com.slytechs.jnet.platform.api.util.format.Detail;

public interface TemplateParser {

	record HeaderTemplate(
			String name,
			Map<Detail, DetailTemplate> details,
			String display,
			Map<String, String> meta) {}

	record DetailTemplate(
			String summary,
			List<FieldTemplate> fields) {}

	record FieldTemplate(
			String name,
			String label,
			String template,
			int width) {}

	/**
	 * Parse header template from a classpath resource
	 * 
	 * @param resourcePath path to the resource (e.g., "/templates/ethernet.yml")
	 * @return parsed HeaderTemplate
	 * @throws IOException if resource cannot be read
	 */
	HeaderTemplate parseResource(String resourcePath) throws IOException;

	/**
	 * Parse header template from a Reader
	 */
	HeaderTemplate parseHeader(Reader reader);

	/**
	 * Parse header template from a String
	 */
	HeaderTemplate parseHeader(String content);
}