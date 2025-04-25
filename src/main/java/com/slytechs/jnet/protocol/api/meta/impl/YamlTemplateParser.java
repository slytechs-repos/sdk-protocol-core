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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.yaml.snakeyaml.Yaml;

import com.slytechs.jnet.platform.api.util.format.Detail;

public class YamlTemplateParser implements TemplateParser {

	private static final List<Detail> DETAIL_HIERARCHY = List.of(
			Detail.HEXDUMP,
			Detail.DEBUG,
			Detail.HIGH,
			Detail.MEDIUM,
			Detail.SUMMARY,
			Detail.OFF);

	@Override
	public HeaderTemplate parseResource(String resourcePath) throws IOException {
		try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
			if (is == null) {
				throw new IOException("Resource not found: " + resourcePath);
			}

			try (InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
				return parseHeader(reader);
			}
		}
	}

	@Override
	public HeaderTemplate parseHeader(Reader reader) {
		Yaml yaml = new Yaml();
		Map<String, Object> root = yaml.load(reader);
		return parseHeaderFromMap(root);
	}

	@Override
	public HeaderTemplate parseHeader(String yamlContent) {
		Yaml yaml = new Yaml();
		Map<String, Object> root = yaml.load(yamlContent);
		return parseHeaderFromMap(root);
	}

	@SuppressWarnings("unchecked")
	private HeaderTemplate parseHeaderFromMap(Map<String, Object> root) {
		Map.Entry<String, Object> protocolEntry = root.entrySet().iterator().next();
		String protocolName = protocolEntry.getKey();
		Map<String, Object> protocol = (Map<String, Object>) protocolEntry.getValue();

		Map<String, Object> defaults = (Map<String, Object>) protocol.get("defaults");
		int defaultWidth = ((Number) defaults.getOrDefault("width", 50)).intValue();

		// Parse display template if exists
		String display = (String) protocol.get("display");

		// Parse meta section
		Map<String, String> meta = new HashMap<>();
		if (protocol.containsKey("meta")) {
			Map<String, Object> metaMap = (Map<String, Object>) protocol.get("meta");
			metaMap.forEach((k, v) -> meta.put(k, String.valueOf(v)));
		}

		// Parse templates with inheritance
		Map<String, Object> templates = (Map<String, Object>) protocol.get("templates");
		Map<Detail, DetailTemplate> details = parseDetailTemplates(templates, defaultWidth);

		return new HeaderTemplate(protocolName, details, display, meta);
	}

	@SuppressWarnings("unchecked")
	private Map<Detail, DetailTemplate> parseDetailTemplates(Map<String, Object> templates, int defaultWidth) {
		Map<Detail, DetailTemplate> details = new EnumMap<>(Detail.class);

		// First pass: parse explicitly defined templates
		for (Map.Entry<String, Object> entry : templates.entrySet()) {
			Detail detail = Detail.valueOf(entry.getKey());
			Map<String, Object> template = (Map<String, Object>) entry.getValue();

			String summary = (String) template.get("summary");
			List<FieldTemplate> fields = new ArrayList<>();

			if (template.containsKey("fields")) {
				Object fieldsObj = template.get("fields");
				fields = parseFields(fieldsObj, defaultWidth);
			}

			details.put(detail, new DetailTemplate(summary, fields));
		}

		// Second pass: apply inheritance
		for (Detail detail : DETAIL_HIERARCHY) {
			if (!details.containsKey(detail)) {
				DetailTemplate inherited = findInheritedTemplate(detail, details);
				if (inherited != null) {
					details.put(detail, inherited);
				}
			}
		}

		return details;
	}

	private DetailTemplate findInheritedTemplate(Detail detail, Map<Detail, DetailTemplate> details) {
		// Find the next higher detail level that has a template defined
		int currentIndex = DETAIL_HIERARCHY.indexOf(detail);
		for (int i = currentIndex - 1; i >= 0; i--) {
			Detail higherDetail = DETAIL_HIERARCHY.get(i);
			DetailTemplate template = details.get(higherDetail);
			if (template != null) {
				return template;
			}
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	private List<FieldTemplate> parseFields(Object fieldsObj, int defaultWidth) {
		List<FieldTemplate> fields = new ArrayList<>();

		if (fieldsObj instanceof List) {
			List<Map<String, Object>> fieldsList = (List<Map<String, Object>>) fieldsObj;
			for (Map<String, Object> field : fieldsList) {
				fields.add(createFieldTemplate(field, defaultWidth));
			}
		} else if (fieldsObj instanceof Map) {
			Map<String, Map<String, Object>> fieldsMap = (Map<String, Map<String, Object>>) fieldsObj;
			for (Map.Entry<String, Map<String, Object>> field : fieldsMap.entrySet()) {
				Map<String, Object> fieldProps = new HashMap<>(field.getValue());
				fieldProps.put("name", field.getKey());
				fields.add(createFieldTemplate(fieldProps, defaultWidth));
			}
		}

		return fields;
	}

	private FieldTemplate createFieldTemplate(Map<String, Object> field, int defaultWidth) {
		return new FieldTemplate(
				(String) field.get("name"),
				(String) field.get("label"),
				(String) field.get("template"),
				((Number) field.getOrDefault("width", defaultWidth)).intValue());
	}

	public static void main(String[] args) {
		TemplateParser parser = new YamlTemplateParser();

		try {
			// Load and parse Ethernet template
			TemplateParser.HeaderTemplate ethernet = parser.parseResource("/tcpip/ip4.yaml");
			System.out.println("Loaded " + ethernet.name() + " template:");
			printTemplate(ethernet);

			System.out.println("\n" + "=".repeat(80) + "\n");

			// Load and parse TCP template
			TemplateParser.HeaderTemplate tcp = parser.parseResource("/tcpip/tcp.yaml");
			System.out.println("Loaded " + tcp.name() + " template:");
			printTemplate(tcp);

		} catch (IOException e) {
			System.err.println("Error loading templates: " + e.getMessage());
			e.printStackTrace();
		}
	}

	private static void printTemplate(TemplateParser.HeaderTemplate header) {
		// Print each detail level
		for (Map.Entry<Detail, TemplateParser.DetailTemplate> entry : header.details().entrySet()) {
			Detail detail = entry.getKey();
			TemplateParser.DetailTemplate template = entry.getValue();

			System.out.println("\nDetail Level: " + detail);
			System.out.println("Summary: " + template.summary());

			if (template.fields() != null && !template.fields().isEmpty()) {
				System.out.println("Fields:");
				for (TemplateParser.FieldTemplate field : template.fields()) {
					System.out.printf("  - %s:%n", field.name());
					System.out.printf("      Label: %s%n", field.label());
					System.out.printf("      Template: %s%n", field.template());
					System.out.printf("      Width: %d%n", field.width());
				}
			}
		}
	}
}
