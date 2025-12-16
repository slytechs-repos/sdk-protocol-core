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
package com.slytechs.jnet.protocol.api.table;

import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Registry for accessing protocol-specific lookup tables.
 * <p>
 * This singleton class aggregates TableLookup instances from TableProvider
 * implementations discovered via ServiceLoader. It caches tables using
 * WeakReferences to allow garbage collection of unused tables and supports
 * efficient string-based key lookups across various protocol modules.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public final class TableRegistry {

	private static final Logger LOGGER = Logger.getLogger(TableRegistry.class.getName());
	private static final TableRegistry INSTANCE = new TableRegistry();

	/**
	 * Gets the singleton instance of the TableRegistry.
	 *
	 * @return the singleton instance
	 */
	public static TableRegistry getInstance() {
		return INSTANCE;
	}

	private final Map<String, WeakReference<TableLookup>> tableCache = new ConcurrentHashMap<>();
	private final ReferenceQueue<TableLookup> refQueue = new ReferenceQueue<>();
	private final Map<String, TableProvider> providers = new HashMap<>();

	private TableRegistry() {
		// Load all available TableProvider implementations
		ServiceLoader<TableProvider> loader = ServiceLoader.load(TableProvider.class);
		for (TableProvider provider : loader) {
			for (String protocol : provider.getSupportedProtocols()) {
				providers.put(protocol, provider);
			}
		}
	}

	/**
	 * Retrieves the set of supported protocol names.
	 *
	 * @return an unmodifiable set of protocol names
	 */
	public Set<String> getSupportedProtocols() {
		return Collections.unmodifiableSet(providers.keySet());
	}

	/**
	 * Retrieves the set of supported table names for a given protocol.
	 *
	 * @param protocol the protocol name
	 * @return an unmodifiable set of table names, or empty set if protocol is not
	 *         supported
	 */
	public Set<String> getSupportedTables(String protocol) {
		TableProvider provider = providers.get(protocol);
		return provider != null
				? Collections.unmodifiableSet(provider.getSupportedTables(protocol))
				: Collections.emptySet();
	}

	/**
	 * Performs a lookup for the given string key in the specified protocol and
	 * table.
	 *
	 * @param protocol  the protocol name (e.g., "tcpip")
	 * @param tableName the table name (e.g., "ether_type")
	 * @param key       the key to look up (e.g., "0x0800" for EtherType, "00:00:0C"
	 *                  for OUI)
	 * @return the string value associated with the key, or null if not found
	 * @throws TableNotFoundException   if the protocol or table is not supported
	 * @throws IllegalArgumentException if the key format is not supported
	 */
	public StringTableValue lookupString(String protocol, String tableName, String key) {
		return lookupString(protocol, tableName, key, Locale.getDefault());
	}

	/**
	 * Performs a lookup for the given string key in the specified protocol and
	 * table with the specified locale.
	 *
	 * @param protocol  the protocol name (e.g., "tcpip")
	 * @param tableName the table name (e.g., "ether_type")
	 * @param key       the key to look up (e.g., "0x0800" for EtherType, "00:00:0C"
	 *                  for OUI)
	 * @param locale    the locale for the value
	 * @return the string value associated with the key, or null if not found
	 * @throws TableNotFoundException   if the protocol or table is not supported
	 * @throws IllegalArgumentException if the key format is not supported
	 */
	public StringTableValue lookupString(String protocol, String tableName, String key, Locale locale) {
		TableLookup table = getTable(protocol, tableName);
		if (table == null) {
			LOGGER.warning("Table not found: " + protocol + "/" + tableName);
			throw new TableNotFoundException("Table not found: " + protocol + "/" + tableName);
		}
		return table.lookupString(key, locale);
	}

	public TableLookup getTable(String protocol, String tableName) {
		// Clean up stale references
		Reference<? extends TableLookup> stale;
		while ((stale = refQueue.poll()) != null) {
			tableCache.values().remove(stale);
		}

		String cacheKey = protocol + "/" + tableName;
		WeakReference<TableLookup> ref = tableCache.get(cacheKey);
		TableLookup table = ref != null
				? ref.get()
				: null;

		if (table == null) {
			TableProvider provider = providers.get(protocol);
			if (provider == null) {
				return null;
			}
			table = provider.provideTable(protocol, tableName);
			if (table != null) {
				tableCache.put(cacheKey, new WeakReference<>(table, refQueue));
			}
		}

		return table;
	}
}