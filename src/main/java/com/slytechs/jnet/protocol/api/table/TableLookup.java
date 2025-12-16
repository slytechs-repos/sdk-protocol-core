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

import java.util.Locale;
import java.util.Optional;

/**
 * Interface for accessing protocol-specific lookup tables.
 * <p>
 * Provides methods to perform string-based key lookups, retrieve table
 * metadata, and support locale-specific value retrieval for multilingual
 * support. Implementations are typically provided by protocol modules via the
 * TableProvider SPI.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public interface TableLookup {

	/**
	 * Retrieves the protocol name associated with this table.
	 *
	 * @return the protocol name (e.g., "tcpip", "web")
	 */
	String getProtocol();

	/**
	 * Retrieves the name of this table.
	 *
	 * @return the table name (e.g., "ether_type", "oui")
	 */
	String getTableName();

	/**
	 * Performs a lookup for the given string key, returning a string-based value.
	 *
	 * @param key the key to look up (e.g., "0x0800" for EtherType, "00:00:0C" for
	 *            OUI)
	 * @return the string value associated with the key, or null if not found
	 * @throws IllegalArgumentException if the key format is not supported
	 */
	StringTableValue lookupString(String key);

	default StringTableValue lookupString(int key) {
		return lookupString(Integer.toString(key));
	}

	/**
	 * Performs a lookup for the given string key with the specified locale,
	 * returning a string-based value.
	 *
	 * @param key    the key to look up (e.g., "0x0800" for EtherType, "00:00:0C"
	 *               for OUI)
	 * @param locale the locale for the value (e.g., for multilingual descriptions)
	 * @return the string value associated with the key, or null if not found
	 * @throws IllegalArgumentException if the key format is not supported
	 */
	StringTableValue lookupString(String key, Locale locale);

	default StringTableValue lookupString(int key, Locale locale) {
		return lookupString(Integer.toString(key), locale);
	}

	/**
	 * Performs a lookup for the given string key with the specified locale,
	 * returning a string-based value.
	 *
	 * @param key    the key to look up (e.g., "0x0800" for EtherType, "00:00:0C"
	 *               for OUI)
	 * @param locale the locale for the value (e.g., for multilingual descriptions)
	 * @return the string value associated with the key, or empty optional if not
	 *         found
	 * @throws IllegalArgumentException if the key format is not supported
	 */
	default Optional<StringTableValue> findString(String key, Locale locale) {
		return Optional.ofNullable(lookupString(key, locale));
	}

}