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

import java.util.Set;

/**
 * Service Provider Interface (SPI) for providing protocol-specific lookup tables.
 * <p>
 * Implementations of this interface are discovered via ServiceLoader and provide
 * TableLookup instances for specific protocols and table names. Protocol modules
 * (e.g., protocol-tcpip, protocol-web) implement this interface to contribute
 * lookup tables.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public interface TableProvider {

    /**
     * Retrieves the set of protocol names supported by this provider.
     *
     * @return the set of supported protocol names (e.g., "tcpip", "web")
     */
    Set<String> getSupportedProtocols();

    /**
     * Retrieves the set of table names supported for a given protocol.
     *
     * @param protocol the protocol name
     * @return the set of table names available for the protocol, or empty set if none
     */
    Set<String> getSupportedTables(String protocol);

    /**
     * Provides a TableLookup instance for the specified protocol and table name.
     *
     * @param protocol  the protocol name (e.g., "tcpip")
     * @param tableName the table name (e.g., "ether_type")
     * @return a TableLookup instance, or null if not supported
     */
    TableLookup provideTable(String protocol, String tableName);
}