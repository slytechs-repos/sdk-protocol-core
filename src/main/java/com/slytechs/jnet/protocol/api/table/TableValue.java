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

/**
 * Marker interface for values returned from table lookups.
 * <p>
 * Implementations of this interface represent values retrieved from lookup tables,
 * such as protocol descriptions (e.g., "Internet Protocol version 4 (IPv4)") or
 * vendor names for MAC OUI lookups. This ensures type safety in table operations.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public interface TableValue {

    /**
     * Returns the string representation of the value.
     * <p>
     * Implementations should provide a meaningful string representation, especially
     * for display or logging purposes.
     * </p>
     *
     * @return the string representation of the value
     */
    String asString();
}