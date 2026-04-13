/*
 * Copyright 2005-2026 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.protocol.core.filter;

/**
 * Checked exception thrown when a packet filter cannot be constructed due to
 * invalid parameters or unsupported filter combinations.
 * <p>
 * {@code FilterException} is thrown at filter construction time (during DSL
 * chain building) rather than at compile or runtime, ensuring that invalid
 * filter configurations are caught as early as possible.
 * </p>
 * <p>
 * Common causes include:
 * <ul>
 *   <li>Out-of-range field values (e.g. VLAN ID > 4095, port > 65535)</li>
 *   <li>Invalid address formats (e.g. wrong byte array length for MAC or IP)</li>
 *   <li>Malformed CIDR notation</li>
 *   <li>Unsupported filter combinations for a specific backend</li>
 * </ul>
 *
 * {@snippet :
 * try {
 *     PacketDsl dsl = PacketFilter.vlan(v -> v.vid(5000));
 * } catch (FilterException e) {
 *     // "VLAN ID must be 0-4095, got: 5000"
 * }
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see PacketFilter
 * @see PacketDsl
 * @see HeaderDsl
 */
public class FilterException extends Exception {

    private static final long serialVersionUID = -2553574393170239644L;

    /**
     * Constructs a new filter exception with the specified detail message.
     *
     * @param message description of the validation error
     */
    public FilterException(String message) {
        super(message);
    }

    /**
     * Constructs a new filter exception with the specified detail message and
     * cause.
     *
     * @param message description of the validation error
     * @param cause   the underlying cause (e.g. a parse error)
     */
    public FilterException(String message, Throwable cause) {
        super(message, cause);
    }
}