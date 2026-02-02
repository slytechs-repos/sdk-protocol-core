/*
 * Sly Technologies Free License
 * 
 * Copyright 2025 Sly Technologies Inc.
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
package com.slytechs.sdk.protocol.core.header;

import com.slytechs.sdk.common.detail.Detailable;

/**
 * Common interface for protocol header options containers.
 * 
 * <p>
 * Provides access to the options area of a protocol header (e.g., TCP options,
 * IPv4 options). Options are variable-length fields that follow the fixed
 * portion of the header.
 * </p>
 * 
 * <h2>Design Principles</h2>
 * <ul>
 * <li><strong>Zero-allocation:</strong> Pre-allocated option instances are
 * reused</li>
 * <li><strong>Lazy parsing:</strong> Options are parsed on first access</li>
 * <li><strong>Type-safe iteration:</strong> Iterator provides typed option
 * access</li>
 * </ul>
 * 
 * <h2>Usage Example</h2>
 * <pre>{@code
 * HeaderOptions<TcpOption> opts = tcp.options();
 * 
 * // Check presence
 * if (opts.hasOption(TcpOptions.MSS)) {
 *     TcpOption opt = opts.option(TcpOptions.MSS);
 * }
 * 
 * // Iterate all options
 * for (TcpOption opt : opts) {
 *     System.out.println(opt.optionName());
 * }
 * }</pre>
 *
 * @param <O> the option type
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 * @see HeaderOption
 */
public interface HeaderOptions<O extends HeaderOption> extends Iterable<O>, Detailable {

    /**
     * Returns the number of options present.
     * 
     * @return option count
     */
    int count();

    /**
     * Checks if an option with the specified ID is present.
     * 
     * @param id the option identifier
     * @return true if option is present
     */
    boolean hasOption(int id);

    /**
     * Returns the option instance for the specified ID.
     * 
     * <p>
     * Returns the pre-allocated option instance regardless of presence. Use
     * {@link #hasOption(int)} or {@link HeaderOption#isPresent()} to check if
     * the option exists in the current packet.
     * </p>
     * 
     * @param id the option identifier
     * @return the option instance, or null if ID is not recognized
     */
    O option(int id);

    /**
     * Returns the total length of all options in bytes.
     * 
     * @return total options length
     */
    default long totalLength() {
        long total = 0;
        for (O opt : this) {
            total += opt.optionLength();
        }
        return total;
    }

    /**
     * Checks if any options are present.
     * 
     * @return true if at least one option exists
     */
    default boolean hasOptions() {
        return count() > 0;
    }
}