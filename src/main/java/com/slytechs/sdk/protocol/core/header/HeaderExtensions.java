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

/**
 * Common interface for protocol header extensions containers.
 * 
 * <p>
 * Provides access to extension headers that follow a base protocol header
 * (e.g., IPv6 extension headers, 802.3 LLC/SNAP). Extensions are separate
 * protocol entities chained after the base header.
 * </p>
 * 
 * <h2>Design Principles</h2>
 * <ul>
 * <li><strong>Zero-allocation:</strong> Pre-allocated extension instances are
 * reused</li>
 * <li><strong>Lazy parsing:</strong> Extensions are parsed on first access</li>
 * <li><strong>Type-safe iteration:</strong> Iterator provides typed extension
 * access</li>
 * </ul>
 * 
 * <h2>Usage Example</h2>
 * 
 * <pre>{@code
 * HeaderExtensions<Ip6Extension> exts = ip6.extensions();
 * 
 * // Check presence
 * if (exts.hasExtension(Ip6Extensions.FRAGMENT)) {
 * 	Ip6Extension ext = exts.extension(Ip6Extensions.FRAGMENT);
 * }
 * 
 * // Iterate all extensions
 * for (Ip6Extension ext : exts) {
 * 	System.out.println(ext.extensionName());
 * }
 * }</pre>
 *
 * @param <E> the extension type
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 * @see HeaderExtension
 */
public interface HeaderExtensions<E extends HeaderExtension> extends Iterable<E> {

	/**
	 * Returns the number of extensions present.
	 * 
	 * @return extension count
	 */
	int count();

	/**
	 * Checks if an extension with the specified ID is present.
	 * 
	 * @param id the extension identifier
	 * @return true if extension is present
	 */
	boolean hasExtension(int id);

	/**
	 * Returns the extension instance for the specified ID.
	 * 
	 * <p>
	 * Returns the pre-allocated extension instance regardless of presence. Use
	 * {@link #hasExtension(int)} or {@link HeaderExtension#isPresent()} to check if
	 * the extension exists in the current packet.
	 * </p>
	 * 
	 * @param id the extension identifier
	 * @return the extension instance, or null if ID is not recognized
	 */
	E extension(int id);

	/**
	 * Returns the total length of all extensions in bytes.
	 * 
	 * @return total extensions length
	 */
	default long totalLength() {
		long total = 0;
		for (E ext : this) {
			total += ext.extensionLength();
		}
		return total;
	}

	/**
	 * Checks if any extensions are present.
	 * 
	 * @return true if at least one extension exists
	 */
	default boolean hasExtensions() {
		return count() > 0;
	}

}