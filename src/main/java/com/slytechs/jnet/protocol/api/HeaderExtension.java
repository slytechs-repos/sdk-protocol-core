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
package com.slytechs.jnet.protocol.api;

import com.slytechs.jnet.core.api.detail.DetailBuilder;

/**
 * Common interface for protocol header extensions.
 * 
 * <p>
 * Represents an individual extension header that follows a base protocol header
 * (e.g., IPv6 extension headers, 802.3 LLC/SNAP). Extensions are separate
 * protocol entities that extend the functionality of the base header.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 * @see HeaderExtensions
 */
public interface HeaderExtension {

    /**
     * Returns the extension identifier (Next Header value for IPv6, type for
     * others).
     * 
     * @return the extension identifier
     */
    int extensionId();

    /**
     * Returns the offset of this extension within the extensions area.
     * 
     * @return offset in bytes from start of extensions area
     */
    int extensionOffset();

    /**
     * Returns the total length of this extension header.
     * 
     * @return extension length in bytes
     */
    int extensionLength();

    /**
     * Checks if this extension is present in the current packet.
     * 
     * @return true if extension is present
     */
    boolean isPresent();

    /**
     * Returns the human-readable name of this extension.
     * 
     * @return extension name
     */
    String extensionName();

    /**
     * Builds detailed output for this extension.
     * 
     * @param h the header builder to populate
     */
    void buildDetail(DetailBuilder.HeaderBuilder h);
}