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
 * Common interface for protocol header options.
 * 
 * <p>
 * Represents an individual option within a header's options area (e.g., TCP
 * options, IPv4 options). Options are variable-length fields that provide
 * additional protocol functionality beyond the fixed header fields.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 * @see HeaderOptions
 */
public interface HeaderOption {

    /**
     * Returns the option type/kind identifier.
     * 
     * @return the option identifier (0-255)
     */
    int optionId();

    /**
     * Returns the offset of this option within the options area.
     * 
     * @return offset in bytes from start of options area
     */
    int optionOffset();

    /**
     * Returns the total length of this option including type and length bytes.
     * 
     * @return option length in bytes
     */
    int optionLength();

    /**
     * Checks if this option is present in the current packet.
     * 
     * @return true if option is present
     */
    boolean isPresent();

    /**
     * Returns the human-readable name of this option.
     * 
     * @return option name
     */
    String optionName();
    
    String optionAbbr();

    /**
     * Builds detailed output for this option.
     * 
     * @param h the header builder to populate
     */
    void buildDetail(DetailBuilder.HeaderBuilder h);
}