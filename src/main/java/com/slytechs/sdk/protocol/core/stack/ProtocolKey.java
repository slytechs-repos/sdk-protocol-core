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
package com.slytechs.sdk.protocol.core.stack;

/**
 * Key for looking up protocol configurations by type and depth.
 * 
 * <p>
 * Protocol depth allows different configurations for the same protocol at
 * different encapsulation levels. For example, outer IP (depth 0) and inner
 * IP after a GRE tunnel (depth 1) can have different reassembly settings.
 * </p>
 * 
 * <h2>Depth Examples</h2>
 * <pre>
 * Eth → IP → TCP                    : IP at depth 0
 * Eth → IP → GRE → IP → TCP         : Outer IP at depth 0, inner IP at depth 1
 * Eth → IP → GRE → IP → GRE → IP    : IPs at depths 0, 1, 2
 * </pre>
 *
 * @param type  the protocol configuration class
 * @param depth the encapsulation depth (0 = outermost)
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public record ProtocolKey(Class<? extends ProtocolConfig> type, int depth) {
    
    /**
     * Creates a key for depth 0 (outermost/default).
     *
     * @param type the protocol configuration class
     * @return key for depth 0
     */
    public static ProtocolKey of(Class<? extends ProtocolConfig> type) {
        return new ProtocolKey(type, 0);
    }
    
    /**
     * Creates a key for a specific depth.
     *
     * @param type  the protocol configuration class
     * @param depth the encapsulation depth
     * @return key for specified depth
     */
    public static ProtocolKey of(Class<? extends ProtocolConfig> type, int depth) {
        return new ProtocolKey(type, depth);
    }
}