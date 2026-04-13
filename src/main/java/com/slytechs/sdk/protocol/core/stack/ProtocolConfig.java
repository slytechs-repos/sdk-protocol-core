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

import com.slytechs.sdk.common.settings.BooleanProperty;
import com.slytechs.sdk.common.settings.Settings;

/**
 * Base class for protocol configuration in the protocol stack.
 * 
 * <p>
 * ProtocolConfig provides the Settings-based configuration foundation for all
 * protocol-specific configurations. Each protocol (IP, TCP, TLS, etc.) extends
 * this class to define its own configuration properties with layered resolution.
 * </p>
 * 
 * <h2>Configuration Resolution Order</h2>
 * <ol>
 * <li>Explicit value (fluent setter method)</li>
 * <li>System property: {@code -Dprotocol.<name>.<property>=value}</li>
 * <li>Environment variable: {@code PROTOCOL_<NAME>_<PROPERTY>=value}</li>
 * <li>Loaded configuration file</li>
 * <li>ProtocolPack defaults (from protocol pack JAR)</li>
 * <li>Coded default value</li>
 * </ol>
 * 
 * <h2>Usage Example</h2>
 * <pre>{@code
 * // Define a protocol configuration
 * public class IpProtocolConfig extends ProtocolConfig {
 *     
 *     private final BooleanProperty reassemblyEnabled;
 *     private final IntProperty fragmentTimeout;
 *     
 *     public IpProtocolConfig() {
 *         super("ip");
 *         this.reassemblyEnabled = booleanProperty("reassembly.enabled", false);
 *         this.fragmentTimeout = intProperty("reassembly.timeout", 30);
 *     }
 *     
 *     public IpProtocolConfig enableReassembly(boolean enable) {
 *         reassemblyEnabled.setBoolean(enable);
 *         return this;
 *     }
 * }
 * 
 * // Use in protocol stack
 * stack.setProtocol(new IpProtocolConfig())
 *      .enableReassembly(true)
 *      .fragmentTimeout(60);
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Settings
 * @see ProtocolStack
 */
public abstract class ProtocolConfig extends Settings {

    /** Property: whether this protocol is enabled. */
    private final BooleanProperty enabled;
    
    /** Property: whether to decapsulate (strip) this protocol layer. */
    private final BooleanProperty decap;

    /**
     * Constructs a new protocol configuration with the given base name.
     * 
     * <p>
     * The base name is used to construct property names. For example, a base
     * name of "ip" results in properties like "protocol.ip.enabled".
     * </p>
     *
     * @param baseName the protocol base name (e.g., "ip", "tcp", "tls")
     */
    protected ProtocolConfig(String baseName) {
        super("protocol", baseName);
        
        this.enabled = booleanProperty("enabled", true)
                .comment("Whether this protocol is enabled for processing");
        
        this.decap = booleanProperty("decap", false)
                .comment("Whether to decapsulate (strip) this protocol layer");
    }

    /**
     * Enables or disables this protocol.
     * 
     * <p>
     * When disabled, the processor for this protocol will be skipped during
     * packet processing.
     * </p>
     *
     * @param enable true to enable, false to disable
     * @return this config for method chaining
     */
    public ProtocolConfig enabled(boolean enable) {
        this.enabled.setBoolean(enable);
        return this;
    }

    /**
     * Checks if this protocol is enabled.
     *
     * @return true if enabled
     */
    public boolean isEnabled() {
        return enabled.getBoolean();
    }

    /**
     * Enables decapsulation for this protocol.
     * 
     * <p>
     * When decap is enabled, this protocol layer is stripped from packets,
     * presenting downstream processors with the inner payload as if the
     * encapsulation was not present. Useful for VLAN, GRE, MPLS, etc.
     * </p>
     *
     * @return this config for method chaining
     */
    public ProtocolConfig decap() {
        this.decap.setBoolean(true);
        return this;
    }

    /**
     * Sets decapsulation mode.
     *
     * @param decap true to enable decapsulation
     * @return this config for method chaining
     */
    public ProtocolConfig decap(boolean decap) {
        this.decap.setBoolean(decap);
        return this;
    }

    /**
     * Checks if decapsulation is enabled.
     *
     * @return true if decap enabled
     */
    public boolean isDecap() {
        return decap.getBoolean();
    }
}