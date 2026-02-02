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
package com.slytechs.sdk.protocol.core.spi;

import java.util.Objects;
import java.util.ServiceLoader;
import java.util.ServiceLoader.Provider;

import com.slytechs.sdk.protocol.core.id.ProtocolIds;
import com.slytechs.sdk.protocol.core.stack.ProtocolConfig;

/**
 * SPI provider for protocol configuration creation.
 * 
 * <p>
 * Protocol packs (sdk-protocol-tcpip, sdk-protocol-web, etc.) implement this
 * interface to provide protocol configurations. Discovery happens at the pack
 * level, not per-protocol, to avoid unnecessary class loading.
 * </p>
 * 
 * <h2>Implementation Example</h2>
 * <pre>{@code
 * public class TcpIpProtocolConfigProvider implements ProtocolConfigProvider {
 *     
 *     static {
 *         // Load pack defaults
 *         loadDefaults("/tcpip-protocol-defaults.properties");
 *     }
 *     
 *     @Override
 *     public int packId() {
 *         return ProtocolIds.PACK_TCPIP;
 *     }
 *     
 *     @Override
 *     public String packName() {
 *         return "tcpip";
 *     }
 *     
 *     @Override
 *     public <T extends ProtocolConfig> T findConfig(Class<T> type) {
 *         if (type == IpProtocolConfig.class) return type.cast(new IpProtocolConfig());
 *         if (type == TcpProtocolConfig.class) return type.cast(new TcpProtocolConfig());
 *         return null;
 *     }
 *     
 *     @Override
 *     public ProtocolConfig findConfig(int protocolId) {
 *         int index = ProtocolIds.indexOf(protocolId);
 *         return switch (index) {
 *             case 0x21 -> new IpProtocolConfig();   // IPv4
 *             case 0x40 -> new TcpProtocolConfig();  // TCP
 *             default -> null;
 *         };
 *     }
 * }
 * }</pre>
 * 
 * <h2>Service Registration</h2>
 * <p>
 * Create file: {@code META-INF/services/com.slytechs.sdk.protocol.core.spi.ProtocolConfigProvider}
 * </p>
 * <pre>
 * com.slytechs.sdk.protocol.tcpip.spi.TcpIpProtocolConfigProvider
 * </pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see ProtocolConfig
 */
public interface ProtocolConfigProvider {

    /** Service loader for discovering providers. */
    ServiceLoader<ProtocolConfigProvider> SERVICE = 
            ServiceLoader.load(ProtocolConfigProvider.class);

    // =========================================================================
    // Static Lookup Methods
    // =========================================================================

    /**
     * Creates a protocol configuration by class.
     * 
     * <p>
     * Iterates through all registered providers until one can create the
     * requested configuration type.
     * </p>
     *
     * @param <T>  the config type
     * @param type the config class
     * @return the configuration, or null if no provider supports it
     */
    static <T extends ProtocolConfig> T createConfig(Class<T> type) {
        Objects.requireNonNull(type, "type");
        
        return SERVICE.stream()
                .map(Provider::get)
                .map(provider -> provider.findConfig(type))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    /**
     * Creates a protocol configuration by protocol ID.
     * 
     * <p>
     * Routes to the correct provider based on pack ID encoded in the
     * protocol ID.
     * </p>
     *
     * @param protocolId the protocol ID
     * @return the configuration, or null if no provider supports it
     */
    static ProtocolConfig createConfig(int protocolId) {
        int packId = ProtocolIds.packId(protocolId);
        
        return SERVICE.stream()
                .map(Provider::get)
                .filter(provider -> provider.packId() == packId)
                .map(provider -> provider.findConfig(protocolId))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    /**
     * Reloads all providers.
     * 
     * <p>
     * Call this after dynamically adding protocol pack modules to the
     * classpath/modulepath.
     * </p>
     */
    static void reload() {
        SERVICE.reload();
    }

    // =========================================================================
    // Provider Instance Methods
    // =========================================================================

    /**
     * Gets the pack ID this provider handles.
     * 
     * <p>
     * ProtocolPack IDs are defined in {@link ProtocolIds}:
     * <ul>
     * <li>{@code PACK_TCPIP = 0x0200}</li>
     * <li>{@code PACK_WEB = 0x0300}</li>
     * <li>{@code PACK_INFRA = 0x0100}</li>
     * <li>{@code PACK_TELCO = 0x0400}</li>
     * </ul>
     *
     * @return the pack ID
     */
    int packId();

    /**
     * Gets the human-readable pack name.
     *
     * @return the pack name (e.g., "tcpip", "web", "telco")
     */
    String packName();

    /**
     * Finds a protocol configuration by class.
     *
     * @param <T>  the config type
     * @param type the config class
     * @return the configuration, or null if not supported by this provider
     */
    <T extends ProtocolConfig> T findConfig(Class<T> type);

    /**
     * Finds a protocol configuration by protocol ID.
     *
     * @param protocolId the protocol ID
     * @return the configuration, or null if not supported by this provider
     */
    ProtocolConfig findConfig(int protocolId);

    /**
     * Checks if this provider supports a configuration class.
     *
     * @param type the config class
     * @return true if supported
     */
    default boolean supports(Class<? extends ProtocolConfig> type) {
        return findConfig(type) != null;
    }

    /**
     * Checks if this provider supports a protocol ID.
     *
     * @param protocolId the protocol ID
     * @return true if supported
     */
    default boolean supports(int protocolId) {
        return ProtocolIds.packId(protocolId) == packId();
    }
}