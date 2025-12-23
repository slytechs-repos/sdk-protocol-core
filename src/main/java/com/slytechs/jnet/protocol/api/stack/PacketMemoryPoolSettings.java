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
package com.slytechs.jnet.protocol.api.stack;

import com.slytechs.jnet.core.api.memory.MemoryPoolSettings;
import com.slytechs.jnet.core.api.memory.MemoryUnit;
import com.slytechs.jnet.core.api.settings.IntProperty;

/**
 * Configuration settings for packet memory pools.
 * 
 * <p>
 * PacketMemoryPoolSettings extends {@link MemoryPoolSettings} with packet-specific
 * configuration options. It uses the "capture" domain and base name
 * "packet.memory.pool" while inheriting common pool properties.
 * </p>
 * 
 * <h2>Inherited Properties</h2>
 * <ul>
 * <li><b>size</b> - Total pool size in bytes</li>
 * <li><b>buffer.count</b> - Number of buffers to pre-allocate</li>
 * <li><b>direct</b> - Use direct (off-heap) memory</li>
 * </ul>
 * 
 * <h2>Additional Properties</h2>
 * <ul>
 * <li><b>max.packet.size</b> - Maximum packet size in bytes (default: 9000 for jumbo frames)</li>
 * <li><b>descriptor.size</b> - Size of packet descriptor in bytes (default: 96)</li>
 * </ul>
 * 
 * <h2>Usage Example</h2>
 * <pre>{@code
 * // Load capture defaults from SDK
 * Settings.loadDefaults(Sdk.class.getResourceAsStream("/capture-defaults.properties"), "capture");
 * 
 * // Fluent configuration - specialized properties first, then inherited
 * var settings = new PacketMemoryPoolSettings()
 *     .withMaxPacketSize(16384)           // Specialized property
 *     .withDescriptorSize(128)            // Specialized property  
 *     .withSize(1, MemoryUnit.GIGABYTES)  // Inherited property
 *     .withBufferCount(4096);             // Inherited property
 * 
 * // Use settings to create pool
 * var pool = PacketMemoryPool.create(settings);
 * 
 * // Save all capture settings
 * Settings.save(new File("capture.properties"), "capture");
 * }</pre>
 * 
 * <h2>External Configuration</h2>
 * <pre>
 * # System properties
 * -Dpacket.memory.pool.size=1073741824
 * -Dpacket.memory.pool.max.packet.size=16384
 * 
 * # Environment variables
 * PACKET_MEMORY_POOL_SIZE=1073741824
 * PACKET_MEMORY_POOL_MAX_PACKET_SIZE=16384
 * </pre>
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 * @see MemoryPoolSettings
 */
public final class PacketMemoryPoolSettings extends MemoryPoolSettings {

    /** Default maximum packet size (jumbo frame). */
    private static final int DEFAULT_MAX_PACKET_SIZE = 9000;

    /** Default descriptor size (Net3PacketDescriptor). */
    private static final int DEFAULT_DESCRIPTOR_SIZE = 96;

    /** Maximum packet size in bytes. */
    private final IntProperty maxPacketSize;

    /** Packet descriptor size in bytes. */
    private final IntProperty descriptorSize;

    /**
     * Constructs packet memory pool settings with default values.
     * 
     * <p>
     * Uses domain "capture" and base name "packet.memory.pool" for property resolution.
     * </p>
     */
    public PacketMemoryPoolSettings() {
        super("capture", "packet.memory.pool");
        setComment("Packet memory pool configuration for high-speed capture");
        
        this.maxPacketSize = intProperty("max.packet.size", DEFAULT_MAX_PACKET_SIZE)
            .comment("Maximum packet size in bytes (9000 for jumbo frames)");
        this.descriptorSize = intProperty("descriptor.size", DEFAULT_DESCRIPTOR_SIZE)
            .comment("Packet descriptor size in bytes");
    }

    // =========================================================================
    // Specialized Getters
    // =========================================================================

    /**
     * Returns the maximum packet size in bytes.
     * 
     * <p>
     * This determines the maximum capture length for packets. Common values:
     * </p>
     * <ul>
     * <li>1500 - Standard Ethernet MTU</li>
     * <li>9000 - Jumbo frames (default)</li>
     * <li>16384 - Maximum for some NICs</li>
     * </ul>
     *
     * @return maximum packet size in bytes
     */
    public int maxPacketSize() {
        return maxPacketSize.getInt();
    }

    /**
     * Returns the packet descriptor size in bytes.
     * 
     * <p>
     * The descriptor is stored alongside packet data and contains metadata
     * such as timestamp, capture length, and protocol information.
     * </p>
     *
     * @return descriptor size in bytes
     */
    public int descriptorSize() {
        return descriptorSize.getInt();
    }

    /**
     * Calculates the total slot size (descriptor + max packet).
     *
     * @return total slot size in bytes
     */
    public int slotSize() {
        return descriptorSize() + maxPacketSize();
    }

    // =========================================================================
    // Specialized Fluent Setters
    // =========================================================================

    /**
     * Sets the maximum packet size.
     *
     * @param bytes maximum packet size in bytes
     * @return this settings instance for chaining
     */
    public PacketMemoryPoolSettings withMaxPacketSize(int bytes) {
        maxPacketSize.setInt(bytes);
        return this;
    }

    /**
     * Sets the packet descriptor size.
     *
     * @param bytes descriptor size in bytes
     * @return this settings instance for chaining
     */
    public PacketMemoryPoolSettings withDescriptorSize(int bytes) {
        descriptorSize.setInt(bytes);
        return this;
    }

    // =========================================================================
    // Covariant Overrides for Fluent Chaining
    // =========================================================================

    /**
     * {@inheritDoc}
     * 
     * @return this settings instance for chaining
     */
    @Override
    public PacketMemoryPoolSettings withSize(long bytes) {
        super.withSize(bytes);
        return this;
    }

    /**
     * {@inheritDoc}
     * 
     * @return this settings instance for chaining
     */
    @Override
    public PacketMemoryPoolSettings withSize(long value, MemoryUnit unit) {
        super.withSize(value, unit);
        return this;
    }

    /**
     * {@inheritDoc}
     * 
     * @return this settings instance for chaining
     */
    @Override
    public PacketMemoryPoolSettings withBufferCount(int count) {
        super.withBufferCount(count);
        return this;
    }

    /**
     * {@inheritDoc}
     * 
     * @return this settings instance for chaining
     */
    @Override
    public PacketMemoryPoolSettings withDirect(boolean direct) {
        super.withDirect(direct);
        return this;
    }
}