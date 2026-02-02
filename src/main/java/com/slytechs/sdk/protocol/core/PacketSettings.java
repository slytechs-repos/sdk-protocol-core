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
package com.slytechs.sdk.protocol.core;

import com.slytechs.sdk.common.memory.pool.PoolSettings;
import com.slytechs.sdk.common.settings.BooleanProperty;
import com.slytechs.sdk.common.settings.IntProperty;
import com.slytechs.sdk.common.settings.Settings;
import com.slytechs.sdk.protocol.core.descriptor.DescriptorType;
import com.slytechs.sdk.protocol.core.descriptor.HeaderBinding;

/**
 * Configuration settings for the packet pipeline.
 * 
 * <p>
 * PacketSettings controls how packets are processed in the capture pipeline,
 * including dissection strategy, descriptor type, and memory management. The
 * settings determine whether packets use zero-copy memory, hybrid memory (scoped
 * data with fixed descriptors), and how protocol headers are dissected.
 * </p>
 * 
 * <h2>Dissection Modes</h2>
 * 
 * <p>
 * Three dissection modes are available, selected via fluent methods:
 * </p>
 * 
 * <table>
 * <caption>Dissection Modes</caption>
 * <tr>
 * <th>Method</th>
 * <th>Descriptor</th>
 * <th>Memory Model</th>
 * <th>Description</th>
 * </tr>
 * <tr>
 * <td>{@link #dissect()}</td>
 * <td>TYPE2</td>
 * <td>Hybrid</td>
 * <td>Eager dissection, full header table in descriptor</td>
 * </tr>
 * <tr>
 * <td>{@link #dissectOnDemand()}</td>
 * <td>PCAP</td>
 * <td>Zero-copy</td>
 * <td>Lazy dissection on {@code hasHeader()} calls</td>
 * </tr>
 * <tr>
 * <td>{@link #noDissection()}</td>
 * <td>PCAP</td>
 * <td>Zero-copy</td>
 * <td>No dissection, L2 access only via DLT</td>
 * </tr>
 * </table>
 * 
 * <h2>Memory Models</h2>
 * 
 * <ul>
 * <li><b>Zero-copy:</b> Both packet data and descriptor use {@code ScopedMemory}
 *     bound directly to native capture buffers. Maximum performance, but packets
 *     are only valid within the capture callback scope.</li>
 * <li><b>Hybrid:</b> Packet data uses {@code ScopedMemory} (zero-copy), while
 *     the descriptor uses {@code FixedMemory} from an internal pool. Required
 *     for eager dissection since the TYPE2 descriptor stores dissection results.</li>
 * </ul>
 * 
 * <h2>Usage Examples</h2>
 * 
 * <h3>Default Configuration (Eager Dissection)</h3>
 * <pre>{@code
 * PacketSettings settings = new PacketSettings();
 * // Defaults: dissect() mode, TYPE2 descriptor, hybrid memory
 * 
 * try (NetPcap pcap = NetPcap.openOffline(file, settings)) {
 *     pcap.dispatch(10, packet -> {
 *         if (packet.hasHeader(tcp)) {
 *             System.out.println(tcp.srcPort());
 *         }
 *     });
 * }
 * }</pre>
 * 
 * <h3>High-Performance Zero-Copy</h3>
 * <pre>{@code
 * PacketSettings settings = new PacketSettings()
 *     .dissectOnDemand();  // Zero-copy, lazy dissection
 * 
 * try (NetPcap pcap = NetPcap.openOffline(file, settings)) {
 *     pcap.dispatch(10, packet -> {
 *         // Dissection happens here, on demand
 *         if (packet.hasHeader(ip4)) {
 *             System.out.println(ip4.src());
 *         }
 *     });
 * }
 * }</pre>
 * 
 * <h3>Raw Packet Access</h3>
 * <pre>{@code
 * PacketSettings settings = new PacketSettings()
 *     .noDissection();  // Zero-copy, no dissection
 * 
 * try (NetPcap pcap = NetPcap.openOffline(file, settings)) {
 *     pcap.dispatch(10, packet -> {
 *         // Only L2 frame type available
 *         System.out.println(packet.captureLength());
 *     });
 * }
 * }</pre>
 * 
 * <h3>Custom Pool Configuration</h3>
 * <pre>{@code
 * PacketSettings settings = new PacketSettings()
 *     .dissect()
 *     .poolSettings(new PoolSettings()
 *         .minCapacity(1000)
 *         .maxCapacity(10000));
 * }</pre>
 * 
 * <h2>Property Resolution</h2>
 * <p>
 * PacketSettings extends {@link Settings}, providing layered property resolution:
 * </p>
 * <ol>
 * <li>Explicit value set programmatically</li>
 * <li>System property: {@code -Dpacket.<property>=value}</li>
 * <li>Environment variable: {@code PACKET_<PROPERTY>=value}</li>
 * <li>Configuration file</li>
 * <li>Coded default</li>
 * </ol>
 * 
 * <h2>Configuration File</h2>
 * <pre>
 * # Packet pipeline settings
 * packet.dissection.eager=true
 * packet.dissection.ondemand=false
 * packet.descriptor.maxHeaders=16
 * </pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Packet
 * @see PoolSettings
 * @see HeaderBinding
 */
public class PacketSettings extends Settings {

    public static final String DOMAIN = "packet";
    public static final String BASE_NAME = "packet";

    private final BooleanProperty eagerDissection;
    private final BooleanProperty onDemandDissection;
    private final IntProperty maxHeaderCount;

    private PoolSettings poolSettings;
    private HeaderBinding headerBinding;

    /**
     * Creates packet settings with default configuration.
     * 
     * <p>
     * Defaults to eager dissection mode ({@link #dissect()}) with TYPE2 descriptor
     * and hybrid memory model.
     * </p>
     */
    public PacketSettings() {
        super(DOMAIN, BASE_NAME);
        setComment("Packet pipeline configuration");

        this.eagerDissection = booleanProperty("dissection.eager", true)
                .comment("Enable eager protocol dissection into TYPE2 descriptor");

        this.onDemandDissection = booleanProperty("dissection.ondemand", false)
                .comment("Enable on-demand dissection via HeaderBinding");

        this.maxHeaderCount = intProperty("descriptor.maxHeaders", 16)
                .comment("Maximum headers stored in TYPE2 descriptor table");

        this.poolSettings = new PoolSettings();
        this.headerBinding = null;
    }

    /**
     * Enables eager dissection mode.
     * 
     * <p>
     * In this mode, packets are fully dissected immediately upon receipt. The
     * dissection results are stored in a {@link DescriptorType#TYPE2} descriptor,
     * which requires hybrid memory (scoped data + fixed descriptor from pool).
     * </p>
     * 
     * <p>
     * This is the default mode and provides the fastest header access since
     * dissection is already complete when {@code hasHeader()} is called.
     * </p>
     *
     * @return this settings instance for method chaining
     */
    public PacketSettings dissect() {
        this.eagerDissection.setBoolean(true);
        this.onDemandDissection.setBoolean(false);
        return this;
    }

    /**
     * Enables on-demand dissection mode.
     * 
     * <p>
     * In this mode, the eager dissector is disabled and packets use the native
     * PCAP descriptor with zero-copy memory. A {@link HeaderBinding} is installed
     * that triggers dissection lazily when {@code hasHeader()} is called for
     * protocols beyond L2.
     * </p>
     * 
     * <p>
     * This mode is ideal for filtering scenarios where only a subset of packets
     * need full dissection, or when maximum zero-copy performance is required.
     * </p>
     *
     * @return this settings instance for method chaining
     */
    public PacketSettings dissectOnDemand() {
        this.eagerDissection.setBoolean(false);
        this.onDemandDissection.setBoolean(true);
        return this;
    }

    /**
     * Disables all dissection.
     * 
     * <p>
     * In this mode, no protocol dissection is performed. Packets use the native
     * PCAP descriptor with zero-copy memory. Only L2 frame type information is
     * available via the data link type (DLT).
     * </p>
     * 
     * <p>
     * This mode provides maximum performance for scenarios where only raw packet
     * data is needed, such as packet capture to file or simple byte-level analysis.
     * </p>
     *
     * @return this settings instance for method chaining
     */
    public PacketSettings noDissection() {
        this.eagerDissection.setBoolean(false);
        this.onDemandDissection.setBoolean(false);
        return this;
    }

    /**
     * Sets the pool settings for descriptor memory allocation.
     * 
     * <p>
     * These settings control the internal descriptor pool used in eager dissection
     * mode ({@link #dissect()}). The pool provides fixed memory for TYPE2 descriptors
     * in the hybrid memory model.
     * </p>
     * 
     * <p>
     * In zero-copy modes ({@link #dissectOnDemand()} and {@link #noDissection()}),
     * these settings are ignored since no descriptor pool is needed.
     * </p>
     *
     * @param poolSettings the pool configuration
     * @return this settings instance for method chaining
     */
    public PacketSettings poolSettings(PoolSettings poolSettings) {
        this.poolSettings = poolSettings != null ? poolSettings : new PoolSettings();
        return this;
    }

    /**
     * Sets a custom header binding for on-demand dissection.
     * 
     * <p>
     * The header binding is invoked when {@code hasHeader()} is called for protocols
     * beyond L2 in on-demand dissection mode. This allows custom dissector injection
     * for specialized protocol handling.
     * </p>
     * 
     * <p>
     * If not set, the default on-demand dissector is used when
     * {@link #dissectOnDemand()} is enabled.
     * </p>
     *
     * @param headerBinding the custom header binding, or null for default
     * @return this settings instance for method chaining
     */
    public PacketSettings headerBinding(HeaderBinding headerBinding) {
        this.headerBinding = headerBinding;
        return this;
    }

    /**
     * Sets the maximum number of headers stored in the descriptor.
     * 
     * <p>
     * This setting applies to the TYPE2 descriptor used in eager dissection mode.
     * It limits the size of the protocol header table in the descriptor.
     * </p>
     *
     * @param count maximum header count
     * @return this settings instance for method chaining
     */
    public PacketSettings maxHeaderCount(int count) {
        this.maxHeaderCount.setInt(count);
        return this;
    }

    /**
     * Checks if eager dissection is enabled.
     *
     * @return true if eager dissection mode is active
     */
    public boolean isEagerDissection() {
        return eagerDissection.getBoolean();
    }

    /**
     * Checks if on-demand dissection is enabled.
     *
     * @return true if on-demand dissection mode is active
     */
    public boolean isOnDemandDissection() {
        return onDemandDissection.getBoolean();
    }

    /**
     * Checks if any dissection is enabled.
     *
     * @return true if either eager or on-demand dissection is enabled
     */
    public boolean isDissectionEnabled() {
        return isEagerDissection() || isOnDemandDissection();
    }

    /**
     * Checks if hybrid memory model is required.
     * 
     * <p>
     * Hybrid memory (scoped data + fixed descriptor) is required when eager
     * dissection is enabled, since the TYPE2 descriptor needs fixed memory to
     * store dissection results.
     * </p>
     *
     * @return true if hybrid memory model is needed
     */
    public boolean isHybridMemory() {
        return isEagerDissection();
    }

    /**
     * Returns the appropriate descriptor type for the current mode.
     * 
     * <p>
     * Eager dissection requires {@link DescriptorType#TYPE2} to store the protocol
     * header table. Other modes use {@link DescriptorType#PCAP_PACKED} for
     * zero-copy compatibility with native pcap headers.
     * </p>
     *
     * @return the descriptor type for the current configuration
     */
    public DescriptorType descriptorType() {
        return isEagerDissection() ? DescriptorType.TYPE2 : DescriptorType.PCAP_PACKED;
    }

    /**
     * Returns the maximum header count for the descriptor.
     *
     * @return maximum headers stored in descriptor table
     */
    public int maxHeaderCount() {
        return maxHeaderCount.getInt();
    }

    /**
     * Returns the pool settings for descriptor allocation.
     *
     * @return pool settings, never null
     */
    public PoolSettings poolSettings() {
        return poolSettings;
    }

    /**
     * Returns the custom header binding, if set.
     *
     * @return the header binding, or null if using default
     */
    public HeaderBinding headerBinding() {
        return headerBinding;
    }
}