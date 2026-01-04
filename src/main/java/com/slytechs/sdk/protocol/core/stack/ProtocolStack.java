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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import com.slytechs.sdk.protocol.core.spi.ProtocolConfigProvider;
import com.slytechs.sdk.protocol.core.stack.processor.PassthroughProcessor;
import com.slytechs.sdk.protocol.core.stack.processor.Processor;

/**
 * User-facing configuration container for the protocol processing stack.
 * 
 * <p>
 * ProtocolStack holds protocol configurations (which extend Settings) and
 * packet-level policies. It serves as the user's primary interface for
 * configuring protocol processing behavior.
 * </p>
 * 
 * <h2>Architecture</h2>
 * 
 * <pre>
 * ProtocolStack (Configuration)
 *       │
 *       ▼
 * ProtocolTree (Template from SPI)
 *       │
 *       ▼
 * ProcessorTree (Runtime instances)
 * </pre>
 * 
 * <h2>Usage Examples</h2>
 * 
 * <pre>{@code
 * // Create stack and configure protocols
 * ProtocolStack stack = new ProtocolStack();
 * 
 * stack.setProtocol(new IpProtocolConfig())
 * 		.enableReassembly(true)
 * 		.fragmentTimeout(30);
 * 
 * stack.setProtocol(new TcpProtocolConfig())
 * 		.enableReassembly(true)
 * 		.maxOutOfOrder(200);
 * 
 * // Configure inner IP differently (tunneled traffic)
 * stack.setProtocol(new IpProtocolConfig(), 1) // depth 1
 * 		.enableReassembly(false); // Don't reassemble inner
 * 
 * // Use with jNetPcap
 * try (NetPcap pcap = NetPcap.create("en0", stack)) {
 * 	pcap.dispatch(count, handler);
 * }
 * 
 * // Use with jNetWorks
 * PacketStream[] streams = net.createPacketStreams("rx-%d", 4, stack);
 * }</pre>
 * 
 * <h2>Factory Methods</h2>
 * 
 * <pre>{@code
 * // Dissection only (no reassembly, no decryption)
 * ProtocolStack stack = ProtocolStack.packetDissectionOnly();
 * 
 * // Full processing (reassembly + decryption enabled)
 * ProtocolStack stack = ProtocolStack.fullProcessing();
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see ProtocolConfig
 * @see PacketPolicy
 */
public class ProtocolStack {

	// =========================================================================
	// Factory Methods
	// =========================================================================

	/**
	 * Creates a stack configured for packet dissection only.
	 * 
	 * <p>
	 * No reassembly, no decryption - just protocol parsing. This is the most
	 * efficient mode for basic packet inspection.
	 * </p>
	 *
	 * @return a new dissection-only stack
	 */
	public static ProtocolStack packetDissectionOnly() {
		return new ProtocolStack();
	}

	/**
	 * Creates a stack with full protocol processing enabled.
	 * 
	 * <p>
	 * IP reassembly, TCP reassembly, and TLS decryption are enabled with default
	 * settings. Configure individual protocols for custom settings.
	 * </p>
	 *
	 * @return a new full-processing stack
	 */
	public static ProtocolStack fullProcessing() {
		ProtocolStack stack = new ProtocolStack();
		// Will be populated when protocol configs are implemented
		// stack.getProtocol(IpProtocolConfig.class).enableReassembly(true);
		// stack.getProtocol(TcpProtocolConfig.class).enableReassembly(true);
		return stack;
	}

	// =========================================================================
	// Instance Fields
	// =========================================================================

	/** Protocol configurations keyed by (class, depth). */
	private final Map<ProtocolKey, ProtocolConfig> protocols = new HashMap<>();

	/** Root processor (temporary until ProcessorTree is built). */
	private Processor root = new PassthroughProcessor();

	/** Quiet mode - suppress output during context rebuild. */
	private boolean quietMode = false;

	/** Token subscription mask (combined from all subscribers). */
	private long tokenMask = 0L;

	// =========================================================================
	// Constructors
	// =========================================================================

	/**
	 * Creates a new protocol stack with default settings.
	 */
	public ProtocolStack() {}

	// =========================================================================
	// Protocol Configuration - Primary API
	// =========================================================================

	/**
	 * Sets a protocol configuration at depth 0.
	 * 
	 * <p>
	 * This is the primary pattern for configuring protocols:
	 * </p>
	 * 
	 * <pre>{@code
	 * stack.setProtocol(new IpProtocolConfig())
	 * 		.enableReassembly(true)
	 * 		.fragmentTimeout(30);
	 * }</pre>
	 *
	 * @param <T>    the protocol config type
	 * @param config the protocol configuration
	 * @return the same config instance for method chaining
	 */
	public <T extends ProtocolConfig> T setProtocol(T config) {
		return setProtocol(config, 0);
	}

	/**
	 * Sets a protocol configuration at the specified depth.
	 * 
	 * <p>
	 * Use depth > 0 for tunneled/encapsulated protocols:
	 * </p>
	 * 
	 * <pre>{@code
	 * // Outer IP (depth 0)
	 * stack.setProtocol(new IpProtocolConfig(), 0)
	 * 		.enableReassembly(true);
	 * 
	 * // Inner IP after GRE tunnel (depth 1)
	 * stack.setProtocol(new IpProtocolConfig(), 1)
	 * 		.enableReassembly(false);
	 * }</pre>
	 *
	 * @param <T>    the protocol config type
	 * @param config the protocol configuration
	 * @param depth  the encapsulation depth (0 = outermost)
	 * @return the same config instance for method chaining
	 */
	public <T extends ProtocolConfig> T setProtocol(T config, int depth) {
		Objects.requireNonNull(config, "config");
		if (depth < 0) {
			throw new IllegalArgumentException("depth must be >= 0");
		}

		@SuppressWarnings("unchecked")
		Class<T> type = (Class<T>) config.getClass();
		ProtocolKey key = ProtocolKey.of(type, depth);
		protocols.put(key, config);

		return config;
	}

	/**
	 * Gets or creates a protocol configuration at depth 0.
	 * 
	 * <p>
	 * If no configuration exists, one is created via SPI lookup. This allows
	 * modifying the default configuration:
	 * </p>
	 * 
	 * <pre>{@code
	 * stack.getProtocol(IpProtocolConfig.class)
	 * 		.enableReassembly(true);
	 * }</pre>
	 *
	 * @param <T>  the protocol config type
	 * @param type the protocol config class
	 * @return the protocol configuration (existing or newly created)
	 */
	public <T extends ProtocolConfig> T getProtocol(Class<T> type) {
		return getProtocol(type, 0);
	}

	/**
	 * Gets or creates a protocol configuration at the specified depth.
	 *
	 * @param <T>   the protocol config type
	 * @param type  the protocol config class
	 * @param depth the encapsulation depth (0 = outermost)
	 * @return the protocol configuration (existing or newly created)
	 */
	@SuppressWarnings("unchecked")
	public <T extends ProtocolConfig> T getProtocol(Class<T> type, int depth) {
		Objects.requireNonNull(type, "type");
		if (depth < 0) {
			throw new IllegalArgumentException("depth must be >= 0");
		}

		ProtocolKey key = ProtocolKey.of(type, depth);
		return (T) protocols.computeIfAbsent(key, k -> createProtocolConfig(type));
	}

	/**
	 * Checks if a protocol configuration exists at depth 0.
	 *
	 * @param type the protocol config class
	 * @return true if configuration exists
	 */
	public boolean hasProtocol(Class<? extends ProtocolConfig> type) {
		return hasProtocol(type, 0);
	}

	/**
	 * Checks if a protocol configuration exists at the specified depth.
	 *
	 * @param type  the protocol config class
	 * @param depth the encapsulation depth
	 * @return true if configuration exists
	 */
	public boolean hasProtocol(Class<? extends ProtocolConfig> type, int depth) {
		return protocols.containsKey(ProtocolKey.of(type, depth));
	}

	/**
	 * Creates a protocol config via SPI lookup.
	 */
	private <T extends ProtocolConfig> T createProtocolConfig(Class<T> type) {
		T config = ProtocolConfigProvider.createConfig(type);
		if (config == null) {
			throw new ProtocolStackException("No provider found for: " + type.getName());
		}
		return config;
	}

	/**
	 * Enables a protocol type at all depths.
	 *
	 * @param type the protocol config class
	 * @return this stack for method chaining
	 */
	public ProtocolStack enable(Class<? extends ProtocolConfig> type) {
		protocols.entrySet().stream()
				.filter(e -> type.isAssignableFrom(e.getKey().type()))
				.forEach(e -> e.getValue().enabled(true));
		return this;
	}

	/**
	 * Disables a protocol type at all depths.
	 *
	 * @param type the protocol config class
	 * @return this stack for method chaining
	 */
	public ProtocolStack disable(Class<? extends ProtocolConfig> type) {
		protocols.entrySet().stream()
				.filter(e -> type.isAssignableFrom(e.getKey().type()))
				.forEach(e -> e.getValue().enabled(false));
		return this;
	}

	/**
	 * Disables all protocols matching a layer marker.
	 * 
	 * <p>
	 * Example: Disable all L5+ protocols for jNetPcap:
	 * </p>
	 * 
	 * <pre>{@code
	 * stack.disableLayer(L5Protocol.class);
	 * }</pre>
	 *
	 * @param layerMarker the layer marker interface (L3Protocol, L4Protocol, etc.)
	 * @return this stack for method chaining
	 */
	public ProtocolStack disableLayer(Class<?> layerMarker) {
		protocols.entrySet().stream()
				.filter(e -> layerMarker.isAssignableFrom(e.getKey().type()))
				.forEach(e -> e.getValue().enabled(false));
		return this;
	}

	// =========================================================================
	// State Management
	// =========================================================================

	/**
	 * Clears all processor state (flow tables, reassembly buffers, etc.).
	 * 
	 * <p>
	 * Use when jumping to a new position in a capture file or when resetting
	 * processing context.
	 * </p>
	 *
	 * @return this stack for method chaining
	 */
	public ProtocolStack clearState() {
		if (root != null) {
			root.clearState();
		}
		return this;
	}

	/**
	 * Clears state for a specific protocol at all depths.
	 *
	 * @param type the protocol config class
	 * @return this stack for method chaining
	 */
	public ProtocolStack clearState(Class<? extends ProtocolConfig> type) {
		// Will delegate to ProcessorTree when implemented
		return this;
	}

	/**
	 * Sets quiet mode (suppress output during context rebuild).
	 * 
	 * <p>
	 * In quiet mode, processors update their state but don't emit tokens or output.
	 * Use when rebuilding context after a file seek.
	 * </p>
	 *
	 * @param quiet true to enable quiet mode
	 * @return this stack for method chaining
	 */
	public ProtocolStack setQuietMode(boolean quiet) {
		this.quietMode = quiet;
		return this;
	}

	/**
	 * Checks if quiet mode is enabled.
	 *
	 * @return true if in quiet mode
	 */
	public boolean isQuietMode() {
		return quietMode;
	}

	// =========================================================================
	// Token Subscription
	// =========================================================================

	/**
	 * Subscribes to token types from a specific layer.
	 * 
	 * <p>
	 * The combined mask from all subscriptions determines which tokens are
	 * generated. If no subscriptions, token generation is disabled (zero cost).
	 * </p>
	 *
	 * @param layerId the layer ID
	 * @param mask    bitmask of token types to subscribe to
	 * @return this stack for method chaining
	 */
	public ProtocolStack subscribeTokens(int layerId, long mask) {
		this.tokenMask |= mask;
		return this;
	}

	/**
	 * Gets the combined token subscription mask.
	 *
	 * @return the token mask
	 */
	public long getTokenMask() {
		return tokenMask;
	}

	/**
	 * Clears all token subscriptions.
	 *
	 * @return this stack for method chaining
	 */
	public ProtocolStack clearTokenSubscriptions() {
		this.tokenMask = 0L;
		return this;
	}

	// =========================================================================
	// Processor Access (Temporary - will be replaced by ProcessorTree)
	// =========================================================================

	/**
	 * Gets the root processor.
	 * 
	 * <p>
	 * <b>Note:</b> This is temporary. Will be replaced by ProcessorTree when the
	 * full tree building infrastructure is in place.
	 * </p>
	 *
	 * @return the root processor
	 */
	public Processor getRootProcessor() {
		return root;
	}

	/**
	 * Sets the root processor.
	 * 
	 * <p>
	 * <b>Note:</b> This is temporary.
	 * </p>
	 *
	 * @param processor the root processor
	 */
	public void setRootProcessor(Processor processor) {
		this.root = processor;
	}

	// =========================================================================
	// Cloning
	// =========================================================================

	/**
	 * Creates a deep clone of this stack.
	 * 
	 * <p>
	 * Used when creating stream-specific stacks that may be modified independently
	 * of the original.
	 * </p>
	 *
	 * @return a new stack with cloned configurations
	 */
	@Override
	public ProtocolStack clone() {
		ProtocolStack clone = new ProtocolStack();

		// Deep clone all protocol configs
		for (Map.Entry<ProtocolKey, ProtocolConfig> entry : protocols.entrySet()) {
			// TODO: Implement deep clone for ProtocolConfig
			// For now, configs are shared (need to implement Cloneable in ProtocolConfig)
			clone.protocols.put(entry.getKey(), entry.getValue());
		}

		clone.quietMode = this.quietMode;
		clone.tokenMask = this.tokenMask;

		return clone;
	}
}