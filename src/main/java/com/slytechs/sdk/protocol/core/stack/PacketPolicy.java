/*
 * Apache License, Version 2.0
 * 
 * Copyright 2025 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.sdk.protocol.core.stack;

import com.slytechs.sdk.common.memory.pool.PoolSettings;
import com.slytechs.sdk.common.spec.Spec;
import com.slytechs.sdk.protocol.core.descriptor.DescriptorInfo;

/**
 * User configuration for packet handling policy.
 * 
 * <p>
 * PacketPolicy is a Spec that determines how packets are acquired, bound, and
 * released. It provides fluent configuration for freeListPool settings,
 * descriptor types, and copy behavior. The configuration is validated and
 * instantiated through the standard Spec lifecycle.
 * </p>
 * 
 * <h2>Lifecycle</h2>
 * 
 * <pre>
 * PacketPolicy (Spec)           - User configuration, mutable
 *     → ResolvedPacketPolicy    - Validated, backend-aware, immutable
 *     → RuntimePacketPolicy     - Instantiated, pools allocated, operational
 * </pre>
 * 
 * <h2>Policy Types</h2>
 * 
 * <table>
 * <tr>
 * <th>Policy</th>
 * <th>Data Memory</th>
 * <th>Descriptor Memory</th>
 * <th>Use Case</th>
 * </tr>
 * <tr>
 * <td>ZeroCopy</td>
 * <td>ScopedMemory (bind)</td>
 * <td>ScopedMemory/FixedMemory</td>
 * <td>High-speed capture</td>
 * </tr>
 * <tr>
 * <td>MemoryCopy</td>
 * <td>FixedMemory (copy)</td>
 * <td>FixedMemory (copy)</td>
 * <td>Packet persistence</td>
 * </tr>
 * <tr>
 * <td>FactoryCopy</td>
 * <td>User-provided</td>
 * <td>User-provided</td>
 * <td>Custom allocation</td>
 * </tr>
 * </table>
 * 
 * <h2>Usage Example</h2>
 * 
 * <pre>{@code
 * // Configure zero-copy for high-speed capture
 * stack.setPacketPolicy(PacketPolicy.zeroCopy()
 * 		.usePacketPool(new PacketPoolSettings()
 * 				.capacity(100_000)
 * 				.packetSize(9000))
 * 		.descriptorType(DescriptorInfo.NET)
 * 		.dissectorDepth(4)
 * 		.copyPolicy(PacketPolicy.memoryCopy()));
 * 
 * // Or memory-copy for persistence
 * stack.setPacketPolicy(PacketPolicy.memoryCopy()
 * 		.usePacketPool(new PacketPoolSettings()
 * 				.capacity(10_000)
 * 				.packetSize(16384)));
 * }</pre>
 * 
 * <h2>Backend Resolution</h2>
 * 
 * <p>
 * Backends (jnetpcap, jnetworks) resolve this configuration via SPI:
 * </p>
 * 
 * <pre>{@code
 * ResolvedPacketPolicy resolved = PacketPolicyService.resolve(policy, backendContext);
 * RuntimePacketPolicy runtime = PacketPolicyService.build(resolved, streamContext);
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see ResolvedPacketPolicy
 * @see RuntimePacketPolicy
 * @see Spec
 */
public interface PacketPolicy extends Spec {

	/**
	 * Configures this policy to use the specified packet freeListPool settings.
	 *
	 * @param settings the freeListPool settings
	 * @return this for chaining
	 */
	PacketPolicy usePacketPool(PoolSettings settings);

	/**
	 * Sets the descriptor type for this policy.
	 * 
	 * <p>
	 * The backend may substitute a different descriptor type during resolution
	 * based on its capabilities.
	 * </p>
	 *
	 * @param type the descriptor type
	 * @return this for chaining
	 */
	PacketPolicy descriptorType(DescriptorInfo type);

	/**
	 * Sets the maximum protocol layer depth for dissection.
	 *
	 * @param maxLayer maximum layer (e.g., 4 for L4, 7 for L7)
	 * @return this for chaining
	 */
	PacketPolicy dissectorDepth(int maxLayer);

	/**
	 * Sets the policy to use when copying packets.
	 * 
	 * <p>
	 * When {@code Packet.copy()} is called, the copy policy determines how the new
	 * packet is allocated and whether data is copied.
	 * </p>
	 *
	 * @param policy the copy policy
	 * @return this for chaining
	 */
	PacketPolicy copyPolicy(PacketPolicy policy);

	/**
	 * Returns the configured descriptor type.
	 *
	 * @return the descriptor type
	 */
	DescriptorInfo descriptorType();

	/**
	 * Returns whether this is a zero-copy policy.
	 *
	 * @return true if zero-copy
	 */
	boolean isZeroCopy();

	/**
	 * Returns whether this policy supports copying.
	 *
	 * @return true if copying is supported
	 */
	boolean allowsCopying();

	/**
	 * Returns the configured freeListPool settings.
	 *
	 * @return freeListPool settings, or null if not configured
	 */
	PoolSettings poolSettings();

	/**
	 * Returns the configured copy policy.
	 *
	 * @return copy policy, or null if not configured
	 */
	PacketPolicy copyPolicy();

	/**
	 * Returns the configured dissector depth.
	 *
	 * @return dissector depth
	 */
	int dissectorDepth();

	/**
	 * @param net
	 * @param i
	 * @return
	 */
	static PacketPolicy zeroCopy(DescriptorInfo net, int i) {
		throw new UnsupportedOperationException("not implemented yet");
	}

}