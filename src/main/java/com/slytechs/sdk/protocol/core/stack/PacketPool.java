/*
 * Copyright 2005-2025 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.protocol.core.stack;

import com.slytechs.sdk.common.memory.pool.BucketPool;
import com.slytechs.sdk.common.memory.pool.BucketPool.BucketFactory;
import com.slytechs.sdk.common.memory.pool.FreeListPool;
import com.slytechs.sdk.common.memory.pool.Pool;
import com.slytechs.sdk.common.memory.pool.PoolSettings;
import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.descriptor.DescriptorInfo;

/**
 * Factory for creating packet pools optimized for different capture scenarios.
 * 
 * <p>
 * PacketPool provides static factory methods for creating pools suited to
 * various packet processing requirements. Three pool types are available:
 * </p>
 * 
 * <table>
 * <caption>Pool Types</caption>
 * <tr>
 * <th>Type</th>
 * <th>Data Memory</th>
 * <th>Descriptor</th>
 * <th>Use Case</th>
 * </tr>
 * <tr>
 * <td>Fixed</td>
 * <td>FixedMemory (slab)</td>
 * <td>FixedMemory</td>
 * <td>Copied packets, variable sizes</td>
 * </tr>
 * <tr>
 * <td>Scoped</td>
 * <td>ScopedMemory</td>
 * <td>ScopedMemory</td>
 * <td>Zero-copy native capture</td>
 * </tr>
 * <tr>
 * <td>Hybrid</td>
 * <td>ScopedMemory</td>
 * <td>FixedMemory</td>
 * <td>Zero-copy with descriptor conversion</td>
 * </tr>
 * </table>
 * 
 * <h2>Fixed Pools</h2>
 * <p>
 * Fixed pools use {@link BucketPool} with size-tiered allocation. Packet data
 * is copied into slab-allocated memory that persists across recycle cycles. Use
 * when packets need to outlive native buffers or be queued/stored.
 * </p>
 * 
 * <pre>{@code
 * // Default bucket sizes: 64, 1518, 9000, 65536
 * Pool<Packet> pool = PacketPool.ofFixed();
 * 
 * // Custom sizes
 * Pool<Packet> pool = PacketPool.ofFixed(settings, new long[] {
 * 		128,
 * 		1500,
 * 		9000
 * });
 * 
 * // Usage
 * Packet packet = pool.allocate(1500); // Gets 1518-byte bucket
 * packet.memory().segment().copyFrom(nativeData);
 * processPacket(packet);
 * packet.recycle();
 * }</pre>
 * 
 * <h2>Scoped Pools</h2>
 * <p>
 * Scoped pools use {@link FreeListPool} for zero-copy capture. Packet memory is
 * bound directly to native segments (DPDK mbufs, Napatech buffers, etc.) with
 * no data copying. Maximum performance for inline processing.
 * </p>
 * 
 * <pre>{@code
 * Pool<Packet> pool = PacketPool.ofScoped();
 * 
 * // Capture loop
 * Packet packet = pool.allocate();
 * packet.memory().bind(nativeSegment, offset, length);
 * processPacket(packet);
 * packet.memory().unbind();
 * packet.recycle();
 * }</pre>
 * 
 * <h2>Hybrid Pools</h2>
 * <p>
 * Hybrid pools combine zero-copy data access with fixed descriptor memory. Use
 * when native descriptors need conversion to a different format while packet
 * data can remain zero-copy.
 * </p>
 * 
 * <pre>{@code
 * Pool<Packet> pool = PacketPool.ofHybrid();
 * 
 * // Capture loop
 * Packet packet = pool.allocate();
 * packet.memory().bind(nativeSegment, offset, length); // Zero-copy data
 * convertDescriptor(nativeDesc, packet.descriptor()); // Copy/convert descriptor
 * processPacket(packet);
 * packet.memory().unbind();
 * packet.recycle();
 * }</pre>
 * 
 * <h2>Configuration</h2>
 * <p>
 * All factory methods accept optional {@link PoolSettings} for capacity and
 * contraction configuration:
 * </p>
 * 
 * <pre>{@code
 * PoolSettings settings = new PoolSettings()
 * 		.minCapacity(1000)
 * 		.maxCapacity(10000)
 * 		.contractionEnabled(true);
 * 
 * Pool<Packet> pool = PacketPool.ofFixed(settings);
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Pool
 * @see Packet
 * @see PoolSettings
 * @see BucketPool
 * @see FreeListPool
 */
public final class PacketPool {

	/**
	 * Default bucket sizes for fixed packet pools.
	 * 
	 * <p>
	 * Sizes chosen to match common network packet sizes:
	 * </p>
	 * <ul>
	 * <li>64 - Minimum Ethernet frame</li>
	 * <li>1518 - Standard Ethernet MTU</li>
	 * <li>9000 - Jumbo frames</li>
	 * <li>65536 - Maximum capture size</li>
	 * </ul>
	 */
	private static final long[] DEFAULT_BUCKET_SIZES = new long[] {
			64,
			1518,
			9000,
			65536
	};

	/** Default pool settings with standard capacity limits. */
	private static final PoolSettings DEFAULT_POOL_SETTINGS = new PoolSettings();

	/**
	 * Creates a fixed packet pool with default settings and bucket sizes.
	 * 
	 * <p>
	 * Uses default bucket sizes (64, 1518, 9000, 65536) and default pool settings.
	 * Packets are allocated from the smallest bucket that fits the requested size.
	 * </p>
	 *
	 * @return a new bucketed fixed packet pool
	 * @see #ofFixed(PoolSettings, long[])
	 */
	public static Pool<Packet> ofFixed() {
		return ofFixed(DEFAULT_POOL_SETTINGS, DEFAULT_BUCKET_SIZES);
	}

	/**
	 * Creates a fixed packet pool with custom settings and default bucket sizes.
	 *
	 * @param settings pool configuration for capacity and contraction
	 * @return a new bucketed fixed packet pool
	 * @see #ofFixed(PoolSettings, long[])
	 */
	public static Pool<Packet> ofFixed(PoolSettings settings) {
		return ofFixed(settings, DEFAULT_BUCKET_SIZES);
	}

	/**
	 * Creates a fixed packet pool with custom settings and bucket sizes.
	 * 
	 * <p>
	 * Fixed pools allocate packet data from slab memory. Each bucket maintains its
	 * own slab allocator for efficient bulk allocation. The pool settings apply
	 * per-bucket (each bucket has minCapacity to maxCapacity range).
	 * </p>
	 * 
	 * <p>
	 * Bucket sizes must be in ascending order. Allocation requests are served by
	 * the smallest bucket that can accommodate the requested size.
	 * </p>
	 *
	 * @param settings pool configuration for capacity and contraction
	 * @param sizes    bucket sizes in ascending order
	 * @return a new bucketed fixed packet pool
	 * @throws IllegalArgumentException if sizes is null, empty, or not ascending
	 */
	public static Pool<Packet> ofFixed(PoolSettings settings, long[] sizes) {
		return new BucketPool<>(settings, sizes, (BucketFactory<Packet>) Packet::ofFixed);
	}

	/**
	 * Creates a fixed packet pool with custom settings and bucket sizes.
	 * 
	 * <p>
	 * Fixed pools allocate packet data from slab memory. Each bucket maintains its
	 * own slab allocator for efficient bulk allocation. The pool settings apply
	 * per-bucket (each bucket has minCapacity to maxCapacity range).
	 * </p>
	 * 
	 * <p>
	 * Bucket sizes must be in ascending order. Allocation requests are served by
	 * the smallest bucket that can accommodate the requested size.
	 * </p>
	 *
	 * @param settings pool configuration for capacity and contraction
	 * @param sizes    bucket sizes in ascending order
	 * @return a new bucketed fixed packet pool
	 * @throws IllegalArgumentException if sizes is null, empty, or not ascending
	 */
	public static Pool<Packet> ofFixed(PoolSettings settings, long[] sizes, DescriptorInfo type) {
		return new BucketPool<>(settings, sizes, (allocator, dataSize) -> Packet.ofFixedType(allocator, dataSize,
				type));
	}

	/**
	 * Creates a scoped packet pool with default settings.
	 * 
	 * <p>
	 * Scoped pools provide zero-copy packet access. The pool manages reusable
	 * Packet wrapper objects with ScopedMemory that binds directly to native
	 * segments.
	 * </p>
	 *
	 * @return a new scoped packet pool
	 * @see #ofScoped(PoolSettings)
	 */
	public static Pool<Packet> ofScoped() {
		return ofScoped(DEFAULT_POOL_SETTINGS);
	}

	/**
	 * Creates a scoped packet pool with custom settings.
	 * 
	 * <p>
	 * Scoped pools are ideal for high-performance capture where packet data doesn't
	 * need to persist beyond immediate processing. The packet's ScopedMemory binds
	 * directly to native buffers (DPDK mbufs, Napatech descriptors, etc.) with no
	 * data copying.
	 * </p>
	 * 
	 * <p>
	 * Typical usage:
	 * </p>
	 * <ol>
	 * <li>Allocate packet from pool</li>
	 * <li>Bind packet memory to native segment</li>
	 * <li>Process packet (zero-copy access)</li>
	 * <li>Unbind packet memory</li>
	 * <li>Recycle packet to pool</li>
	 * </ol>
	 *
	 * @param settings pool configuration for capacity and contraction
	 * @return a new scoped packet pool
	 */
	public static Pool<Packet> ofScoped(PoolSettings settings) {
		return new FreeListPool<>(settings, Packet::ofScoped);
	}

	/**
	 * Creates a hybrid packet pool with default settings.
	 * 
	 * <p>
	 * Hybrid pools combine zero-copy data access with fixed descriptor memory.
	 * </p>
	 *
	 * @return a new hybrid packet pool
	 * @see #ofHybrid(PoolSettings)
	 */
	public static Pool<Packet> ofHybrid() {
		return ofHybrid(DEFAULT_POOL_SETTINGS);
	}

	/**
	 * Creates a hybrid packet pool with custom settings.
	 * 
	 * <p>
	 * Hybrid pools are useful when native packet descriptors need to be converted
	 * or enhanced while packet data can remain zero-copy. The packet's data memory
	 * is ScopedMemory (binds to native), while the descriptor uses FixedMemory
	 * (allocated from Arena.ofShared()).
	 * </p>
	 * 
	 * <p>
	 * Common use cases:
	 * </p>
	 * <ul>
	 * <li>Converting native descriptor formats to protocol-specific format</li>
	 * <li>Adding metadata to packets while keeping data zero-copy</li>
	 * <li>Protocol stacks that enhance descriptors during processing</li>
	 * </ul>
	 *
	 * @param settings pool configuration for capacity and contraction
	 * @return a new hybrid packet pool
	 */
	public static Pool<Packet> ofHybrid(PoolSettings settings) {
		return new FreeListPool<>(settings, Packet::ofHybrid);
	}

	/** Private constructor - static factory only. */
	private PacketPool() {
		// Static factory class
	}
}