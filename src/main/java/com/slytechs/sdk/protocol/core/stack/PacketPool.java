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
 * various packet processing requirements. The factory method name explicitly
 * indicates the pool type and allocation strategy.
 * </p>
 * 
 * <h2>Pool Types Overview</h2>
 * <table>
 * <caption>Pool Types</caption>
 * <tr>
 * <th>Factory Method</th>
 * <th>Pool Type</th>
 * <th>Memory</th>
 * <th>Use Case</th>
 * </tr>
 * <tr>
 * <td>{@link #ofFixedSize}</td>
 * <td>FreeListPool</td>
 * <td>Single fixed size</td>
 * <td>Uniform packet sizes, simple allocation</td>
 * </tr>
 * <tr>
 * <td>{@link #ofBucketed}</td>
 * <td>BucketPool</td>
 * <td>Size-tiered buckets</td>
 * <td>Variable packet sizes, efficient memory</td>
 * </tr>
 * <tr>
 * <td>{@link #ofDefaultBuckets}</td>
 * <td>BucketPool</td>
 * <td>Network-optimized buckets</td>
 * <td>General network capture</td>
 * </tr>
 * <tr>
 * <td>{@link #ofScoped}</td>
 * <td>FreeListPool</td>
 * <td>Zero-copy binding</td>
 * <td>High-performance native capture</td>
 * </tr>
 * <tr>
 * <td>{@link #ofHybrid}</td>
 * <td>FreeListPool</td>
 * <td>Zero-copy + fixed descriptor</td>
 * <td>Native capture with descriptor conversion</td>
 * </tr>
 * </table>
 * 
 * <h2>Fixed-Size Pools</h2>
 * <p>
 * Use {@link #ofFixedSize(long)} when all packets are approximately the same
 * size. Simpler allocation, no bucket selection overhead.
 * </p>
 * 
 * <pre>{@code
 * // Pool for standard Ethernet frames
 * Pool<Packet> pool = PacketPool.ofFixedSize(1518);
 * 
 * // Pool for jumbo frames with custom capacity
 * PoolSettings settings = new PoolSettings()
 * 		.capacity(1000);
 * Pool<Packet> pool = PacketPool.ofFixedSize(settings, 9000);
 * 
 * // Usage
 * Packet packet = pool.allocate();
 * packet.copyTo(nativePacket);
 * processPacket(packet);
 * packet.recycle();
 * }</pre>
 * 
 * <h2>Bucketed Pools</h2>
 * <p>
 * Use {@link #ofBucketed(long...)} or {@link #ofDefaultBuckets()} when packet
 * sizes vary significantly. Memory is allocated efficiently from the smallest
 * bucket that fits each packet.
 * </p>
 * 
 * <pre>{@code
 * // Default network-optimized buckets (64, 1518, 9000, 65536)
 * Pool<Packet> pool = PacketPool.ofDefaultBuckets();
 * 
 * // Custom bucket sizes
 * Pool<Packet> pool = PacketPool.ofBucketed(128, 1500, 9000);
 * 
 * // With settings (capacity applies PER BUCKET)
 * PoolSettings settings = new PoolSettings()
 * 		.capacity(500); // 500 per bucket = 2000 total for 4 buckets
 * Pool<Packet> pool = PacketPool.ofDefaultBuckets(settings);
 * 
 * // Allocation selects appropriate bucket
 * Packet small = pool.allocate(64); // From 64-byte bucket
 * Packet medium = pool.allocate(1000); // From 1518-byte bucket
 * Packet jumbo = pool.allocate(8000); // From 9000-byte bucket
 * }</pre>
 * 
 * <p>
 * <b>Important:</b> For bucketed pools, {@link Pool#available()} returns the
 * total capacity across all buckets. A specific bucket may be exhausted while
 * others have capacity. Always handle null returns from
 * {@link Pool#allocate(long)}.
 * </p>
 * 
 * <h2>Zero-Copy Pools</h2>
 * <p>
 * Use {@link #ofScoped()} for maximum performance when packet data doesn't need
 * to persist beyond immediate processing.
 * </p>
 * 
 * <pre>{@code
 * Pool<Packet> pool = PacketPool.ofScoped();
 * 
 * // Capture loop - no data copying
 * Packet packet = pool.allocate();
 * packet.memory().bind(nativeSegment, offset, length);
 * processPacket(packet);
 * packet.memory().unbind();
 * packet.recycle();
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
	 * Default bucket sizes for network packet pools.
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
	public static final long[] DEFAULT_BUCKET_SIZES = {
			64,
			1518,
			9000,
			65536
	};

	/** Default pool settings. */
	private static final PoolSettings DEFAULT_SETTINGS = new PoolSettings();

	/**
	 * Creates a bucketed packet pool with custom bucket sizes.
	 * 
	 * <p>
	 * Bucket sizes must be in ascending order. Allocation requests are served by
	 * the smallest bucket that can accommodate the requested size.
	 * </p>
	 *
	 * @param bucketSizes bucket sizes in ascending order
	 * @return a new bucketed packet pool
	 * @throws IllegalArgumentException if sizes is null, empty, or not ascending
	 */
	public static Pool<Packet> ofBucketed(long... bucketSizes) {
		return ofBucketed(DEFAULT_SETTINGS, bucketSizes);
	}

	/**
	 * Creates a bucketed packet pool with custom settings and bucket sizes.
	 * 
	 * <p>
	 * Each bucket maintains its own allocation pool. The settings apply per-bucket,
	 * so total pool capacity is {@code settings.capacity() * bucketSizes.length}.
	 * </p>
	 * 
	 * <p>
	 * <b>Allocation behavior:</b> When allocating, the pool selects the smallest
	 * bucket that fits the requested size. If that bucket is exhausted,
	 * {@link Pool#allocate(long)} returns null even if other buckets have capacity.
	 * Always check for null returns.
	 * </p>
	 *
	 * @param settings    pool configuration (capacity applies per bucket)
	 * @param bucketSizes bucket sizes in ascending order
	 * @return a new bucketed packet pool
	 * @throws IllegalArgumentException if sizes is null, empty, or not ascending
	 */
	public static Pool<Packet> ofBucketed(PoolSettings settings, long... bucketSizes) {
		validateBucketSizes(bucketSizes);
		return new BucketPool<>(settings, bucketSizes, (BucketFactory<Packet>) Packet::ofFixed);
	}

	/**
	 * Creates a bucketed packet pool with custom descriptor type.
	 *
	 * @param settings    pool configuration (capacity applies per bucket)
	 * @param bucketSizes bucket sizes in ascending order
	 * @param type        descriptor type for packets
	 * @return a new bucketed packet pool
	 * @throws IllegalArgumentException if sizes is null, empty, or not ascending
	 */
	public static Pool<Packet> ofBucketed(PoolSettings settings, long[] bucketSizes, DescriptorInfo type) {
		validateBucketSizes(bucketSizes);
		return new BucketPool<>(settings, bucketSizes,
				(allocator, dataSize) -> Packet.ofFixedType(allocator, dataSize, type));
	}

	/**
	 * Creates a bucketed packet pool with default network-optimized sizes.
	 * 
	 * <p>
	 * Uses bucket sizes optimized for network traffic: 64, 1518, 9000, 65536 bytes.
	 * Packets are allocated from the smallest bucket that fits the requested size.
	 * </p>
	 * 
	 * <p>
	 * <b>Note:</b> Pool capacity settings apply <em>per bucket</em>. With default
	 * settings and 4 buckets, total capacity is 4x the configured capacity.
	 * </p>
	 *
	 * @return a new bucketed packet pool
	 */
	public static Pool<Packet> ofDefaultBuckets() {
		return ofBucketed(DEFAULT_SETTINGS, DEFAULT_BUCKET_SIZES);
	}

	/**
	 * Creates a bucketed packet pool with default sizes and custom settings.
	 * 
	 * <p>
	 * <b>Important:</b> The capacity in settings applies <em>per bucket</em>. For
	 * example, {@code capacity(100)} with 4 default buckets creates a pool with
	 * total capacity of 400.
	 * </p>
	 *
	 * @param settings pool configuration (capacity applies per bucket)
	 * @return a new bucketed packet pool
	 */
	public static Pool<Packet> ofDefaultBuckets(PoolSettings settings) {
		return ofBucketed(settings, DEFAULT_BUCKET_SIZES);
	}

	/**
	 * Creates a fixed-size packet pool with default settings.
	 * 
	 * <p>
	 * All packets in this pool have the same memory size. Use when packet sizes are
	 * uniform or when simplicity is preferred over memory efficiency.
	 * </p>
	 *
	 * @param segmentSize memory size for each packet in bytes
	 * @return a new fixed-size packet pool
	 * @throws IllegalArgumentException if segmentSize is not positive
	 */
	public static Pool<Packet> ofFixedSize(long segmentSize) {
		return ofFixedSize(DEFAULT_SETTINGS, segmentSize);
	}

	/**
	 * Creates a fixed-size packet pool with custom settings.
	 * 
	 * <p>
	 * The pool will contain packets all of the same size. Settings control capacity
	 * and contraction behavior.
	 * </p>
	 *
	 * @param settings    pool configuration
	 * @param segmentSize memory size for each packet in bytes
	 * @return a new fixed-size packet pool
	 * @throws IllegalArgumentException if segmentSize is not positive
	 */
	public static Pool<Packet> ofFixedSize(PoolSettings settings, long segmentSize) {
		if (segmentSize <= 0)
			throw new IllegalArgumentException("segmentSize must be positive: " + segmentSize);

		// Use PoolableFactory - allocator comes from FreeListPool's slab
		return new FreeListPool<>(
				settings.segmentSize(segmentSize), // Set segment size for slab allocation
				allocator -> Packet.ofFixed(allocator, segmentSize));
	}

	/**
	 * Creates a fixed-size packet pool with custom descriptor type.
	 *
	 * @param settings    pool configuration
	 * @param segmentSize memory size for each packet in bytes
	 * @param type        descriptor type for packets
	 * @return a new fixed-size packet pool
	 * @throws IllegalArgumentException if segmentSize is not positive
	 */
	public static Pool<Packet> ofFixedSize(PoolSettings settings, long segmentSize, DescriptorInfo type) {
		if (segmentSize <= 0)
			throw new IllegalArgumentException("segmentSize must be positive: " + segmentSize);

		return new FreeListPool<>(
				settings.segmentSize(segmentSize),
				allocator -> Packet.ofFixedType(allocator, segmentSize, type));
	}

	/**
	 * Creates a hybrid packet pool with default settings.
	 * 
	 * <p>
	 * Hybrid pools combine zero-copy data access with fixed descriptor memory. Use
	 * when native packet descriptors need conversion while packet data remains
	 * zero-copy.
	 * </p>
	 *
	 * @return a new hybrid packet pool
	 */
	public static Pool<Packet> ofHybrid() {
		return ofHybrid(DEFAULT_SETTINGS);
	}

	/**
	 * Creates a hybrid packet pool with custom settings.
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
	 * @param settings pool configuration
	 * @return a new hybrid packet pool
	 */
	public static Pool<Packet> ofHybrid(PoolSettings settings) {
		return new FreeListPool<>(settings, Packet::ofHybrid);
	}

	/**
	 * Creates a scoped (zero-copy) packet pool with default settings.
	 * 
	 * <p>
	 * Scoped pools provide zero-copy packet access. The pool manages reusable
	 * Packet wrapper objects with ScopedMemory that binds directly to native
	 * segments. No packet data is copied.
	 * </p>
	 * 
	 * <p>
	 * Use for high-performance capture where packets are processed inline and don't
	 * need to persist beyond the capture callback.
	 * </p>
	 *
	 * @return a new scoped packet pool
	 */
	public static Pool<Packet> ofScoped() {
		return ofScoped(DEFAULT_SETTINGS);
	}

	/**
	 * Creates a scoped (zero-copy) packet pool with custom settings.
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
	 * @param settings pool configuration
	 * @return a new scoped packet pool
	 */
	public static Pool<Packet> ofScoped(PoolSettings settings) {
		return new FreeListPool<>(settings, Packet::ofScoped);
	}

	/**
	 * Validates bucket sizes array.
	 */
	private static void validateBucketSizes(long[] sizes) {
		if (sizes == null || sizes.length == 0)
			throw new IllegalArgumentException("bucketSizes cannot be null or empty");

		for (int i = 0; i < sizes.length; i++) {
			if (sizes[i] <= 0)
				throw new IllegalArgumentException("bucket size must be positive: " + sizes[i]);
			if (i > 0 && sizes[i] <= sizes[i - 1])
				throw new IllegalArgumentException("bucket sizes must be in ascending order");
		}
	}

	/** Private constructor - static factory only. */
	private PacketPool() {}
}