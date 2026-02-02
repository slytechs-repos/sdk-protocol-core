/*
 * Copyright 2005-2026 Sly Technologies Inc.
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
package com.slytechs.sdk.protocol.core;

import com.slytechs.sdk.common.detail.Detail;
import com.slytechs.sdk.common.detail.DetailBuilder;
import com.slytechs.sdk.common.detail.Detailable;
import com.slytechs.sdk.common.detail.render.TextRenderer;
import com.slytechs.sdk.common.memory.BindableView;
import com.slytechs.sdk.common.memory.BoundView;
import com.slytechs.sdk.common.memory.FixedMemory;
import com.slytechs.sdk.common.memory.Memory;
import com.slytechs.sdk.common.memory.ScopedMemory;
import com.slytechs.sdk.common.memory.pool.Persistable;
import com.slytechs.sdk.common.memory.pool.PoolEntry;
import com.slytechs.sdk.common.memory.pool.Poolable;
import com.slytechs.sdk.common.time.Timestamp;
import com.slytechs.sdk.protocol.core.descriptor.DescriptorType;
import com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor;
import com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor.BindingInfo;
import com.slytechs.sdk.protocol.core.header.Header;
import com.slytechs.sdk.protocol.core.descriptor.RxCapabilities;
import com.slytechs.sdk.protocol.core.descriptor.TxCapabilities;
import com.slytechs.sdk.protocol.core.descriptor.Type2PacketDescriptor;
import com.slytechs.sdk.protocol.core.stack.PacketPool;

/**
 * High-performance network packet representation with zero-copy access to
 * native memory.
 * 
 * <p>
 * The {@code Packet} class is the central abstraction for network packet
 * processing in the protocol framework. It provides efficient, zero-copy access
 * to packet data stored in native memory segments while maintaining protocol
 * dissection results and metadata.
 * </p>
 * 
 * <h2>Architecture Overview</h2>
 * 
 * <p>
 * A {@code Packet} instance consists of three key components:
 * </p>
 * <ol>
 * <li><strong>Memory Binding:</strong> Direct access to native packet data
 * through {@link BoundView}</li>
 * <li><strong>Packet Descriptor:</strong> Protocol dissection results and
 * header locations</li>
 * <li><strong>PacketTag Chain:</strong> Extended metadata and processing
 * annotations</li>
 * </ol>
 * 
 * <h2>Pool Types</h2>
 * 
 * <p>
 * Packets are typically allocated from pools for zero-allocation hot paths.
 * Three pool configurations are available via {@link PacketPool}:
 * </p>
 * 
 * <table>
 * <caption>Packet Pool Types</caption>
 * <tr>
 * <th>Type</th>
 * <th>Data Memory</th>
 * <th>Descriptor</th>
 * <th>Use Case</th>
 * </tr>
 * <tr>
 * <td>Fixed</td>
 * <td>FixedMemory</td>
 * <td>FixedMemory</td>
 * <td>Copied packets, persistence</td>
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
 * <h2>Usage Examples</h2>
 * 
 * <h3>Pooled Packet Processing (Zero-Copy)</h3>
 * 
 * <pre>{@code
 * Pool<Packet> pool = PacketPool.ofScoped();
 * 
 * // Capture loop
 * Packet packet = pool.allocate();
 * packet.memory().bind(nativeSegment, offset, length);
 * 
 * // Process packet
 * if (packet.hasHeader(tcp)) {
 * 	processTcp(packet, tcp);
 * }
 * 
 * // Return to pool
 * packet.recycle();
 * }</pre>
 * 
 * <h3>Packet Copying</h3>
 * 
 * <pre>{@code
 * // Create independent copy (not pooled)
 * Packet copy = packet.copy();
 * 
 * // Copy to pooled target
 * Pool<Packet> copyPool = PacketPool.ofFixed();
 * Packet target = copyPool.allocate(packet.captureLength());
 * packet.copyTo(target);
 * }</pre>
 * 
 * <h2>Pooled Packet Warning</h2>
 * 
 * <p>
 * <b>Important:</b> Pooled packets have pre-allocated memory structures managed
 * by the pool. Manually rebinding a pooled packet's memory destroys this
 * structure and corrupts the pool. Use {@link #isPooled()} to check before
 * manual rebinding. Pool-managed packets should only be rebound by the pool
 * itself during allocation.
 * </p>
 * 
 * <h2>Thread Safety</h2>
 * 
 * <p>
 * The {@code Packet} class is <strong>NOT thread-safe</strong>. Each thread
 * should use its own {@code Packet} instances via thread-local pools.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see PacketPool
 * @see PacketDescriptor
 * @see BoundView
 */
public class Packet
		implements BindableView, Poolable, Persistable<Packet>, Detailable {

	/**
	 * Default descriptor type: {@link DescriptorType#TYPE2 Type2PacketDescriptor}.
	 * 
	 * <p>
	 * The most versatile descriptor capable of storing full dissection tables, TX
	 * settings, color, hash, and various flags.
	 * </p>
	 */
	public static final DescriptorType DEFAULT_DESCRIPTOR_TYPE = DescriptorType.TYPE2;

	/**
	 * Default packet buffer length (65,536 bytes).
	 * 
	 * <p>
	 * Accommodates jumbo frames and TSO-reassembled packets up to 64KB.
	 * </p>
	 */
	public static final long DEFAULT_PACKET_LENGTH = 65_536;

	/**
	 * Creates a hybrid packet using the default descriptor type.
	 *
	 * @return new hybrid packet
	 * @see #ofHybridType(DescriptorType)
	 */
	public static Packet ofHybrid() {
		return ofHybridType(DEFAULT_DESCRIPTOR_TYPE);
	}

	/**
	 * Creates a hybrid packet with the specified descriptor type.
	 * 
	 * <p>
	 * Packet data uses {@link ScopedMemory} (zero-copy binding to native memory),
	 * while the descriptor uses {@link FixedMemory} for independent persistence.
	 * Ideal when converting native descriptors but keeping zero-copy data access.
	 * </p>
	 *
	 * @param type descriptor type
	 * @return new hybrid packet
	 */
	public static Packet ofHybridType(DescriptorType type) {
		PacketDescriptor descriptor = type.newPacketDescriptor();
		ScopedMemory dataMemory = new ScopedMemory();
		FixedMemory descMemory = new FixedMemory(descriptor.length());
		descriptor.bind(descMemory);

		return new Packet(dataMemory, descriptor);
	}

	/**
	 * Creates a scoped packet using the default descriptor type.
	 *
	 * @return new scoped packet
	 * @see #ofScopedType(DescriptorType)
	 */
	public static Packet ofScoped() {
		return ofScopedType(DEFAULT_DESCRIPTOR_TYPE);
	}

	/**
	 * Creates a scoped packet with the specified descriptor type.
	 * 
	 * <p>
	 * Both data and descriptor use {@link ScopedMemory} for direct zero-copy
	 * binding to native memory segments. Optimal for high-performance capture paths
	 * where packets are processed immediately and do not need persistence.
	 * </p>
	 *
	 * @param type descriptor type
	 * @return new scoped packet
	 */
	public static Packet ofScopedType(DescriptorType type) {
		ScopedMemory dataMemory = new ScopedMemory();
		ScopedMemory descMemory = new ScopedMemory();
		PacketDescriptor descriptor = type.newPacketDescriptor();
		descriptor.bind(descMemory);

		return new Packet(dataMemory, descriptor);
	}

	/** Packet descriptor holding dissection results and metadata. */
	private PacketDescriptor packetDescriptor;

	/**
	 * The memory view binding with assert checks for pooled packets. When java
	 * asserts are enabled, the binding checks to ensure that a pooled packet with
	 * complex structure is not being rebound to some other user memory. Pooled
	 * packets need to preserve their structure so that they can be reused. When
	 * assert is disabled (from command line), all these are no-ops and delegate to
	 * base class implementation.
	 */
	private final BoundView boundView = new BoundView() {
		/**
		 * {@inheritDoc}
		 * 
		 * <p>
		 * <b>Warning:</b> Manual rebinding of pooled packets corrupts the pool's
		 * pre-allocated structure. Check {@link #isPooled()} first.
		 * </p>
		 */
		@Override
		public void bind(BindableView view) {
			assert !isPooled() : "Rebinding pooled packet destroys pool structure";
			super.bind(view);
		}

		/**
		 * {@inheritDoc}
		 * 
		 * <p>
		 * <b>Warning:</b> Manual rebinding of pooled packets corrupts the pool's
		 * pre-allocated structure. Check {@link #isPooled()} first.
		 * </p>
		 */
		@Override
		public void bind(BindableView view, long offset) {
			assert !isPooled() : "Rebinding pooled packet destroys pool structure";
			super.bind(view, offset);
		}

		/**
		 * {@inheritDoc}
		 * 
		 * <p>
		 * <b>Warning:</b> Manual rebinding of pooled packets corrupts the pool's
		 * pre-allocated structure. Check {@link #isPooled()} first.
		 * </p>
		 */
		@Override
		public void bind(BindableView view, long offset, long length) {
			assert !isPooled() : "Rebinding pooled packet destroys pool structure";
			super.bind(view, offset, length);
		}

		/**
		 * {@inheritDoc}
		 * 
		 * <p>
		 * <b>Warning:</b> Manual rebinding of pooled packets corrupts the pool's
		 * pre-allocated structure. Check {@link #isPooled()} first.
		 * </p>
		 */
		@Override
		public void bind(Memory memory) {
			assert !isPooled() : "Rebinding pooled packet destroys pool structure";
			super.bind(memory);
		}

		/**
		 * {@inheritDoc}
		 * 
		 * <p>
		 * <b>Warning:</b> Manual rebinding of pooled packets corrupts the pool's
		 * pre-allocated structure. Check {@link #isPooled()} first.
		 * </p>
		 */
		@Override
		public void bind(Memory memory, long offset) {
			assert !isPooled() : "Rebinding pooled packet destroys pool structure";
			super.bind(memory, offset);
		}

		/**
		 * {@inheritDoc}
		 * 
		 * <p>
		 * <b>Warning:</b> Manual rebinding of pooled packets corrupts the pool's
		 * pre-allocated structure. Check {@link #isPooled()} first.
		 * </p>
		 */
		@Override
		public void bind(Memory memory, long offset, long length) {
			assert !isPooled() : "Rebinding pooled packet destroys pool structure";
			super.bind(memory, offset, length);
		}

		/**
		 * {@inheritDoc}
		 * 
		 * <p>
		 * <b>Warning:</b> Manual unbinding of pooled packets corrupts the pool. Use
		 * {@link #recycle()} instead.
		 * </p>
		 */
		@Override
		public void unbind() {
			assert !isPooled() : "Unbinding pooled packet destroys pool structure - use poolRecycle()";
			super.unbind();
		}
	};

	/**
	 * Internal pool entry managing lifecycle callbacks for pooled instances.
	 */
	public final PoolEntry poolEntry = new PoolEntry() {

		@Override
		protected void onAllocate() {
			// Packet is ready for new use; memory bindings are preserved from pool
		}

		@Override
		protected void onRecycle() {
			if (super.isPooled()) {
				boundMemory().unbindIfScoped();
				packetDescriptor.boundMemory().unbindIfScoped();
			} else {
				unbind();
			}
		}
	};

	/**
	 * Creates an unbound packet with the default {@link Type2PacketDescriptor}.
	 * 
	 * <p>
	 * The packet must be subsequently bound to memory (via {@link #bind(Memory)} or
	 * pool allocation) before use.
	 * </p>
	 */
	public Packet() {
		this(DescriptorType.DEFAULT_TYPE);
	}

	/**
	 * Creates an unbound packet with a specific descriptor type.
	 *
	 * @param descriptorType the descriptor type to use
	 */
	public Packet(DescriptorType descriptorType) {
		this.packetDescriptor = descriptorType.newPacketDescriptor();
	}

	/**
	 * Package-private constructor used by factory methods to create pre-configured
	 * packets.
	 *
	 * @param dataMemory pre-allocated memory for packet data (may be null)
	 * @param descriptor pre-created descriptor instance
	 */
	public Packet(Memory dataMemory, PacketDescriptor descriptor) {
		this.packetDescriptor = descriptor;
		if (dataMemory != null) {
			boundView.bind(dataMemory);
		}
	}

	@Override
	public BoundView boundView() {
		return boundView;
	}

	/**
	 * Builds detailed textual representation of the packet and its headers.
	 *
	 * @param detail builder to append detail information to
	 */
	@Override
	public void buildDetail(DetailBuilder detail) {
		for (BindingInfo info : packetDescriptor) {
			Header header = info.newBoundHeader(this);

			if (header == null) {
				detail.header("Unknown Protocol (0x%04X)".formatted(info.id()), "",
						info.id(), info.offset(), info.length(), _ -> {});
				continue;
			}

			if (header instanceof Detailable d) {
				d.buildDetail(detail);
			} else {
				detail.header(header.name(), "", info.id(), info.offset(), info.length(), _ -> {});
			}
		}
	}

	/**
	 * Returns the number of bytes captured from the wire (may be less than wire
	 * length if truncated).
	 *
	 * @return capture length in bytes
	 */
	public int captureLength() {
		return packetDescriptor.captureLength();
	}

	/**
	 * Creates a deep copy of this packet with independently allocated memory.
	 *
	 * @return new independent packet containing copied data and descriptor
	 */
	@Override
	public Packet copy() {
		long length = boundMemory().segment().byteSize();
		Packet target = newUnbound();

		Memory fixedPacket = Memory.of(length);
		target.bind(fixedPacket);

		Memory fixedDesc = Memory.of(packetDescriptor.length());
		target.packetDescriptor.bind(fixedDesc);

		return copyTo(target);
	}

	/**
	 * Copies packet data and descriptor into the provided target packet.
	 * 
	 * <p>
	 * Target must have sufficient pre-allocated capacity. Useful for copying into
	 * pooled packets without additional allocation.
	 * </p>
	 *
	 * @param target destination packet
	 * @return the target packet (for chaining)
	 * @throws IllegalArgumentException if target capacity is insufficient
	 */
	@Override
	public Packet copyTo(Packet target) {
		assert target != null : "Target packet cannot be null";
		assert target.boundMemory().segment().byteSize() >= this.captureLength()
				: "Target packet has insufficient data capacity";
		assert target.packetDescriptor.boundMemory().segment().byteSize() >= this.packetDescriptor.boundMemory()
				.segment().byteSize()
				: "Target packet has insufficient descriptor capacity";

		Persistable.super.copyTo(target);
		packetDescriptor.copyTo(target.descriptor());

		return target;
	}

	/**
	 * Returns the current packet descriptor.
	 *
	 * @return packet descriptor instance
	 */
	public PacketDescriptor descriptor() {
		return packetDescriptor;
	}

	/**
	 * Creates a shallow duplicate sharing memory references (reference-counted).
	 *
	 * @param target packet to duplicate into
	 * @return the target packet
	 */
	@Override
	public Packet duplicate(Packet target) {
		Persistable.super.duplicate(target);

		packetDescriptor.boundMemory().incrementRef();
		target.packetDescriptor.bind(this.packetDescriptor.boundView());

		return target;
	}

	/**
	 * Binds a reusable header instance to this packet (default depth 0).
	 *
	 * @param header header instance to bind
	 * @return {@code true} if protocol is present and header was bound
	 * @see #hasHeader(Header, int)
	 */
	public boolean hasHeader(Header header) {
		return hasHeader(header, 0);
	}

	/**
	 * Binds a reusable header instance at the specified occurrence depth.
	 *
	 * @param header header instance to bind
	 * @param depth  protocol occurrence (0 = outermost)
	 * @return {@code true} if protocol present at depth and header bound
	 */
	public boolean hasHeader(Header header, int depth) {
		return packetDescriptor.bindHeader(this, header, header.getProtocolId(), depth);
	}

	/**
	 * Checks whether this packet instance is managed by a pool.
	 *
	 * @return {@code true} if owned by a pool
	 */
	public boolean isPooled() {
		return poolEntry.isPooled();
	}

	/**
	 * Checks if a protocol is present (default depth 0).
	 *
	 * @param id protocol ID
	 * @return {@code true} if protocol present
	 */
	public boolean isPresent(int id) {
		return isPresent(id, 0);
	}

	/**
	 * Checks if a protocol is present at the specified depth.
	 *
	 * @param id    protocol ID
	 * @param depth occurrence depth (0 = outermost)
	 * @return {@code true} if protocol present at depth
	 */
	public boolean isPresent(int id, int depth) {
		long encoded = packetDescriptor.mapProtocol(id, depth);
		return encoded >= 0;
	}

	/**
	 * Creates a new unbound packet of the same descriptor type.
	 *
	 * @return new unbound packet instance
	 */
	@Override
	public Packet newUnbound() {
		return new Packet(descriptor().descriptorType());
	}

	/**
	 * Returns the internal pool entry for lifecycle management.
	 *
	 * @return pool entry (never null)
	 */
	@Override
	public PoolEntry poolEntry() {
		return poolEntry;
	}

	/**
	 * Returns RX offload/capabilities from the descriptor.
	 *
	 * @return RX capabilities
	 */
	public RxCapabilities rx() {
		return descriptor().rx();
	}

	/**
	 * Replaces the current packet descriptor.
	 * 
	 * <p>
	 * Typically used after dissection to attach new results.
	 * </p>
	 *
	 * @param descriptor new descriptor
	 */
	public void setDescriptor(PacketDescriptor descriptor) {
		assert descriptor != null : "Descriptor cannot be null";
		this.packetDescriptor = descriptor;
	}

	/**
	 * Returns the raw packet capture timestamp value.
	 *
	 * @return timestamp in native units
	 */
	public long timestamp() {
		return packetDescriptor.timestamp();
	}

	/**
	 * Returns the packet timestamp with resolution/unit information.
	 *
	 * @return {@link Timestamp} object
	 */
	public Timestamp timestampInfo() {
		return new Timestamp(packetDescriptor.timestamp(), packetDescriptor.timestampUnit());
	}

	/**
	 * Creates a string representation of the packet. Formats the three main packet
	 * fields into a typical object description string.
	 *
	 * @return formatted packet summary
	 */
	@Override
	public String toString() {
		String fmt = (captureLength() == wireLength())
				? "Packet [len=%,-6d ts=%3$s]"
				: "Packet [len=%,-6d wirelen=%,-6d ts=%s]";

		return fmt.formatted(captureLength(), wireLength(), timestampInfo().toString());
	}

	/**
	 * Returns a detailed string representation according to the specified detail
	 * level.
	 *
	 * @param detail detail level
	 * @return formatted packet summary or full dissection
	 */
	public String toString(Detail detail) {
		if (detail == Detail.OFF)
			return toString();

		return new TextRenderer(detail).render(getDetail());
	}

	/**
	 * Returns TX offload/capabilities from the descriptor.
	 *
	 * @return TX capabilities
	 */
	public TxCapabilities tx() {
		return descriptor().tx();
	}

	/**
	 * Returns the original wire length of the packet (before any capture
	 * truncation).
	 *
	 * @return wire length in bytes
	 */
	public int wireLength() {
		return packetDescriptor.wireLength();
	}
}