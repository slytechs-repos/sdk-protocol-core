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
package com.slytechs.sdk.protocol.core;

import java.lang.foreign.MemorySegment;
import java.nio.ByteOrder;

import com.slytechs.sdk.common.detail.DetailBuilder;
import com.slytechs.sdk.common.detail.Detailable;
import com.slytechs.sdk.common.memory.BindableView;
import com.slytechs.sdk.common.memory.BoundView;
import com.slytechs.sdk.common.memory.FixedMemory;
import com.slytechs.sdk.common.memory.Memory;
import com.slytechs.sdk.common.memory.ScopedMemory;
import com.slytechs.sdk.common.memory.pool.Persistable;
import com.slytechs.sdk.common.memory.pool.Pool;
import com.slytechs.sdk.common.memory.pool.PoolEntry;
import com.slytechs.sdk.common.memory.pool.Poolable;
import com.slytechs.sdk.common.memory.pool.SlabAllocator;
import com.slytechs.sdk.common.time.Timestamp;
import com.slytechs.sdk.protocol.core.descriptor.DescriptorInfo;
import com.slytechs.sdk.protocol.core.descriptor.NetPacketDescriptor;
import com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor;
import com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor.BindingInfo;
import com.slytechs.sdk.protocol.core.descriptor.PacketTag;
import com.slytechs.sdk.protocol.core.descriptor.PcapDescriptorPacked;
import com.slytechs.sdk.protocol.core.descriptor.PcapDescriptorPadded;
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
public class Packet extends BoundView
		implements Poolable, Persistable<Packet>, Detailable {

	/**
	 * The Constant DEFAULT_DESCRIPTOR_TYPE set to NetPacketDescriptor type. Net
	 * descriptor type is the most versitile descriptor type, capable of storing
	 * full packet dissection table as well as, TX settings, color, hash and many
	 * flag types.
	 */
	private static final DescriptorInfo DEFAULT_DESCRIPTOR_TYPE = DescriptorInfo.NET;

	/**
	 * The Constant DEFAULT_PACKET_LENGTH. The packet length with TSO (TCP Segment
	 * Offload, a common NIC feature) can be up to 64KB when TCP segments are
	 * reassembled before capture.
	 */
	private static final long DEFAULT_PACKET_LENGTH = 65_536;

	/**
	 * Creates a descriptor of the specified type.
	 */
	private static PacketDescriptor createDescriptor(DescriptorInfo type) {
		return switch (type) {
		case NET -> new NetPacketDescriptor();
		case PCAP_PACKED -> PcapDescriptorPacked.of(ByteOrder.nativeOrder());
		case PCAP_PADDED -> new PcapDescriptorPadded();
		default -> throw new IllegalArgumentException("Unsupported descriptor type: " + type);
		};
	}

	/**
	 * Creates a fixed packet with slab-allocated memory.
	 * 
	 * <p>
	 * Both data and descriptor use {@link FixedMemory} allocated from the provided
	 * slab allocator. Data is copied into this memory and persists across recycle
	 * cycles.
	 * </p>
	 *
	 * @param allocator the slab allocator for memory allocation
	 * @return a new fixed packet
	 */
	public static Packet ofFixed(SlabAllocator allocator) {
		return ofFixedType(allocator, DEFAULT_PACKET_LENGTH, DEFAULT_DESCRIPTOR_TYPE); // Default jumbo frame size
	}

	/**
	 * Creates a fixed packet with slab-allocated memory of specified size.
	 *
	 * @param allocator the slab allocator for memory allocation
	 * @param dataSize  the size of the data buffer in bytes
	 * @return a new fixed packet
	 */
	public static Packet ofFixed(SlabAllocator allocator, long dataSize) {
		return ofFixedType(allocator, dataSize, DEFAULT_DESCRIPTOR_TYPE);
	}

	/**
	 * Creates a fixed packet with slab-allocated memory.
	 * 
	 * <p>
	 * Both data and descriptor use {@link FixedMemory} allocated from the provided
	 * slab allocator. Data is copied into this memory and persists across recycle
	 * cycles.
	 * </p>
	 *
	 * @param allocator the slab allocator for memory allocation
	 * @return a new fixed packet
	 */
	public static Packet ofFixedType(SlabAllocator allocator, DescriptorInfo type) {
		return ofFixedType(allocator, DEFAULT_PACKET_LENGTH, type); // Default jumbo frame size
	}

	/**
	 * Creates a fixed packet with slab-allocated memory of specified size.
	 *
	 * @param allocator the slab allocator for memory allocation
	 * @param dataSize  the size of the data buffer in bytes
	 * @return a new fixed packet
	 */
	public static Packet ofFixedType(SlabAllocator allocator, long dataSize, DescriptorInfo type) {
		PacketDescriptor descriptor = createDescriptor(type);
		MemorySegment dataSeg = allocator.allocate(dataSize, 8);
		MemorySegment descSeg = allocator.allocate(descriptor.length(), 8);

		FixedMemory dataMemory = new FixedMemory(dataSeg);
		FixedMemory descMemory = new FixedMemory(descSeg);
		descriptor.bind(descMemory);

		Packet packet = new Packet(dataMemory, descriptor);
		packet.poolEntry.bindSlab(allocator, dataSeg);

		return packet;
	}

	/**
	 * Creates a hybrid packet with scoped data and fixed descriptor.
	 * 
	 * <p>
	 * Data uses {@link ScopedMemory} for zero-copy native access, while the
	 * descriptor uses {@link FixedMemory} for persistence. Useful when native
	 * descriptors need conversion while data remains zero-copy.
	 * </p>
	 *
	 * @return a new hybrid packet
	 */
	public static Packet ofHybrid() {
		return ofHybridType(DEFAULT_DESCRIPTOR_TYPE);
	}

	/**
	 * Creates a hybrid packet with scoped data and fixed descriptor.
	 * 
	 * <p>
	 * Data uses {@link ScopedMemory} for zero-copy native access, while the
	 * descriptor uses {@link FixedMemory} for persistence. Useful when native
	 * descriptors need conversion while data remains zero-copy.
	 * </p>
	 *
	 * @return a new hybrid packet
	 */
	public static Packet ofHybridType(DescriptorInfo type) {
		PacketDescriptor descriptor = createDescriptor(type);
		ScopedMemory dataMemory = new ScopedMemory();
		FixedMemory descMemory = new FixedMemory(descriptor.length());
		descriptor.bind(descMemory);

		return new Packet(dataMemory, descriptor);
	}

	/**
	 * Creates a scoped packet for zero-copy capture.
	 * 
	 * <p>
	 * Both data and descriptor use {@link ScopedMemory} that binds directly to
	 * native segments without copying. Ideal for high-speed capture where packets
	 * don't need to persist beyond immediate processing.
	 * </p>
	 *
	 * @return a new scoped packet
	 */
	public static Packet ofScoped() {
		return ofScopedType(DEFAULT_DESCRIPTOR_TYPE);

	}

	/**
	 * Creates a scoped packet for zero-copy capture.
	 * 
	 * <p>
	 * Both data and descriptor use {@link ScopedMemory} that binds directly to
	 * native segments without copying. Ideal for high-speed capture where packets
	 * don't need to persist beyond immediate processing.
	 * </p>
	 *
	 * @return a new scoped packet
	 */
	public static Packet ofScopedType(DescriptorInfo type) {
		ScopedMemory dataMemory = new ScopedMemory();
		ScopedMemory descMemory = new ScopedMemory();
		PacketDescriptor descriptor = createDescriptor(type);
		descriptor.bind(descMemory);

		return new Packet(dataMemory, descriptor);
	}

	/** The packet descriptor containing dissection results. */
	private PacketDescriptor packetDescriptor;

	// =========================================================================
	// Factory Methods
	// =========================================================================

	/** Head of the packet tag chain for extended metadata. */
	private PacketTag headTag;

	/**
	 * Pool entry for pool lifecycle management.
	 * 
	 * <p>
	 * Handles allocation/recycle callbacks and maintains pool linkage. The inner
	 * class pattern gives callbacks access to packet fields.
	 * </p>
	 */
	private final PoolEntry poolEntry = new PoolEntry() {

		@Override
		protected void onAllocate() {
			// Ready for new use - bindings preserved from pool structure
		}

		@Override
		protected void onEvict() {
			super.onEvict();
			// Additional cleanup if needed when permanently removed from pool
		}

		@Override
		protected void onRecycle() {
			// Reset packet state for reuse
			headTag = null;

			if (isPooled()) {
				// Pooled packets: preserve data/descriptor view structures,
				// only unbind scoped segments (FixedMemory.unbindIfScoped is no-op)
				boundMemory().unbindIfScoped();
				packetDescriptor.boundMemory().unbindIfScoped();
			} else {
				// Non-pooled packets: full unbind, view can be reused elsewhere
				unbind();
			}
		}
	};

	/**
	 * Constructs an unbound packet.
	 * 
	 * <p>
	 * The packet must be bound to memory before use, either directly via
	 * {@link #bind(Memory)} or through pool allocation.
	 * </p>
	 */
	public Packet() {
		this.packetDescriptor = new NetPacketDescriptor();
	}

	/**
	 * Constructs a packet with the specified descriptor type.
	 *
	 * @param descriptorType the descriptor type to use
	 */
	public Packet(DescriptorInfo descriptorType) {
		this.packetDescriptor = createDescriptor(descriptorType);
	}

	// =========================================================================
	// Pool Management
	// =========================================================================

	/**
	 * Constructs a packet with pre-allocated memory structures.
	 * 
	 * <p>
	 * Used by pool factories to create packets with specific memory configurations.
	 * </p>
	 *
	 * @param dataMemory the memory for packet data
	 * @param descriptor the packet descriptor
	 */
	protected Packet(Memory dataMemory, PacketDescriptor descriptor) {
		this.packetDescriptor = descriptor;
		if (dataMemory != null) {
			super.bind(dataMemory);
		}
	}

	/**
	 * Adds a tag to the packet tag chain.
	 *
	 * @param tag the tag to add
	 */
	public void addTag(PacketTag tag) {
		assert tag != null : "Tag cannot be null";
		tag.setNext(headTag);
		headTag = tag;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * <b>Warning:</b> For pooled packets, rebinding destroys the pool's
	 * pre-allocated structure. Use {@link #isPooled()} to check before manual
	 * rebinding.
	 * </p>
	 *
	 * @param view the view to bind to
	 * @throws AssertionError if assertions enabled and packet is pooled
	 */
	@Override
	public void bind(BindableView view) {
		assert !isPooled() : "Rebinding pooled packet destroys pool structure - use isPooled() to check";
		super.bind(view);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * <b>Warning:</b> For pooled packets, rebinding destroys the pool's
	 * pre-allocated structure. Use {@link #isPooled()} to check before manual
	 * rebinding.
	 * </p>
	 *
	 * @param view   the view to bind to
	 * @param offset the offset within the view's active data
	 * @throws AssertionError if assertions enabled and packet is pooled
	 */
	@Override
	public void bind(BindableView view, long offset) {
		assert !isPooled() : "Rebinding pooled packet destroys pool structure - use isPooled() to check";
		super.bind(view, offset);
	}

	// =========================================================================
	// Binding Overrides (with pool protection assertions)
	// =========================================================================

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * <b>Warning:</b> For pooled packets, rebinding destroys the pool's
	 * pre-allocated structure. Use {@link #isPooled()} to check before manual
	 * rebinding.
	 * </p>
	 *
	 * @param view   the view to bind to
	 * @param offset the offset within the view's active data
	 * @param length the length of the new view
	 * @throws AssertionError if assertions enabled and packet is pooled
	 */
	@Override
	public void bind(BindableView view, long offset, long length) {
		assert !isPooled() : "Rebinding pooled packet destroys pool structure - use isPooled() to check";
		super.bind(view, offset, length);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * <b>Warning:</b> For pooled packets, rebinding destroys the pool's
	 * pre-allocated structure. Use {@link #isPooled()} to check before manual
	 * rebinding.
	 * </p>
	 *
	 * @param memory the memory to bind to
	 * @throws AssertionError if assertions enabled and packet is pooled
	 */
	@Override
	public void bind(Memory memory) {
		assert !isPooled() : "Rebinding pooled packet destroys pool structure - use isPooled() to check";
		super.bind(memory);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * <b>Warning:</b> For pooled packets, rebinding destroys the pool's
	 * pre-allocated structure. Use {@link #isPooled()} to check before manual
	 * rebinding.
	 * </p>
	 *
	 * @param memory the memory to bind to
	 * @param offset the offset within the memory's active data
	 * @throws AssertionError if assertions enabled and packet is pooled
	 */
	@Override
	public void bind(Memory memory, long offset) {
		assert !isPooled() : "Rebinding pooled packet destroys pool structure - use isPooled() to check";
		super.bind(memory, offset);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * <b>Warning:</b> For pooled packets, rebinding destroys the pool's
	 * pre-allocated structure. Use {@link #isPooled()} to check before manual
	 * rebinding.
	 * </p>
	 *
	 * @param memory the memory to bind to
	 * @param offset the offset within the memory's active data
	 * @param length the length of the view
	 * @throws AssertionError if assertions enabled and packet is pooled
	 */
	@Override
	public void bind(Memory memory, long offset, long length) {
		assert !isPooled() : "Rebinding pooled packet destroys pool structure - use isPooled() to check";
		super.bind(memory, offset, length);
	}

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
	 * Returns the capture length in bytes.
	 * 
	 * <p>
	 * This is the number of bytes actually captured and available in the packet
	 * data. May be less than {@link #wireLength()} if the packet was truncated
	 * during capture.
	 * </p>
	 *
	 * @return the captured length in bytes
	 */
	public int captureLength() {
		return packetDescriptor.captureLength();
	}

	/**
	 * Clears all tags from this packet.
	 */
	public void clearTags() {
		headTag = null;
	}

	/**
	 * @see com.slytechs.sdk.common.memory.pool.Persistable#copy()
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
	 * Copies this packet's data and descriptor into the target packet.
	 * 
	 * <p>
	 * The target packet must have sufficient capacity for both data and descriptor.
	 * This method is useful for copying into pooled packets to avoid allocation.
	 * </p>
	 * 
	 * <pre>{@code
	 * Pool<Packet> copyPool = PacketPool.ofFixed();
	 * Packet target = copyPool.allocate(packet.captureLength());
	 * packet.copyTo(target);
	 * // target now contains copy of packet data
	 * }</pre>
	 *
	 * @param target the target packet to copy into
	 * @throws IllegalArgumentException if target has insufficient capacity
	 */
	@Override
	public Packet copyTo(Packet target) {
		assert target != null : "Target packet cannot be null";
		assert target.boundMemory().segment().byteSize() >= this.captureLength()
				: "Target packet has insufficient data capacity, boundMemory length=" + target.boundMemory()
						+ ", captureLength=" + this.captureLength();
		assert target.packetDescriptor.boundMemory().segment().byteSize() >= this.packetDescriptor.boundMemory()
				.segment().byteSize()
				: "Target packet has insufficient descriptor capacity";

		// Copy packet data
		Persistable.super.copyTo(target);

		// Copy descriptor
		packetDescriptor.copyTo(target.descriptor());

		// Copy tags if present
		if (headTag != null) {
			target.headTag = headTag.copy();
		} else {
			target.headTag = null;
		}

		return target;
	}

	/**
	 * Returns the packet descriptor containing dissection results.
	 * 
	 * <p>
	 * The descriptor provides protocol presence information and header
	 * offset/length data for efficient header access.
	 * </p>
	 *
	 * @return the packet descriptor
	 */
	public PacketDescriptor descriptor() {
		return packetDescriptor;
	}

	/**
	 * @see com.slytechs.sdk.common.memory.pool.Persistable#duplicate(com.slytechs.sdk.common.memory.pool.Persistable)
	 */
	@Override
	public Packet duplicate(Packet target) {
		Persistable.super.duplicate(target);

		// Descriptor shared
		packetDescriptor.boundMemory().incrementRef();
		target.packetDescriptor.bind(this.packetDescriptor.boundView());

		target.headTag = this.headTag;
		return target;
	}

	/**
	 * Returns the head of the packet tag chain.
	 *
	 * @return the first tag, or null if no tags
	 */
	public PacketTag getTags() {
		return headTag;
	}

	/**
	 * Binds a header instance to this packet if the protocol is present.
	 * 
	 * <p>
	 * This is the primary zero-allocation header access pattern. The same header
	 * instance can be reused across packets.
	 * </p>
	 * 
	 * <pre>{@code
	 * Tcp tcp = new Tcp();
	 * if (packet.hasHeader(tcp)) {
	 * 	int srcPort = tcp.srcPort();
	 * 	int dstPort = tcp.dstPort();
	 * }
	 * }</pre>
	 *
	 * @param header the header instance to bind
	 * @return true if the header was bound (protocol present)
	 */
	public boolean hasHeader(Header header) {
		return hasHeader(header, 0);
	}

	/**
	 * Binds a header instance at the specified depth.
	 *
	 * @param header the header instance to bind
	 * @param depth  the occurrence depth (0 = first/outer)
	 * @return true if the header was bound
	 */
	public boolean hasHeader(Header header, int depth) {
		return packetDescriptor.bindHeader(this, header, header.getProtocolId(), depth);
	}

	/**
	 * Checks if this packet is owned by a pool.
	 *
	 * @return true if this packet belongs to a pool
	 */
	public boolean isPooled() {
		return poolEntry.isPooled();
	}

	/**
	 * Checks if a protocol header is present in this packet.
	 *
	 * @param id the protocol ID constant
	 * @return true if the protocol is present
	 */
	public boolean isPresent(int id) {
		return isPresent(id, 0);
	}

	/**
	 * Checks if a protocol header is present at the specified depth.
	 * 
	 * <p>
	 * Depth is used for tunneled protocols where multiple instances of the same
	 * protocol may be present (e.g., outer IP vs inner IP).
	 * </p>
	 *
	 * @param id    the protocol ID constant
	 * @param depth the occurrence depth (0 = first/outer)
	 * @return true if the protocol is present at the specified depth
	 */
	public boolean isPresent(int id, int depth) {
		long encoded = packetDescriptor.mapProtocol(id, depth);
		return encoded >= 0;
	}

	/**
	 * @see com.slytechs.sdk.common.memory.pool.Persistable#newUnbound()
	 */
	@Override
	public Packet newUnbound() {
		return new Packet(descriptor().descriptorInfo());
	}

	/**
	 * Returns the pool that owns this packet.
	 * 
	 * <p>
	 * The returned pool is always typed as {@code Pool<Packet>} since packets are
	 * only ever allocated from packet pools.
	 * </p>
	 *
	 * @return the owning pool, or null if not pooled
	 */
	@SuppressWarnings("unchecked")
	public Pool<Packet> pool() {
		return (Pool<Packet>) poolEntry.owningPool();
	}

	/**
	 * Returns the pool entry for pool lifecycle management.
	 *
	 * @return the pool entry (never null)
	 */
	@Override
	public PoolEntry poolEntry() {
		return poolEntry;
	}

	/**
	 * Returns this packet to its owning pool.
	 * 
	 * <p>
	 * If this packet was allocated from a pool, it is returned to that pool for
	 * reuse. The {@code onRecycle()} callback clears packet state and unbinds
	 * scoped memory while preserving pool structure.
	 * </p>
	 * 
	 * <p>
	 * If this packet is not pooled, this method does nothing.
	 * </p>
	 */
	@Override
	public void poolRecycle() {
		poolEntry.recycle();
	}

	/**
	 * Removes a tag from the packet tag chain.
	 *
	 * @param tag the tag to remove
	 * @return true if the tag was found and removed
	 */
	public boolean removeTag(PacketTag tag) {
		if (headTag == tag) {
			headTag = tag.next();
			return true;
		}

		PacketTag current = headTag;
		while (current != null && current.next() != null) {
			if (current.next() == tag) {
				current.setNext(tag.next());
				return true;
			}
			current = current.next();
		}

		return false;
	}

	/**
	 * Sets the packet descriptor containing dissection results.
	 * 
	 * <p>
	 * The descriptor is typically produced by a dissector after analyzing the
	 * packet data.
	 * </p>
	 *
	 * @param descriptor the packet descriptor to set
	 */
	public void setDescriptor(PacketDescriptor descriptor) {
		assert descriptor != null : "Descriptor cannot be null";
		this.packetDescriptor = descriptor;
	}

	/**
	 * Returns the packet capture timestamp.
	 *
	 * @return the timestamp value
	 */
	public long timestamp() {
		return packetDescriptor.timestamp();
	}

	/**
	 * Returns the packet timestamp with unit information.
	 *
	 * @return the timestamp info
	 */
	public Timestamp timestampInfo() {
		return new Timestamp(packetDescriptor.timestamp(), packetDescriptor.timestampUnit());
	}

	@Override
	public String toString() {
		return toDetailString();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * <b>Warning:</b> For pooled packets, unbinding destroys the pool's
	 * pre-allocated structure. Use {@link #isPooled()} to check before manual
	 * unbinding. Use {@link #poolRecycle()} instead to properly return pooled
	 * packets.
	 * </p>
	 *
	 * @throws AssertionError if assertions enabled and packet is pooled
	 */
	@Override
	public void unbind() {
		assert !isPooled() : "Unbinding pooled packet destroys pool structure - use recycle() instead";
		super.unbind();
	}

	/**
	 * Returns the wire length in bytes.
	 * 
	 * <p>
	 * This is the original size of the packet as it appeared on the network, which
	 * may be larger than {@link #captureLength()} if truncated.
	 * </p>
	 *
	 * @return the original packet size in bytes
	 */
	public int wireLength() {
		return packetDescriptor.wireLength();
	}
}