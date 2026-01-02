/*
 * Apache License, Version 2.0
 * 
 * Copyright 2005-2025 Sly Technologies Inc.
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
package com.slytechs.sdk.protocol.core;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.slytechs.sdk.common.memory.Memory;
import com.slytechs.sdk.common.memory.ScopedMemory;
import com.slytechs.sdk.common.memory.pool.FreeListPool;
import com.slytechs.sdk.common.memory.pool.Pool;
import com.slytechs.sdk.common.memory.pool.PoolSettings;
import com.slytechs.sdk.protocol.core.descriptor.DescriptorInfo;
import com.slytechs.sdk.protocol.core.descriptor.PcapDescriptorPadded;

/**
 * Comprehensive test suite for the {@link Packet} class.
 * 
 * <p>
 * Tests cover packet creation, binding, persistence, copying, pooling,
 * and descriptor access using {@link DescriptorInfo#PCAP_PADDED}.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
@DisplayName("Packet Tests")
class PacketTest {

    /** Sample Ethernet frame: Dst MAC + Src MAC + EtherType (IPv4) + payload */
    private static final byte[] SAMPLE_PACKET = {
        // Ethernet header (14 bytes)
        (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55,  // Dst MAC
        (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB,  // Src MAC
        (byte) 0x08, (byte) 0x00,  // EtherType: IPv4
        // IPv4 header (20 bytes minimum)
        (byte) 0x45, (byte) 0x00, (byte) 0x00, (byte) 0x28,  // Version, IHL, TOS, Total Length
        (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,  // ID, Flags, Fragment Offset
        (byte) 0x40, (byte) 0x06, (byte) 0x00, (byte) 0x00,  // TTL, Protocol (TCP), Checksum
        (byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x01,  // Src IP: 192.168.1.1
        (byte) 0xC0, (byte) 0xA8, (byte) 0x01, (byte) 0x02,  // Dst IP: 192.168.1.2
        // TCP header (20 bytes)
        (byte) 0x00, (byte) 0x50, (byte) 0x1F, (byte) 0x90,  // Src Port: 80, Dst Port: 8080
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,  // Sequence Number
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,  // Ack Number
        (byte) 0x50, (byte) 0x02, (byte) 0x20, (byte) 0x00,  // Data Offset, Flags (SYN), Window
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00   // Checksum, Urgent Pointer
    };

    private static final int PACKET_LENGTH = SAMPLE_PACKET.length;  // 54 bytes

    /** PCAP_PACKED header values */
    private static final int PCAP_TS_SEC = 1704067200;   // 2024-01-01 00:00:00 UTC
    private static final int PCAP_TS_USEC = 123456;
    private static final int PCAP_CAPLEN = PACKET_LENGTH;
    private static final int PCAP_WIRELEN = PACKET_LENGTH;

    /**
     * Creates a memory segment with sample packet data.
     */
    private MemorySegment createPacketData(Arena arena) {
        MemorySegment seg = arena.allocate(PACKET_LENGTH, 8);
        for (int i = 0; i < SAMPLE_PACKET.length; i++) {
            seg.set(ValueLayout.JAVA_BYTE, i, SAMPLE_PACKET[i]);
        }
        return seg;
    }

    /**
     * Creates a PCAP_PACKED header segment.
     */
    private MemorySegment createPcapHeader(Arena arena) {
        // PCAP_PACKED header: ts_sec (4) + ts_usec (4) + caplen (4) + wirelen (4) = 16 bytes
        MemorySegment seg = arena.allocate(PcapDescriptorPadded.BYTE_SIZE, 8);
        seg.set(ValueLayout.JAVA_INT, 0, PCAP_TS_SEC);
        seg.set(ValueLayout.JAVA_INT, 8, PCAP_TS_USEC);
        seg.set(ValueLayout.JAVA_INT, 16, PCAP_CAPLEN);
        seg.set(ValueLayout.JAVA_INT, 20, PCAP_WIRELEN);
        return seg;
    }

    @Nested
    @DisplayName("Construction Tests")
    class ConstructionTests {

        @Test
        @DisplayName("Default constructor creates unbound packet")
        void defaultConstructorCreatesUnbound() {
            Packet packet = new Packet();
            
            assertFalse(packet.isBound(), "New packet should be unbound");
            assertNotNull(packet.descriptor(), "Descriptor should not be null");
        }

        @Test
        @DisplayName("Constructor with descriptor type creates correct descriptor")
        void constructorWithDescriptorType() {
            Packet packet = new Packet(DescriptorInfo.PCAP_PADDED);
            
            assertNotNull(packet.descriptor());
            assertEquals(DescriptorInfo.PCAP_PADDED, packet.descriptor().descriptorInfo());
        }

        @Test
        @DisplayName("ofScoped creates scoped packet")
        void ofScopedCreatesScopedPacket() {
            Packet packet = Packet.ofScoped();
            
            assertNotNull(packet);
            assertFalse(packet.isPersistent(), "Scoped packet should not be persistent");
        }

        @Test
        @DisplayName("ofHybrid creates hybrid packet")
        void ofHybridCreatesHybridPacket() {
            Packet packet = Packet.ofHybrid();
            
            assertNotNull(packet);
            // Hybrid has scoped data, fixed descriptor
            assertFalse(packet.isPersistent(), "Hybrid packet data should not be persistent");
        }
    }

    @Nested
    @DisplayName("Binding Tests")
    class BindingTests {

        private Arena arena;

        @BeforeEach
        void setUp() {
            arena = Arena.ofConfined();
        }

        @Test
        @DisplayName("Bind to fixed memory makes packet persistent")
        void bindToFixedMemoryMakesPersistent() {
            Packet packet = new Packet(DescriptorInfo.PCAP_PADDED);
            Memory fixed = Memory.of(PACKET_LENGTH);
            
            packet.bind(fixed);
            
            assertTrue(packet.isBound());
            assertTrue(packet.isPersistent());
        }

        @Test
        @DisplayName("Bind to scoped memory makes packet non-persistent")
        void bindToScopedMemoryMakesNonPersistent() {
            Packet packet = new Packet(DescriptorInfo.PCAP_PADDED);
            ScopedMemory scoped = new ScopedMemory();
            MemorySegment seg = createPacketData(arena);
            scoped.bind(seg, 0, PACKET_LENGTH);
            
            packet.bind(scoped);
            
            assertTrue(packet.isBound());
            assertFalse(packet.isPersistent());
        }

        @Test
        @DisplayName("Unbind clears binding")
        void unbindClearsBinding() {
            Packet packet = new Packet(DescriptorInfo.PCAP_PADDED);
            Memory fixed = Memory.of(PACKET_LENGTH);
            packet.bind(fixed);
            
            packet.unbind();
            
            assertFalse(packet.isBound());
        }

        @Test
        @DisplayName("Bound packet provides segment access")
        void boundPacketProvidesSegmentAccess() {
            Packet packet = new Packet(DescriptorInfo.PCAP_PADDED);
            Memory fixed = Memory.of(PACKET_LENGTH);
            packet.bind(fixed);
            
            // Write data
            MemorySegment seg = packet.boundMemory().segment();
            for (int i = 0; i < SAMPLE_PACKET.length; i++) {
                seg.set(ValueLayout.JAVA_BYTE, i, SAMPLE_PACKET[i]);
            }
            
            // Verify
            assertEquals(SAMPLE_PACKET[0], seg.get(ValueLayout.JAVA_BYTE, 0));
            assertEquals(SAMPLE_PACKET[12], seg.get(ValueLayout.JAVA_BYTE, 12));  // EtherType high byte
        }
    }

    @Nested
    @DisplayName("Descriptor Tests")
    class DescriptorTests {

        private Arena arena;
        private Packet packet;

        @BeforeEach
        void setUp() {
            arena = Arena.ofConfined();
            packet = new Packet(DescriptorInfo.PCAP_PADDED);
            
            // Bind packet data
            Memory dataMemory = Memory.of(PACKET_LENGTH);
            MemorySegment dataSeg = dataMemory.segment();
            for (int i = 0; i < SAMPLE_PACKET.length; i++) {
                dataSeg.set(ValueLayout.JAVA_BYTE, i, SAMPLE_PACKET[i]);
            }
            packet.bind(dataMemory);
            
            // Bind descriptor
            Memory descMemory = Memory.of(PcapDescriptorPadded.DEFAULT_DESCRIPTOR_SIZE);
            MemorySegment descSeg = descMemory.segment();
            descSeg.set(ValueLayout.JAVA_INT, 0, PCAP_TS_SEC);
            descSeg.set(ValueLayout.JAVA_INT, 8, PCAP_TS_USEC);
            descSeg.set(ValueLayout.JAVA_INT, 16, PCAP_CAPLEN);
            descSeg.set(ValueLayout.JAVA_INT, 20, PCAP_WIRELEN);
            packet.descriptor().bind(descMemory);
        }

        @Test
        @DisplayName("Descriptor returns correct capture length")
        void descriptorReturnsCaptureLength() {
            assertEquals(PCAP_CAPLEN, packet.captureLength());
        }

        @Test
        @DisplayName("Descriptor returns correct wire length")
        void descriptorReturnsWireLength() {
            assertEquals(PCAP_WIRELEN, packet.wireLength());
        }

        @Test
        @DisplayName("Descriptor returns correct timestamp")
        void descriptorReturnsTimestamp() {
            long timestamp = packet.timestamp();
            // Timestamp format depends on descriptor implementation
            assertNotEquals(0, timestamp, "Timestamp should be set");
        }

        @Test
        @DisplayName("setDescriptor replaces descriptor")
        void setDescriptorReplacesDescriptor() {
            PcapDescriptorPadded newDesc = new PcapDescriptorPadded();
            Memory descMemory = Memory.of(PcapDescriptorPadded.BYTE_SIZE);
            newDesc.bind(descMemory);
            
            packet.setDescriptor(newDesc);
            
            assertSame(newDesc, packet.descriptor());
        }
    }

    @Nested
    @DisplayName("Persistence Tests")
    class PersistenceTests {

        private Arena arena;

        @BeforeEach
        void setUp() {
            arena = Arena.ofConfined();
        }

        @Test
        @DisplayName("isPersistent returns true for fixed memory")
        void isPersistentReturnsTrueForFixed() {
            Packet packet = new Packet(DescriptorInfo.PCAP_PADDED);
            Memory fixed = Memory.of(PACKET_LENGTH);
            packet.bind(fixed);
            
            assertTrue(packet.isPersistent());
        }

        @Test
        @DisplayName("isPersistent returns false for scoped memory")
        void isPersistentReturnsFalseForScoped() {
            Packet packet = Packet.ofScoped();
            ScopedMemory scoped = new ScopedMemory();
            scoped.bind(createPacketData(arena), 0, PACKET_LENGTH);
            packet.bind(scoped);
            
            assertFalse(packet.isPersistent());
        }

        @Test
        @DisplayName("persist on fixed returns same instance")
        void persistOnFixedReturnsSame() {
            Packet packet = new Packet(DescriptorInfo.PCAP_PADDED);
            Memory fixed = Memory.of(PACKET_LENGTH);
            packet.bind(fixed);
            
            Packet result = packet.persist();
            
            assertSame(packet, result);
        }

        @Test
        @DisplayName("persist on scoped returns new persistent copy")
        void persistOnScopedReturnsNewCopy() {
            Packet packet = Packet.ofScopedType(DescriptorInfo.PCAP_PADDED);
            ScopedMemory scoped = new ScopedMemory();
            scoped.bind(createPacketData(arena), 0, PACKET_LENGTH);
            packet.bind(scoped);
            
            // Setup descriptor - use PcapDescriptorPadded's actual layout
            ScopedMemory descScoped = new ScopedMemory();
            MemorySegment descSeg = arena.allocate(PcapDescriptorPadded.BYTE_SIZE, 8);
            
            // Use descriptor's setters instead of manual offsets if available:
            // Or ensure offsets match what PcapDescriptorPadded expects
            descSeg.set(ValueLayout.JAVA_INT, 0, PCAP_TS_SEC);
            descSeg.set(ValueLayout.JAVA_INT, 8, PCAP_TS_USEC);
            descSeg.set(ValueLayout.JAVA_INT.withOrder(ByteOrder.nativeOrder()), 16, PACKET_LENGTH);  // caplen = 54
            descSeg.set(ValueLayout.JAVA_INT.withOrder(ByteOrder.nativeOrder()), 20, PACKET_LENGTH);  // wirelen = 54
            
            descScoped.bind(descSeg, 0, PcapDescriptorPadded.BYTE_SIZE);
            packet.descriptor().bind(descScoped);
            
            // Verify before persist
            assertEquals(PACKET_LENGTH, packet.captureLength(), "captureLength should be set");
            
            Packet result = packet.persist();
            
            assertNotSame(packet, result);
            assertTrue(result.isPersistent());
        }
    }

    @Nested
    @DisplayName("Copy Tests")
    class CopyTests {

        private Packet sourcePacket;
        private Arena arena;

        @BeforeEach
        void setUp() {
            arena = Arena.ofConfined();
            sourcePacket = new Packet(DescriptorInfo.PCAP_PADDED);
            
            // Bind data
            Memory dataMemory = Memory.of(PACKET_LENGTH);
            MemorySegment dataSeg = dataMemory.segment();
            for (int i = 0; i < SAMPLE_PACKET.length; i++) {
                dataSeg.set(ValueLayout.JAVA_BYTE, i, SAMPLE_PACKET[i]);
            }
            sourcePacket.bind(dataMemory);
            
            // Bind descriptor
            Memory descMemory = Memory.of(PcapDescriptorPadded.BYTE_SIZE);
            MemorySegment descSeg = descMemory.segment();
            descSeg.set(ValueLayout.JAVA_INT, 0, PCAP_TS_SEC);
            descSeg.set(ValueLayout.JAVA_INT, 4, PCAP_TS_USEC);
            descSeg.set(ValueLayout.JAVA_INT, 8, PCAP_CAPLEN);
            descSeg.set(ValueLayout.JAVA_INT, 12, PCAP_WIRELEN);
            sourcePacket.descriptor().bind(descMemory);
        }

        @Test
        @DisplayName("copy creates independent instance")
        void copyCreatesIndependentInstance() {
            Packet copy = sourcePacket.copy();
            
            assertNotSame(sourcePacket, copy);
            assertTrue(copy.isPersistent());
        }

        @Test
        @DisplayName("copy preserves packet data")
        void copyPreservesPacketData() {
            Packet copy = sourcePacket.copy();
            
            MemorySegment srcSeg = sourcePacket.boundMemory().segment();
            MemorySegment copySeg = copy.boundMemory().segment();
            
            for (int i = 0; i < PACKET_LENGTH; i++) {
                assertEquals(
                    srcSeg.get(ValueLayout.JAVA_BYTE, i),
                    copySeg.get(ValueLayout.JAVA_BYTE, i),
                    "Byte " + i + " should match"
                );
            }
        }

        @Test
        @DisplayName("copy preserves descriptor data")
        void copyPreservesDescriptorData() {
            Packet copy = sourcePacket.copy();
            
            assertEquals(sourcePacket.captureLength(), copy.captureLength());
            assertEquals(sourcePacket.wireLength(), copy.wireLength());
        }

        @Test
        @DisplayName("copy is independent - modifications don't affect original")
        void copyIsIndependent() {
            Packet copy = sourcePacket.copy();
            
            // Modify copy
            copy.boundMemory().segment().set(ValueLayout.JAVA_BYTE, 0, (byte) 0xFF);
            
            // Original unchanged
            assertEquals(SAMPLE_PACKET[0], 
                sourcePacket.boundMemory().segment().get(ValueLayout.JAVA_BYTE, 0));
        }

        @Test
        @DisplayName("copyTo copies to target")
        void copyToCopiesToTarget() {
            Packet target = new Packet(DescriptorInfo.PCAP_PADDED);
            Memory targetData = Memory.of(PACKET_LENGTH);
            target.bind(targetData);
            Memory targetDesc = Memory.of(PcapDescriptorPadded.BYTE_SIZE);
            target.descriptor().bind(targetDesc);
            
            sourcePacket.copyTo(target);
            
            assertEquals(sourcePacket.captureLength(), target.captureLength());
            
            // Verify data copied
            MemorySegment srcSeg = sourcePacket.boundMemory().segment();
            MemorySegment tgtSeg = target.boundMemory().segment();
            assertEquals(srcSeg.get(ValueLayout.JAVA_BYTE, 0), tgtSeg.get(ValueLayout.JAVA_BYTE, 0));
        }
    }

    @Nested
    @DisplayName("Duplicate Tests")
    class DuplicateTests {

        private Packet sourcePacket;

        @BeforeEach
        void setUp() {
            sourcePacket = new Packet(DescriptorInfo.PCAP_PADDED);
            
            Memory dataMemory = Memory.of(PACKET_LENGTH);
            MemorySegment dataSeg = dataMemory.segment();
            for (int i = 0; i < SAMPLE_PACKET.length; i++) {
                dataSeg.set(ValueLayout.JAVA_BYTE, i, SAMPLE_PACKET[i]);
            }
            sourcePacket.bind(dataMemory);
            
            Memory descMemory = Memory.of(PcapDescriptorPadded.BYTE_SIZE);
            sourcePacket.descriptor().bind(descMemory);
        }

        @Test
        @DisplayName("duplicate creates new instance")
        void duplicateCreatesNewInstance() {
            Packet dup = sourcePacket.duplicate();
            
            assertNotSame(sourcePacket, dup);
        }

        @Test
        @DisplayName("duplicate shares memory - modifications visible")
        void duplicateSharesMemory() {
            Packet dup = sourcePacket.duplicate();
            
            // Modify via original
            sourcePacket.boundMemory().segment().set(ValueLayout.JAVA_BYTE, 0, (byte) 0xAA);
            
            // Visible in duplicate
            assertEquals((byte) 0xAA, dup.boundMemory().segment().get(ValueLayout.JAVA_BYTE, 0));
        }

        @Test
        @DisplayName("duplicate increments ref count")
        void duplicateIncrementsRefCount() {
            int refBefore = sourcePacket.boundMemory().refCount();
            
            Packet dup = sourcePacket.duplicate();
            
            int refAfter = sourcePacket.boundMemory().refCount();
            assertEquals(refBefore + 1, refAfter);
            
            // Cleanup
            dup.boundMemory().decrementRef();
        }
    }

    @Nested
    @DisplayName("Pool Integration Tests")
    class PoolIntegrationTests {

        @Test
        @DisplayName("newUnbound creates unbound packet with correct descriptor type")
        void newUnboundCreatesCorrectType() {
            Packet source = new Packet(DescriptorInfo.PCAP_PADDED);
            Packet unbound = source.newUnbound();
            
            assertFalse(unbound.isBound());
            assertEquals(DescriptorInfo.PCAP_PADDED, unbound.descriptor().descriptorInfo());
        }

        @Test
        @DisplayName("Packet not from pool - isPooled returns false")
        void packetNotFromPoolIsNotPooled() {
            Packet packet = new Packet(DescriptorInfo.PCAP_PADDED);
            
            assertFalse(packet.poolEntry().isPooled());
        }

        @Test
        @DisplayName("recycle on non-pooled packet is no-op")
        void recycleOnNonPooledIsNoOp() {
            Packet packet = new Packet(DescriptorInfo.PCAP_PADDED);
            Memory fixed = Memory.of(PACKET_LENGTH);
            packet.bind(fixed);
            
            // Should not throw
            assertDoesNotThrow(() -> packet.recycle());
        }

        @Test
        @DisplayName("Pooled packet can be recycled")
        void pooledPacketCanBeRecycled() {
            PoolSettings settings = new PoolSettings()
                    .capacity(10)
                    .segmentSize(PACKET_LENGTH)
                    .preallocate(true);
            
            Pool<Packet> pool = new FreeListPool<>(settings, () -> {
                Packet p = new Packet(DescriptorInfo.PCAP_PADDED);
                Memory fixed = Memory.of(PACKET_LENGTH);
                p.bind(fixed);
                Memory descMem = Memory.of(PcapDescriptorPadded.BYTE_SIZE);
                p.descriptor().bind(descMem);
                return p;
            });
            
            long availableBefore = pool.available();
            Packet packet = pool.allocate();
            assertTrue(packet.poolEntry().isPooled());
            
            packet.recycle();
            
            assertEquals(availableBefore, pool.available());
            
            pool.close();
        }
    }

    @Nested
    @DisplayName("Memory Access Tests")
    class MemoryAccessTests {

        private Packet packet;

        @BeforeEach
        void setUp() {
            packet = new Packet(DescriptorInfo.PCAP_PADDED);
            Memory dataMemory = Memory.of(PACKET_LENGTH);
            MemorySegment dataSeg = dataMemory.segment();
            for (int i = 0; i < SAMPLE_PACKET.length; i++) {
                dataSeg.set(ValueLayout.JAVA_BYTE, i, SAMPLE_PACKET[i]);
            }
            packet.bind(dataMemory);
        }

        @Test
        @DisplayName("memory() returns bound memory")
        void memoryReturnsBoundMemory() {
            Memory mem = packet.boundMemory();
            
            assertNotNull(mem);
            assertSame(packet.boundMemory(), mem);
        }

        @Test
        @DisplayName("segment() returns memory segment via view")
        void segmentReturnsSegmentViaView() {
            MemorySegment seg = packet.segment();
            
            assertNotNull(seg);
            assertEquals(SAMPLE_PACKET[0], seg.get(ValueLayout.JAVA_BYTE, 0));
        }

        @Test
        @DisplayName("Can read Ethernet destination MAC")
        void canReadEthernetDstMac() {
            MemorySegment seg = packet.segment();
            
            byte[] dstMac = new byte[6];
            for (int i = 0; i < 6; i++) {
                dstMac[i] = seg.get(ValueLayout.JAVA_BYTE, i);
            }
            
            assertArrayEquals(
                new byte[] {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
                dstMac
            );
        }

        @Test
        @DisplayName("Can read EtherType")
        void canReadEtherType() {
            MemorySegment seg = packet.segment();
            
            short etherType = seg.get(ValueLayout.JAVA_SHORT_UNALIGNED, 12);
            
            assertEquals((short) 0x0800, Short.reverseBytes(etherType));  // Big-endian
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCaseTests {

        @Test
        @DisplayName("Unbound packet throws on segment access")
        void unboundPacketThrowsOnSegmentAccess() {
            Packet packet = new Packet(DescriptorInfo.PCAP_PADDED);
            
            assertThrows(IllegalStateException.class, () -> packet.segment());
        }

        @Test
        @DisplayName("Unbound packet throws on memory access")
        void unboundPacketThrowsOnMemoryAccess() {
            Packet packet = new Packet(DescriptorInfo.PCAP_PADDED);
            
            // boundMemory() returns null for unbound
            assertNull(packet.boundMemory());
        }

        @Test
        @DisplayName("isPersistent returns false for unbound packet")
        void isPersistentReturnsFalseForUnbound() {
            Packet packet = new Packet(DescriptorInfo.PCAP_PADDED);
            
            assertFalse(packet.isPersistent());
        }

        @Test
        @DisplayName("Multiple persist calls on fixed return same instance")
        void multiplePersistCallsReturnSame() {
            Packet packet = new Packet(DescriptorInfo.PCAP_PADDED);
            Memory fixed = Memory.of(PACKET_LENGTH);
            packet.bind(fixed);
            
            Packet p1 = packet.persist();
            Packet p2 = p1.persist();
            Packet p3 = p2.persist();
            
            assertSame(packet, p1);
            assertSame(packet, p2);
            assertSame(packet, p3);
        }
    }
}