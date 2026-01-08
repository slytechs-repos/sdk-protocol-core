/*
 * Apache License, Version 2.0
 * 
 * Copyright 2025 Sly Technologies Inc.
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
package com.slytechs.sdk.protocol.core.hash;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;

/**
 * Hash calculator implementations.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
final class HashCalculators {

    private static final int ETHERTYPE_VLAN = 0x8100;
    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int ETHERTYPE_IPV6 = 0x86DD;

    private static final HashCalculator[] CALCULATORS = new HashCalculator[18];

    static {
        CALCULATORS[HashType.NONE] = new None();
        CALCULATORS[HashType.ROUND_ROBIN] = new RoundRobin();
        CALCULATORS[HashType.HASH_2_TUPLE] = new Hash2Tuple(false);
        CALCULATORS[HashType.HASH_2_TUPLE_SORTED] = new Hash2Tuple(true);
        CALCULATORS[HashType.HASH_5_TUPLE] = new Hash5Tuple(false);
        CALCULATORS[HashType.HASH_5_TUPLE_SORTED] = new Hash5Tuple(true);
        CALCULATORS[HashType.HASH_INNER_2_TUPLE] = new HashInner2Tuple(false);
        CALCULATORS[HashType.HASH_INNER_2_TUPLE_SORTED] = new HashInner2Tuple(true);
        CALCULATORS[HashType.HASH_INNER_5_TUPLE] = new HashInner5Tuple(false);
        CALCULATORS[HashType.HASH_INNER_5_TUPLE_SORTED] = new HashInner5Tuple(true);
        CALCULATORS[HashType.HASH_5_TUPLE_SCTP] = new Hash5TupleSctp(false);
        CALCULATORS[HashType.HASH_5_TUPLE_SCTP_SORTED] = new Hash5TupleSctp(true);
        CALCULATORS[HashType.HASH_3_TUPLE_GTP] = new Hash3TupleGtp(false);
        CALCULATORS[HashType.HASH_3_TUPLE_GTP_SORTED] = new Hash3TupleGtp(true);
        CALCULATORS[HashType.HASH_LAST_MPLS_LABEL] = new HashLastMplsLabel();
        CALCULATORS[HashType.HASH_ALL_MPLS_LABELS] = new HashAllMplsLabels();
        CALCULATORS[HashType.HASH_LAST_VLAN_ID] = new HashLastVlanId();
        CALCULATORS[HashType.HASH_ALL_VLAN_IDS] = new HashAllVlanIds();
    }

    static HashCalculator of(int hashType) {
        if (hashType < 0 || hashType >= CALCULATORS.length || CALCULATORS[hashType] == null)
            throw new IllegalArgumentException("Unknown hash type: " + hashType);

        return CALCULATORS[hashType];
    }

    private static final class None implements HashCalculator {
        @Override
        public int calculate(ByteBuffer buffer) {
            return 0;
        }

        @Override
        public int calculate(MemorySegment segment, long offset) {
            return 0;
        }

        @Override
        public int hashType() {
            return HashType.NONE;
        }
    }

    private static final class RoundRobin implements HashCalculator {
        private int counter;

        @Override
        public int calculate(ByteBuffer buffer) {
            return counter++;
        }

        @Override
        public int calculate(MemorySegment segment, long offset) {
            return counter++;
        }

        @Override
        public int hashType() {
            return HashType.ROUND_ROBIN;
        }
    }

    private static final class Hash2Tuple implements HashCalculator {
        private final long[] words = new long[2];
        private final boolean sorted;
        private final int type;

        Hash2Tuple(boolean sorted) {
            this.sorted = sorted;
            this.type = sorted ? HashType.HASH_2_TUPLE_SORTED : HashType.HASH_2_TUPLE;
        }

        @Override
        public int calculate(ByteBuffer buffer) {
            int pos = buffer.position();
            int ipOffset = pos + findIpOffset(buffer, pos);

            words[0] = buffer.getInt(ipOffset + 12) & 0xFFFFFFFFL;
            words[1] = buffer.getInt(ipOffset + 16) & 0xFFFFFFFFL;

            if (sorted && words[0] > words[1]) {
                long tmp = words[0];
                words[0] = words[1];
                words[1] = tmp;
            }

            return hash(words[0] ^ words[1]);
        }

        @Override
        public int calculate(MemorySegment segment, long offset) {
            long ipOffset = offset + findIpOffset(segment, offset);

            words[0] = segment.get(ValueLayout.JAVA_INT, ipOffset + 12) & 0xFFFFFFFFL;
            words[1] = segment.get(ValueLayout.JAVA_INT, ipOffset + 16) & 0xFFFFFFFFL;

            if (sorted && words[0] > words[1]) {
                long tmp = words[0];
                words[0] = words[1];
                words[1] = tmp;
            }

            return hash(words[0] ^ words[1]);
        }

        @Override
        public int hashType() {
            return type;
        }
    }

    private static final class Hash5Tuple implements HashCalculator {
        private final long[] words = new long[4];
        private final boolean sorted;
        private final int type;

        Hash5Tuple(boolean sorted) {
            this.sorted = sorted;
            this.type = sorted ? HashType.HASH_5_TUPLE_SORTED : HashType.HASH_5_TUPLE;
        }

        @Override
        public int calculate(ByteBuffer buffer) {
            int pos = buffer.position();
            int ipOffset = pos + findIpOffset(buffer, pos);
            int protocol = buffer.get(ipOffset + 9) & 0xFF;
            int ihl = (buffer.get(ipOffset) & 0x0F) * 4;
            int l4Offset = ipOffset + ihl;

            words[0] = buffer.getInt(ipOffset + 12) & 0xFFFFFFFFL;
            words[1] = buffer.getInt(ipOffset + 16) & 0xFFFFFFFFL;
            words[2] = buffer.getShort(l4Offset) & 0xFFFFL;
            words[3] = buffer.getShort(l4Offset + 2) & 0xFFFFL;

            if (sorted) {
                if (words[0] > words[1] || (words[0] == words[1] && words[2] > words[3])) {
                    swap(0, 1);
                    swap(2, 3);
                }
            }

            return hash(words[0] ^ words[1] ^ words[2] ^ words[3] ^ protocol);
        }

        @Override
        public int calculate(MemorySegment segment, long offset) {
            long ipOffset = offset + findIpOffset(segment, offset);
            int protocol = segment.get(ValueLayout.JAVA_BYTE, ipOffset + 9) & 0xFF;
            int ihl = (segment.get(ValueLayout.JAVA_BYTE, ipOffset) & 0x0F) * 4;
            long l4Offset = ipOffset + ihl;

            words[0] = segment.get(ValueLayout.JAVA_INT, ipOffset + 12) & 0xFFFFFFFFL;
            words[1] = segment.get(ValueLayout.JAVA_INT, ipOffset + 16) & 0xFFFFFFFFL;
            words[2] = segment.get(ValueLayout.JAVA_SHORT, l4Offset) & 0xFFFFL;
            words[3] = segment.get(ValueLayout.JAVA_SHORT, l4Offset + 2) & 0xFFFFL;

            if (sorted) {
                if (words[0] > words[1] || (words[0] == words[1] && words[2] > words[3])) {
                    swap(0, 1);
                    swap(2, 3);
                }
            }

            return hash(words[0] ^ words[1] ^ words[2] ^ words[3] ^ protocol);
        }

        private void swap(int a, int b) {
            long tmp = words[a];
            words[a] = words[b];
            words[b] = tmp;
        }

        @Override
        public int hashType() {
            return type;
        }
    }

    private static final class HashInner2Tuple implements HashCalculator {
        private final long[] words = new long[2];
        private final boolean sorted;
        private final int type;

        HashInner2Tuple(boolean sorted) {
            this.sorted = sorted;
            this.type = sorted ? HashType.HASH_INNER_2_TUPLE_SORTED : HashType.HASH_INNER_2_TUPLE;
        }

        @Override
        public int calculate(ByteBuffer buffer) {
            int pos = buffer.position();
            int innerIpOffset = pos + findInnerIpOffset(buffer, pos);

            words[0] = buffer.getInt(innerIpOffset + 12) & 0xFFFFFFFFL;
            words[1] = buffer.getInt(innerIpOffset + 16) & 0xFFFFFFFFL;

            if (sorted && words[0] > words[1]) {
                long tmp = words[0];
                words[0] = words[1];
                words[1] = tmp;
            }

            return hash(words[0] ^ words[1]);
        }

        @Override
        public int calculate(MemorySegment segment, long offset) {
            long innerIpOffset = offset + findInnerIpOffset(segment, offset);

            words[0] = segment.get(ValueLayout.JAVA_INT, innerIpOffset + 12) & 0xFFFFFFFFL;
            words[1] = segment.get(ValueLayout.JAVA_INT, innerIpOffset + 16) & 0xFFFFFFFFL;

            if (sorted && words[0] > words[1]) {
                long tmp = words[0];
                words[0] = words[1];
                words[1] = tmp;
            }

            return hash(words[0] ^ words[1]);
        }

        @Override
        public int hashType() {
            return type;
        }
    }

    private static final class HashInner5Tuple implements HashCalculator {
        private final long[] words = new long[4];
        private final boolean sorted;
        private final int type;

        HashInner5Tuple(boolean sorted) {
            this.sorted = sorted;
            this.type = sorted ? HashType.HASH_INNER_5_TUPLE_SORTED : HashType.HASH_INNER_5_TUPLE;
        }

        @Override
        public int calculate(ByteBuffer buffer) {
            int pos = buffer.position();
            int innerIpOffset = pos + findInnerIpOffset(buffer, pos);
            int protocol = buffer.get(innerIpOffset + 9) & 0xFF;
            int ihl = (buffer.get(innerIpOffset) & 0x0F) * 4;
            int l4Offset = innerIpOffset + ihl;

            words[0] = buffer.getInt(innerIpOffset + 12) & 0xFFFFFFFFL;
            words[1] = buffer.getInt(innerIpOffset + 16) & 0xFFFFFFFFL;
            words[2] = buffer.getShort(l4Offset) & 0xFFFFL;
            words[3] = buffer.getShort(l4Offset + 2) & 0xFFFFL;

            if (sorted) {
                if (words[0] > words[1] || (words[0] == words[1] && words[2] > words[3])) {
                    swap(0, 1);
                    swap(2, 3);
                }
            }

            return hash(words[0] ^ words[1] ^ words[2] ^ words[3] ^ protocol);
        }

        @Override
        public int calculate(MemorySegment segment, long offset) {
            long innerIpOffset = offset + findInnerIpOffset(segment, offset);
            int protocol = segment.get(ValueLayout.JAVA_BYTE, innerIpOffset + 9) & 0xFF;
            int ihl = (segment.get(ValueLayout.JAVA_BYTE, innerIpOffset) & 0x0F) * 4;
            long l4Offset = innerIpOffset + ihl;

            words[0] = segment.get(ValueLayout.JAVA_INT, innerIpOffset + 12) & 0xFFFFFFFFL;
            words[1] = segment.get(ValueLayout.JAVA_INT, innerIpOffset + 16) & 0xFFFFFFFFL;
            words[2] = segment.get(ValueLayout.JAVA_SHORT, l4Offset) & 0xFFFFL;
            words[3] = segment.get(ValueLayout.JAVA_SHORT, l4Offset + 2) & 0xFFFFL;

            if (sorted) {
                if (words[0] > words[1] || (words[0] == words[1] && words[2] > words[3])) {
                    swap(0, 1);
                    swap(2, 3);
                }
            }

            return hash(words[0] ^ words[1] ^ words[2] ^ words[3] ^ protocol);
        }

        private void swap(int a, int b) {
            long tmp = words[a];
            words[a] = words[b];
            words[b] = tmp;
        }

        @Override
        public int hashType() {
            return type;
        }
    }

    private static final class Hash5TupleSctp implements HashCalculator {
        private final long[] words = new long[4];
        private final boolean sorted;
        private final int type;

        Hash5TupleSctp(boolean sorted) {
            this.sorted = sorted;
            this.type = sorted ? HashType.HASH_5_TUPLE_SCTP_SORTED : HashType.HASH_5_TUPLE_SCTP;
        }

        @Override
        public int calculate(ByteBuffer buffer) {
            int pos = buffer.position();
            int ipOffset = pos + findIpOffset(buffer, pos);
            int protocol = buffer.get(ipOffset + 9) & 0xFF;
            int ihl = (buffer.get(ipOffset) & 0x0F) * 4;
            int l4Offset = ipOffset + ihl;

            words[0] = buffer.getInt(ipOffset + 12) & 0xFFFFFFFFL;
            words[1] = buffer.getInt(ipOffset + 16) & 0xFFFFFFFFL;
            words[2] = buffer.getShort(l4Offset) & 0xFFFFL;
            words[3] = buffer.getShort(l4Offset + 2) & 0xFFFFL;

            if (sorted) {
                if (words[0] > words[1] || (words[0] == words[1] && words[2] > words[3])) {
                    swap(0, 1);
                    swap(2, 3);
                }
            }

            return hash(words[0] ^ words[1] ^ words[2] ^ words[3] ^ protocol);
        }

        @Override
        public int calculate(MemorySegment segment, long offset) {
            long ipOffset = offset + findIpOffset(segment, offset);
            int protocol = segment.get(ValueLayout.JAVA_BYTE, ipOffset + 9) & 0xFF;
            int ihl = (segment.get(ValueLayout.JAVA_BYTE, ipOffset) & 0x0F) * 4;
            long l4Offset = ipOffset + ihl;

            words[0] = segment.get(ValueLayout.JAVA_INT, ipOffset + 12) & 0xFFFFFFFFL;
            words[1] = segment.get(ValueLayout.JAVA_INT, ipOffset + 16) & 0xFFFFFFFFL;
            words[2] = segment.get(ValueLayout.JAVA_SHORT, l4Offset) & 0xFFFFL;
            words[3] = segment.get(ValueLayout.JAVA_SHORT, l4Offset + 2) & 0xFFFFL;

            if (sorted) {
                if (words[0] > words[1] || (words[0] == words[1] && words[2] > words[3])) {
                    swap(0, 1);
                    swap(2, 3);
                }
            }

            return hash(words[0] ^ words[1] ^ words[2] ^ words[3] ^ protocol);
        }

        private void swap(int a, int b) {
            long tmp = words[a];
            words[a] = words[b];
            words[b] = tmp;
        }

        @Override
        public int hashType() {
            return type;
        }
    }

    private static final class Hash3TupleGtp implements HashCalculator {
        private final long[] words = new long[3];
        private final boolean sorted;
        private final int type;

        Hash3TupleGtp(boolean sorted) {
            this.sorted = sorted;
            this.type = sorted ? HashType.HASH_3_TUPLE_GTP_SORTED : HashType.HASH_3_TUPLE_GTP;
        }

        @Override
        public int calculate(ByteBuffer buffer) {
            int pos = buffer.position();
            int ipOffset = pos + findIpOffset(buffer, pos);
            int ihl = (buffer.get(ipOffset) & 0x0F) * 4;
            int udpOffset = ipOffset + ihl;
            int gtpOffset = udpOffset + 8;

            words[0] = buffer.getInt(ipOffset + 12) & 0xFFFFFFFFL;
            words[1] = buffer.getInt(ipOffset + 16) & 0xFFFFFFFFL;
            words[2] = buffer.getInt(gtpOffset + 4) & 0xFFFFFFFFL;

            if (sorted && words[0] > words[1]) {
                long tmp = words[0];
                words[0] = words[1];
                words[1] = tmp;
            }

            return hash(words[0] ^ words[1] ^ words[2]);
        }

        @Override
        public int calculate(MemorySegment segment, long offset) {
            long ipOffset = offset + findIpOffset(segment, offset);
            int ihl = (segment.get(ValueLayout.JAVA_BYTE, ipOffset) & 0x0F) * 4;
            long udpOffset = ipOffset + ihl;
            long gtpOffset = udpOffset + 8;

            words[0] = segment.get(ValueLayout.JAVA_INT, ipOffset + 12) & 0xFFFFFFFFL;
            words[1] = segment.get(ValueLayout.JAVA_INT, ipOffset + 16) & 0xFFFFFFFFL;
            words[2] = segment.get(ValueLayout.JAVA_INT, gtpOffset + 4) & 0xFFFFFFFFL;

            if (sorted && words[0] > words[1]) {
                long tmp = words[0];
                words[0] = words[1];
                words[1] = tmp;
            }

            return hash(words[0] ^ words[1] ^ words[2]);
        }

        @Override
        public int hashType() {
            return type;
        }
    }

    private static final class HashLastMplsLabel implements HashCalculator {

        @Override
        public int calculate(ByteBuffer buffer) {
            int pos = buffer.position();
            int offset = pos + 14;
            int label = 0;

            while (true) {
                int entry = buffer.getInt(offset);
                label = (entry >>> 12) & 0xFFFFF;
                if ((entry & 0x100) != 0)
                    break;
                offset += 4;
            }

            return hash(label);
        }

        @Override
        public int calculate(MemorySegment segment, long offset) {
            long pos = offset + 14;
            int label = 0;

            while (true) {
                int entry = segment.get(ValueLayout.JAVA_INT, pos);
                label = (entry >>> 12) & 0xFFFFF;
                if ((entry & 0x100) != 0)
                    break;
                pos += 4;
            }

            return hash(label);
        }

        @Override
        public int hashType() {
            return HashType.HASH_LAST_MPLS_LABEL;
        }
    }

    private static final class HashAllMplsLabels implements HashCalculator {

        @Override
        public int calculate(ByteBuffer buffer) {
            int pos = buffer.position();
            int offset = pos + 14;
            long combined = 0;

            while (true) {
                int entry = buffer.getInt(offset);
                int label = (entry >>> 12) & 0xFFFFF;
                combined ^= label;
                if ((entry & 0x100) != 0)
                    break;
                offset += 4;
            }

            return hash(combined);
        }

        @Override
        public int calculate(MemorySegment segment, long offset) {
            long pos = offset + 14;
            long combined = 0;

            while (true) {
                int entry = segment.get(ValueLayout.JAVA_INT, pos);
                int label = (entry >>> 12) & 0xFFFFF;
                combined ^= label;
                if ((entry & 0x100) != 0)
                    break;
                pos += 4;
            }

            return hash(combined);
        }

        @Override
        public int hashType() {
            return HashType.HASH_ALL_MPLS_LABELS;
        }
    }

    private static final class HashLastVlanId implements HashCalculator {

        @Override
        public int calculate(ByteBuffer buffer) {
            int pos = buffer.position();
            int offset = pos + 12;
            int vlanId = 0;

            while ((buffer.getShort(offset) & 0xFFFF) == ETHERTYPE_VLAN) {
                vlanId = buffer.getShort(offset + 2) & 0x0FFF;
                offset += 4;
            }

            return hash(vlanId);
        }

        @Override
        public int calculate(MemorySegment segment, long offset) {
            long pos = offset + 12;
            int vlanId = 0;

            while ((segment.get(ValueLayout.JAVA_SHORT, pos) & 0xFFFF) == ETHERTYPE_VLAN) {
                vlanId = segment.get(ValueLayout.JAVA_SHORT, pos + 2) & 0x0FFF;
                pos += 4;
            }

            return hash(vlanId);
        }

        @Override
        public int hashType() {
            return HashType.HASH_LAST_VLAN_ID;
        }
    }

    private static final class HashAllVlanIds implements HashCalculator {

        @Override
        public int calculate(ByteBuffer buffer) {
            int pos = buffer.position();
            int offset = pos + 12;
            long combined = 0;

            while ((buffer.getShort(offset) & 0xFFFF) == ETHERTYPE_VLAN) {
                int vlanId = buffer.getShort(offset + 2) & 0x0FFF;
                combined ^= vlanId;
                offset += 4;
            }

            return hash(combined);
        }

        @Override
        public int calculate(MemorySegment segment, long offset) {
            long pos = offset + 12;
            long combined = 0;

            while ((segment.get(ValueLayout.JAVA_SHORT, pos) & 0xFFFF) == ETHERTYPE_VLAN) {
                int vlanId = segment.get(ValueLayout.JAVA_SHORT, pos + 2) & 0x0FFF;
                combined ^= vlanId;
                pos += 4;
            }

            return hash(combined);
        }

        @Override
        public int hashType() {
            return HashType.HASH_ALL_VLAN_IDS;
        }
    }

    private static int findIpOffset(ByteBuffer buffer, int pos) {
        int offset = 12;
        int etherType = buffer.getShort(pos + offset) & 0xFFFF;

        while (etherType == ETHERTYPE_VLAN) {
            offset += 4;
            etherType = buffer.getShort(pos + offset) & 0xFFFF;
        }

        return offset + 2;
    }

    private static int findIpOffset(MemorySegment segment, long pos) {
        int offset = 12;
        int etherType = segment.get(ValueLayout.JAVA_SHORT, pos + offset) & 0xFFFF;

        while (etherType == ETHERTYPE_VLAN) {
            offset += 4;
            etherType = segment.get(ValueLayout.JAVA_SHORT, pos + offset) & 0xFFFF;
        }

        return offset + 2;
    }

    private static int findInnerIpOffset(ByteBuffer buffer, int pos) {
        int ipOffset = findIpOffset(buffer, pos);
        int ihl = (buffer.get(pos + ipOffset) & 0x0F) * 4;
        int protocol = buffer.get(pos + ipOffset + 9) & 0xFF;

        if (protocol == 4)
            return ipOffset + ihl;

        if (protocol == 47) {
            int greOffset = ipOffset + ihl;
            int greFlags = buffer.getShort(pos + greOffset) & 0xFFFF;
            int greHdrLen = 4;
            if ((greFlags & 0x8000) != 0) greHdrLen += 4;
            if ((greFlags & 0x4000) != 0) greHdrLen += 4;
            if ((greFlags & 0x2000) != 0) greHdrLen += 4;
            return greOffset + greHdrLen;
        }

        if (protocol == 17) {
            int udpOffset = ipOffset + ihl;
            int dstPort = buffer.getShort(pos + udpOffset + 2) & 0xFFFF;
            if (dstPort == 4789 || dstPort == 8472)
                return udpOffset + 16;
            if (dstPort == 2152)
                return udpOffset + 16;
        }

        return ipOffset;
    }

    private static int findInnerIpOffset(MemorySegment segment, long pos) {
        int ipOffset = findIpOffset(segment, pos);
        int ihl = (segment.get(ValueLayout.JAVA_BYTE, pos + ipOffset) & 0x0F) * 4;
        int protocol = segment.get(ValueLayout.JAVA_BYTE, pos + ipOffset + 9) & 0xFF;

        if (protocol == 4)
            return ipOffset + ihl;

        if (protocol == 47) {
            int greOffset = ipOffset + ihl;
            int greFlags = segment.get(ValueLayout.JAVA_SHORT, pos + greOffset) & 0xFFFF;
            int greHdrLen = 4;
            if ((greFlags & 0x8000) != 0) greHdrLen += 4;
            if ((greFlags & 0x4000) != 0) greHdrLen += 4;
            if ((greFlags & 0x2000) != 0) greHdrLen += 4;
            return greOffset + greHdrLen;
        }

        if (protocol == 17) {
            int udpOffset = ipOffset + ihl;
            int dstPort = segment.get(ValueLayout.JAVA_SHORT, pos + udpOffset + 2) & 0xFFFF;
            if (dstPort == 4789 || dstPort == 8472)
                return udpOffset + 16;
            if (dstPort == 2152)
                return udpOffset + 16;
        }

        return ipOffset;
    }

    private static int hash(long value) {
        value ^= (value >>> 33);
        value *= 0xff51afd7ed558ccdL;
        value ^= (value >>> 33);
        return (int) value;
    }

    private HashCalculators() {}
}