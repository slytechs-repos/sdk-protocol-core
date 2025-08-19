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
package com.slytechs.jnet.protocol.api.checksum;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;

/**
 * Utility class for computing various network checksums and CRCs.
 * All methods operate directly on MemorySegment for efficiency with native memory.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public final class Checksums {
	

    private static final ValueLayout.OfShort BIG_SHORT = ValueLayout.JAVA_SHORT
            .withOrder(ByteOrder.BIG_ENDIAN)
            .withByteAlignment(1);

    private static final ValueLayout.OfInt BIG_INT = ValueLayout.JAVA_INT
            .withOrder(ByteOrder.BIG_ENDIAN)
            .withByteAlignment(1);

    // Precomputed table for reflected CRC32 (Ethernet FCS, polynomial 0xEDB88320)
    private static final int[] CRC32_REFLECT_TABLE = new int[256];

    static {
        for (int i = 0; i < 256; i++) {
            int crc = i;
            for (int j = 0; j < 8; j++) {
                if ((crc & 1) != 0) {
                    crc = (crc >>> 1) ^ 0xEDB88320;
                } else {
                    crc >>>= 1;
                }
            }
            CRC32_REFLECT_TABLE[i] = crc;
        }
    }

    private Checksums() {}

    /**
     * Computes the unfolded one's complement sum over the segment.
     * Handles odd lengths by padding with 0.
     *
     * @param segment the memory segment
     * @param offset  starting offset
     * @param length  length in bytes
     * @return unfolded sum (may exceed 32 bits)
     */
    private static long onesComplementSum(MemorySegment segment, long offset, int length) {
        long sum = 0;
        int i = 0;
        for (; i < length - 1; i += 2) {
            int word = segment.get(BIG_SHORT, offset + i) & 0xFFFF;
            sum += word;
        }
        // Odd length: last byte << 8 + 0
        if (i < length) {
            int lastByte = (segment.get(ValueLayout.JAVA_BYTE, offset + i) & 0xFF) << 8;
            sum += lastByte;
        }
        return sum;
    }

    /**
     * Folds the sum to 16 bits.
     *
     * @param sum unfolded sum
     * @return folded 16-bit sum
     */
    private static int fold(long sum) {
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >>> 16);
        }
        return (int) sum & 0xFFFF;
    }

    /**
     * Computes a one's complement checksum over the segment.
     *
     * @param segment the memory segment
     * @param offset  starting offset
     * @param length  length in bytes
     * @return 16-bit checksum
     */
    public static int computeOnesComplementChecksum(MemorySegment segment, long offset, int length) {
        long sum = onesComplementSum(segment, offset, length);
        return ~fold(sum) & 0xFFFF;
    }

    /**
     * Computes a one's complement checksum with a skipped region (e.g., for checksum field treated as 0).
     *
     * @param segment    the memory segment
     * @param offset     starting offset
     * @param length     total length in bytes
     * @param skipOffset relative skip start (from offset)
     * @param skipLength length to skip
     * @return 16-bit checksum
     */
    public static int computeOnesComplementChecksumWithSkip(MemorySegment segment, long offset, int length,
                                                            long skipOffset, int skipLength) {
        long absSkipStart = offset + skipOffset;
        long absSkipEnd = absSkipStart + skipLength;

        long sum = onesComplementSum(segment, offset, (int) skipOffset); // Before skip
        sum += onesComplementSum(segment, absSkipEnd, length - (int) skipOffset - skipLength); // After skip

        return ~fold(sum) & 0xFFFF;
    }

    /**
     * Computes the IPv4 header checksum.
     * Reads IHL from the header to determine length, skips checksum field (bytes 10-11).
     *
     * @param segment the memory segment (IPv4 header start)
     * @param offset  starting offset of IPv4 header
     * @return 16-bit checksum
     */
    public static int computeIpv4HeaderChecksum(MemorySegment segment, long offset) {
        int ihl = segment.get(ValueLayout.JAVA_BYTE, offset) & 0x0F;
        int headerLen = ihl * 4;
        return computeOnesComplementChecksumWithSkip(segment, offset, headerLen, 10, 2);
    }

    /**
     * Computes the unfolded sum for IPv4 pseudo-header (for TCP/UDP/ICMP).
     *
     * @param ipSegment  the memory segment (IPv4 header)
     * @param ipOffset   starting offset of IPv4 header
     * @param upperProto upper-layer protocol (e.g., 6 for TCP)
     * @param upperLen   upper-layer length (header + payload)
     * @return unfolded pseudo-header sum
     */
    public static long ipv4PseudoHeaderSum(MemorySegment ipSegment, long ipOffset, int upperProto, int upperLen) {
        long sum = 0;
        // Source IP (2 words)
        int src = ipSegment.get(BIG_INT, ipOffset + 12);
        sum += (src >>> 16) & 0xFFFF;
        sum += src & 0xFFFF;
        // Dest IP (2 words)
        int dst = ipSegment.get(BIG_INT, ipOffset + 16);
        sum += (dst >>> 16) & 0xFFFF;
        sum += dst & 0xFFFF;
        // Proto + Len
        sum += upperProto;
        sum += upperLen;
        return sum;
    }

    /**
     * Computes the unfolded sum for IPv6 pseudo-header (for TCP/UDP/ICMPv6).
     *
     * @param ipSegment  the memory segment (IPv6 header)
     * @param ipOffset   starting offset of IPv6 header
     * @param upperProto upper-layer protocol (next header, e.g., 6 for TCP)
     * @param upperLen   upper-layer length (header + payload)
     * @return unfolded pseudo-header sum
     */
    public static long ipv6PseudoHeaderSum(MemorySegment ipSegment, long ipOffset, int upperProto, int upperLen) {
        long sum = 0;
        // Source address (8 words)
        for (int i = 0; i < 8; i++) {
            sum += ipSegment.get(BIG_SHORT, ipOffset + 8 + i * 2) & 0xFFFF;
        }
        // Dest address (8 words)
        for (int i = 0; i < 8; i++) {
            sum += ipSegment.get(BIG_SHORT, ipOffset + 24 + i * 2) & 0xFFFF;
        }
        // Upper len (2 words)
        sum += (upperLen >>> 16) & 0xFFFF;
        sum += upperLen & 0xFFFF;
        // Next header (proto)
        sum += upperProto;
        return sum;
    }

    /**
     * Computes the transport-layer checksum (e.g., TCP/UDP) using pseudo-header sum.
     * Skips the checksum field in the transport header (treated as 0).
     *
     * @param pseudoSum            precomputed pseudo-header sum (from IPv4 or IPv6)
     * @param transportSegment     the memory segment (transport header + payload)
     * @param transportOffset      starting offset of transport header
     * @param transportLen         total length (header + payload)
     * @param checksumOffsetRel    relative offset of checksum field in transport header
     * @return 16-bit checksum
     */
    public static int computeTransportChecksum(long pseudoSum, MemorySegment transportSegment, long transportOffset,
                                               int transportLen, long checksumOffsetRel) {
        long transportSum = onesComplementSum(transportSegment, transportOffset, transportLen);
        transportSum -= transportSegment.get(BIG_SHORT, transportOffset + checksumOffsetRel) & 0xFFFF; // Subtract current checksum (treat as 0)
        long totalSum = pseudoSum + transportSum;
        return ~fold(totalSum) & 0xFFFF;
    }

    /**
     * Computes the Ethernet Frame Check Sequence (FCS) using reflected CRC32.
     *
     * @param segment the memory segment (Ethernet frame without FCS)
     * @param offset  starting offset
     * @param length  length in bytes (excluding FCS)
     * @return 32-bit FCS value
     */
    public static int computeEthernetFcs(MemorySegment segment, long offset, int length) {
        int crc = -1; // Initial 0xFFFFFFFF
        for (int i = 0; i < length; i++) {
            byte b = segment.get(ValueLayout.JAVA_BYTE, offset + i);
            int index = (crc ^ (b & 0xFF)) & 0xFF;
            crc = CRC32_REFLECT_TABLE[index] ^ (crc >>> 8);
        }
        return ~crc; // Final XOR 0xFFFFFFFF
    }

    // Overload for byte[] (for legacy or convenience)
    public static int computeEthernetFcs(byte[] data, int offset, int length) {
        int crc = -1;
        for (int i = 0; i < length; i++) {
            int index = (crc ^ (data[offset + i] & 0xFF)) & 0xFF;
            crc = CRC32_REFLECT_TABLE[index] ^ (crc >>> 8);
        }
        return ~crc;
    }

    // Legacy IPv4 checksum on byte[] (from original)
    public static int computeIp4Checksum(byte[] bytes, int len) {
        long sum = 0;
        for (int i = 0; i < len; i += 2) {
            if (i == 10) continue; // Skip checksum field
            sum += ((bytes[i] & 0xFF) << 8) | (bytes[i + 1] & 0xFF);
        }
        return ~fold(sum) & 0xFFFF;
    }
}