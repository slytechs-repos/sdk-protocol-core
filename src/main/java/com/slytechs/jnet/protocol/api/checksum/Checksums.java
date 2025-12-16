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
 * 
 * <p>
 * All methods operate directly on MemorySegment for efficiency with native
 * memory and FFM/FFI optimizations.
 * </p>
 * 
 * <h2>Supported Checksums</h2>
 * <ul>
 * <li>IPv4 header checksum (RFC 791)</li>
 * <li>TCP checksum with pseudo-header (RFC 793)</li>
 * <li>UDP checksum with pseudo-header (RFC 768)</li>
 * <li>ICMP checksum (RFC 792)</li>
 * <li>ICMPv6 checksum with pseudo-header (RFC 4443)</li>
 * <li>Ethernet FCS/CRC32 (IEEE 802.3)</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public final class Checksums {

	private static final ValueLayout.OfShort BE_SHORT = ValueLayout.JAVA_SHORT
			.withOrder(ByteOrder.BIG_ENDIAN)
			.withByteAlignment(1);

	private static final ValueLayout.OfInt BE_INT = ValueLayout.JAVA_INT
			.withOrder(ByteOrder.BIG_ENDIAN)
			.withByteAlignment(1);

	/** TCP checksum field offset within TCP header. */
	public static final int TCP_CHECKSUM_OFFSET = 16;

	/** UDP checksum field offset within UDP header. */
	public static final int UDP_CHECKSUM_OFFSET = 6;

	/** ICMP checksum field offset within ICMP header. */
	public static final int ICMP_CHECKSUM_OFFSET = 2;

	/** ICMPv6 checksum field offset within ICMPv6 header. */
	public static final int ICMP6_CHECKSUM_OFFSET = 2;

	/** IPv4 checksum field offset within IPv4 header. */
	public static final int IP4_CHECKSUM_OFFSET = 10;

	// Precomputed table for reflected CRC32 (Ethernet FCS, polynomial 0xEDB88320)
	private static final int[] CRC32_TABLE = new int[256];

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
			CRC32_TABLE[i] = crc;
		}
	}

	private Checksums() {}

	/**
	 * Formats a 16-bit checksum as a hexadecimal string.
	 *
	 * @param checksum the checksum value
	 * @return checksum in "0x0000" format
	 */
	public static String checksumAsHex(int checksum) {
		return "0x%04x".formatted(checksum & 0xFFFF);
	}

	/**
	 * Computes the IPv4 header checksum.
	 * 
	 * <p>
	 * Reads IHL from the header to determine length. The checksum field
	 * (bytes 10-11) is treated as zero during computation.
	 * </p>
	 *
	 * @param segment the memory segment containing IPv4 header
	 * @param offset  starting offset of IPv4 header
	 * @return computed 16-bit checksum
	 */
	public static int computeIp4HeaderChecksum(MemorySegment segment, long offset) {
		int ihl = segment.get(ValueLayout.JAVA_BYTE, offset) & 0x0F;
		int headerLen = ihl * 4;
		return computeWithSkip(segment, offset, headerLen, IP4_CHECKSUM_OFFSET, 2);
	}

	/**
	 * Computes the TCP checksum including pseudo-header.
	 *
	 * @param ipSegment  memory segment containing IP header
	 * @param ipOffset   offset to IP header
	 * @param tcpSegment memory segment containing TCP header and payload
	 * @param tcpOffset  offset to TCP header
	 * @param tcpLen     total TCP length (header + payload)
	 * @param isIp6      true for IPv6, false for IPv4
	 * @return computed 16-bit checksum
	 */
	public static int computeTcpChecksum(MemorySegment ipSegment, long ipOffset,
			MemorySegment tcpSegment, long tcpOffset, int tcpLen, boolean isIp6) {
		
		long pseudoSum = isIp6
				? ip6PseudoHeaderSum(ipSegment, ipOffset, 6, tcpLen)
				: ip4PseudoHeaderSum(ipSegment, ipOffset, 6, tcpLen);

		return computeTransportChecksum(pseudoSum, tcpSegment, tcpOffset, tcpLen, TCP_CHECKSUM_OFFSET);
	}

	/**
	 * Computes the UDP checksum including pseudo-header.
	 *
	 * @param ipSegment  memory segment containing IP header
	 * @param ipOffset   offset to IP header
	 * @param udpSegment memory segment containing UDP header and payload
	 * @param udpOffset  offset to UDP header
	 * @param udpLen     total UDP length (header + payload)
	 * @param isIp6      true for IPv6, false for IPv4
	 * @return computed 16-bit checksum
	 */
	public static int computeUdpChecksum(MemorySegment ipSegment, long ipOffset,
			MemorySegment udpSegment, long udpOffset, int udpLen, boolean isIp6) {
		
		long pseudoSum = isIp6
				? ip6PseudoHeaderSum(ipSegment, ipOffset, 17, udpLen)
				: ip4PseudoHeaderSum(ipSegment, ipOffset, 17, udpLen);

		return computeTransportChecksum(pseudoSum, udpSegment, udpOffset, udpLen, UDP_CHECKSUM_OFFSET);
	}

	/**
	 * Computes the ICMP checksum (IPv4 only, no pseudo-header).
	 *
	 * @param segment memory segment containing ICMP message
	 * @param offset  offset to ICMP header
	 * @param length  total ICMP length (header + payload)
	 * @return computed 16-bit checksum
	 */
	public static int computeIcmpChecksum(MemorySegment segment, long offset, int length) {
		return computeWithSkip(segment, offset, length, ICMP_CHECKSUM_OFFSET, 2);
	}

	/**
	 * Computes the ICMPv6 checksum including pseudo-header.
	 *
	 * @param ipSegment   memory segment containing IPv6 header
	 * @param ipOffset    offset to IPv6 header
	 * @param icmpSegment memory segment containing ICMPv6 message
	 * @param icmpOffset  offset to ICMPv6 header
	 * @param icmpLen     total ICMPv6 length (header + payload)
	 * @return computed 16-bit checksum
	 */
	public static int computeIcmp6Checksum(MemorySegment ipSegment, long ipOffset,
			MemorySegment icmpSegment, long icmpOffset, int icmpLen) {
		
		long pseudoSum = ip6PseudoHeaderSum(ipSegment, ipOffset, 58, icmpLen);
		return computeTransportChecksum(pseudoSum, icmpSegment, icmpOffset, icmpLen, ICMP6_CHECKSUM_OFFSET);
	}

	/**
	 * Computes the Ethernet Frame Check Sequence (FCS) using CRC32.
	 *
	 * @param segment memory segment containing Ethernet frame (without FCS)
	 * @param offset  starting offset
	 * @param length  length in bytes (excluding FCS field)
	 * @return 32-bit FCS value
	 */
	public static int computeEthernetFcs(MemorySegment segment, long offset, int length) {
		int crc = 0xFFFFFFFF;
		for (int i = 0; i < length; i++) {
			byte b = segment.get(ValueLayout.JAVA_BYTE, offset + i);
			int index = (crc ^ (b & 0xFF)) & 0xFF;
			crc = CRC32_TABLE[index] ^ (crc >>> 8);
		}
		return ~crc;
	}

	/**
	 * Computes the IPv4 pseudo-header sum for transport checksums.
	 *
	 * @param segment    memory segment containing IPv4 header
	 * @param offset     offset to IPv4 header
	 * @param protocol   upper-layer protocol (6=TCP, 17=UDP)
	 * @param upperLen   upper-layer length (header + payload)
	 * @return unfolded pseudo-header sum
	 */
	public static long ip4PseudoHeaderSum(MemorySegment segment, long offset, int protocol, int upperLen) {
		long sum = 0;
		
		// Source IP (bytes 12-15, 2 words)
		int src = segment.get(BE_INT, offset + 12);
		sum += (src >>> 16) & 0xFFFF;
		sum += src & 0xFFFF;
		
		// Destination IP (bytes 16-19, 2 words)
		int dst = segment.get(BE_INT, offset + 16);
		sum += (dst >>> 16) & 0xFFFF;
		sum += dst & 0xFFFF;
		
		// Protocol and length
		sum += protocol;
		sum += upperLen;
		
		return sum;
	}

	/**
	 * Computes the IPv6 pseudo-header sum for transport checksums.
	 *
	 * @param segment    memory segment containing IPv6 header
	 * @param offset     offset to IPv6 header
	 * @param nextHeader upper-layer protocol (6=TCP, 17=UDP, 58=ICMPv6)
	 * @param upperLen   upper-layer length (header + payload)
	 * @return unfolded pseudo-header sum
	 */
	public static long ip6PseudoHeaderSum(MemorySegment segment, long offset, int nextHeader, int upperLen) {
		long sum = 0;
		
		// Source address (bytes 8-23, 8 words)
		for (int i = 0; i < 8; i++) {
			sum += segment.get(BE_SHORT, offset + 8 + i * 2) & 0xFFFF;
		}
		
		// Destination address (bytes 24-39, 8 words)
		for (int i = 0; i < 8; i++) {
			sum += segment.get(BE_SHORT, offset + 24 + i * 2) & 0xFFFF;
		}
		
		// Upper-layer length (32-bit, 2 words)
		sum += (upperLen >>> 16) & 0xFFFF;
		sum += upperLen & 0xFFFF;
		
		// Next header
		sum += nextHeader;
		
		return sum;
	}

	/**
	 * Computes a one's complement checksum over the segment.
	 *
	 * @param segment memory segment
	 * @param offset  starting offset
	 * @param length  length in bytes
	 * @return 16-bit checksum
	 */
	public static int compute(MemorySegment segment, long offset, int length) {
		long sum = onesComplementSum(segment, offset, length);
		return ~fold(sum) & 0xFFFF;
	}

	/**
	 * Computes a one's complement checksum with a skipped region.
	 *
	 * @param segment    memory segment
	 * @param offset     starting offset
	 * @param length     total length in bytes
	 * @param skipOffset relative skip start (from offset)
	 * @param skipLength length to skip
	 * @return 16-bit checksum
	 */
	public static int computeWithSkip(MemorySegment segment, long offset, int length,
			int skipOffset, int skipLength) {
		
		long sum = onesComplementSum(segment, offset, skipOffset);
		sum += onesComplementSum(segment, offset + skipOffset + skipLength, 
				length - skipOffset - skipLength);

		return ~fold(sum) & 0xFFFF;
	}

	/**
	 * Computes transport-layer checksum using precomputed pseudo-header sum.
	 *
	 * @param pseudoSum       precomputed pseudo-header sum
	 * @param segment         memory segment containing transport header + payload
	 * @param offset          offset to transport header
	 * @param length          total length (header + payload)
	 * @param checksumOffset  relative offset of checksum field
	 * @return 16-bit checksum
	 */
	public static int computeTransportChecksum(long pseudoSum, MemorySegment segment, 
			long offset, int length, int checksumOffset) {
		
		long sum = pseudoSum;
		sum += onesComplementSum(segment, offset, checksumOffset);
		sum += onesComplementSum(segment, offset + checksumOffset + 2, 
				length - checksumOffset - 2);

		return ~fold(sum) & 0xFFFF;
	}

	/**
	 * Computes the Ethernet FCS using a byte array (legacy/testing).
	 *
	 * @param data   byte array
	 * @param offset starting offset
	 * @param length length in bytes
	 * @return 32-bit FCS value
	 */
	public static int computeEthernetFcs(byte[] data, int offset, int length) {
		int crc = 0xFFFFFFFF;
		for (int i = 0; i < length; i++) {
			int index = (crc ^ (data[offset + i] & 0xFF)) & 0xFF;
			crc = CRC32_TABLE[index] ^ (crc >>> 8);
		}
		return ~crc;
	}

	/**
	 * Computes IPv4 header checksum using a byte array (legacy/testing).
	 *
	 * @param bytes header bytes
	 * @param len   header length
	 * @return 16-bit checksum
	 */
	public static int computeIp4Checksum(byte[] bytes, int len) {
		long sum = 0;
		for (int i = 0; i < len; i += 2) {
			if (i == IP4_CHECKSUM_OFFSET) continue;
			sum += ((bytes[i] & 0xFF) << 8) | (bytes[i + 1] & 0xFF);
		}
		return ~fold(sum) & 0xFFFF;
	}

	private static long onesComplementSum(MemorySegment segment, long offset, int length) {
		long sum = 0;
		int i = 0;
		for (; i < length - 1; i += 2) {
			sum += segment.get(BE_SHORT, offset + i) & 0xFFFF;
		}
		if (i < length) {
			sum += (segment.get(ValueLayout.JAVA_BYTE, offset + i) & 0xFF) << 8;
		}
		return sum;
	}

	private static int fold(long sum) {
		while (sum > 0xFFFF) {
			sum = (sum & 0xFFFF) + (sum >>> 16);
		}
		return (int) sum & 0xFFFF;
	}
}