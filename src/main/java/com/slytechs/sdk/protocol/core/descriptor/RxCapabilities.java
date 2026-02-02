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
package com.slytechs.sdk.protocol.core.descriptor;

import com.slytechs.sdk.common.time.TimestampType;
import com.slytechs.sdk.protocol.core.id.L2FrameTypes;

/**
 * Provides RX-specific metadata for received packets.
 * 
 * <p>
 * This interface extends {@link PacketDescriptor} to provide specialized
 * setters for receive-side properties. The descriptor maintains essential RX
 * metadata while keeping the interface minimal and focused.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface RxCapabilities {

	// @formatter:off
	long RX_NONE                     = 1L << 0;
	long RX_TIMESTAMP                = 1L << 0;
	long RX_CAPTURE_LENGTH           = 1L << 1;
	long RX_WIRE_LENGTH              = 1L << 2;

	long RX_VLAN                     = 1L << 0;
	long RX_RSS_HASH                 = 1L << 1;
	long RX_FDIR                     = 1L << 2;
	long RX_L4_CKSUM_STATUS          = 1L << 3;  // Supports reporting bad/good
	long RX_IP_CKSUM_STATUS          = 1L << 4;
	long RX_OUTER_IP_CKSUM_STATUS    = 1L << 5;
	long RX_VLAN_STRIPPED            = 1L << 6;
	long RX_IEEE1588_PTP             = 1L << 9;
	long RX_IEEE1588_TMST            = 1L << 10;
	long RX_FCS_PRESENT              = 1L << 11;
	long RX_OUTER_L4_CKSUM_STATUS    = 1L << 12;
	long RX_FDIR_ID                  = 1L << 14;
	long RX_QINQ_STRIPPED            = 1L << 15;
	long RX_LRO                      = 1L << 16;
	long RX_SEC_OFFLOAD              = 1L << 17;
	long RX_SEC_OFFLOAD_FAILED       = 1L << 18;
	long RX_MACSEC_STRIPPED          = 1L << 19;
	long RX_QINQ                     = 1L << 20;
	long RX_PORT                     = 1L << 21;
	// @formatter:on

	/** Default NO-OP RxCapabilities instance. */
	RxCapabilities INSTANCE = new RxCapabilities() {

		@Override
		public long rxCapabilitiesBitmask() {
			return 0;
		}

	};

	/**
	 * RX capabilities bitmask as defined by RxCapabilities class.
	 *
	 * @return the rx capabilities bitmask
	 */
	long rxCapabilitiesBitmask();

	/**
	 * Gets the receive port number.
	 *
	 * @return the port number
	 */
	default int rxPort() {
		return 0;
	}

	/**
	 * Gets the timestamp type constant stored in the descriptor as defined by
	 * TimestampType class.
	 *
	 * @return the timestamp type as defined by TimestampType constants
	 */
	default int timestampType() {
		return TimestampType.EPOCH_MILLI;
	}

	/**
	 * Layer 2 frame type constants defined in L2FrameTypes class.
	 *
	 * @return the L2 frame type constant
	 */
	default int l2FrameId() {
		return L2FrameTypes.UNKNOWN;
	}

	/**
	 * Checks if FCS is present in the packet data. Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if FCS is present
	 */
	default boolean isFcsPresent() {
		return (rxCapabilitiesBitmask() & RX_FCS_PRESENT) != 0;
	}

	/**
	 * Checks if the IP checksum is invalid (inner). Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if IP checksum is bad
	 */
	default boolean isIpChecksumBad() {
		return (rxCapabilitiesBitmask() & RX_IP_CKSUM_STATUS) != 0;
	}

	/**
	 * Checks if the IP checksum is valid (inner). Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if IP checksum is good
	 */
	default boolean isIpChecksumGood() {
		return (rxCapabilitiesBitmask() & RX_IP_CKSUM_STATUS) == 0;
	}

	// ========== Convenience flag methods ==========

	/**
	 * Checks if the L4 checksum is invalid (inner). Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if L4 checksum is bad
	 */
	default boolean isL4ChecksumBad() {
		return (rxCapabilitiesBitmask() & RX_OUTER_L4_CKSUM_STATUS) != 0;
	}

	/**
	 * Checks if the L4 checksum is valid (inner). Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if L4 checksum is good
	 */
	default boolean isL4ChecksumGood() {
		return (rxCapabilitiesBitmask() & RX_OUTER_L4_CKSUM_STATUS) == 0;
	}

	/**
	 * Checks if RSS hash was computed. Convenience method that checks the
	 * appropriate flag bit.
	 *
	 * @return true if RSS hash is present
	 */
	default boolean isRssHashPresent() {
		return (rxCapabilitiesBitmask() & RX_RSS_HASH) != 0;
	}

	/**
	 * Sets the packet flags bitmask.
	 *
	 * @param flags the flags bitmask
	 */
	default RxCapabilities setFlags(long flags) {
		return this;
	}

	/**
	 * Sets the RSS hash value.
	 *
	 * @param hash the hash value
	 */
	default RxCapabilities setHash(long hash) {
		return this;
	}

	/**
	 * Sets the receive port number.
	 *
	 * @param port the port number
	 */
	default RxCapabilities setRxPort(int port) {
		return this;
	}
}