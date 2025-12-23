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
package com.slytechs.jnet.protocol.api.descriptor;

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
public interface RxDescriptor extends Descriptor {

	long flags();

	/**
	 * Sets the packet flags bitmask.
	 *
	 * @param flags the flags bitmask
	 */
	void setFlags(long flags);

	/**
	 * Sets the RSS hash value.
	 *
	 * @param hash the hash value
	 */
	void setHash(long hash);

	/**
	 * Sets the receive port number.
	 *
	 * @param port the port number
	 */
	void setRxPort(int port);

	/**
	 * Gets the receive port number.
	 *
	 * @return the port number
	 */
	int getRxPort();

	// ========== Convenience flag methods ==========

	/**
	 * Checks if the IP checksum is valid (inner). Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if IP checksum is good
	 */
	default boolean isIpChecksumGood() {
		return (flags() & PacketFlag.RX_IP_CKSUM_GOOD) != 0;
	}

	/**
	 * Checks if the IP checksum is invalid (inner). Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if IP checksum is bad
	 */
	default boolean isIpChecksumBad() {
		return (flags() & PacketFlag.RX_IP_CKSUM_BAD) != 0;
	}

	/**
	 * Checks if the L4 checksum is valid (inner). Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if L4 checksum is good
	 */
	default boolean isL4ChecksumGood() {
		return (flags() & PacketFlag.RX_L4_CKSUM_GOOD) != 0;
	}

	/**
	 * Checks if the L4 checksum is invalid (inner). Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if L4 checksum is bad
	 */
	default boolean isL4ChecksumBad() {
		return (flags() & PacketFlag.RX_L4_CKSUM_BAD) != 0;
	}

	/**
	 * Checks if FCS is present in the packet data. Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if FCS is present
	 */
	default boolean isFcsPresent() {
		return (flags() & PacketFlag.RX_FCS) != 0;
	}

	/**
	 * Checks if RSS hash was computed. Convenience method that checks the
	 * appropriate flag bit.
	 *
	 * @return true if RSS hash is present
	 */
	default boolean isRssHashPresent() {
		return (flags() & PacketFlag.RX_RSS_HASH) != 0;
	}
}