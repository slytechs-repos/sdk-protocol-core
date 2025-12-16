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
package com.slytechs.jnet.protocol.api.descriptor;

/**
 * Provides TX-specific metadata and settings for packet transmission.
 * 
 * <p>
 * This interface defines transmit-side properties and offload requests that can
 * be set before sending packets to hardware. Maps to:
 * <ul>
 * <li>DPDK: rte_mbuf.ol_flags for TX offloads</li>
 * <li>Napatech: TX descriptor</li>
 * <li>Pcap: sendpacket</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface TxDescriptor extends Descriptor {

	/**
	 * Gets the TSO (TCP Segmentation Offload) segment size.
	 *
	 * @return the TSO segment size in bytes, or 0 if TSO is not enabled
	 */
	int tsoSegmentSize();

	/**
	 * Sets the TSO segment size for hardware segmentation.
	 *
	 * @param size the maximum segment size (MSS) in bytes
	 */
	void setTsoSegmentSize(int size);

	/**
	 * Gets the transmit timestamp.
	 *
	 * @return the scheduled transmit timestamp
	 */
	long txTimestamp();

	/**
	 * Sets the transmit timestamp for scheduled transmission.
	 *
	 * @param timestamp the transmit timestamp
	 */
	void setTxTimestamp(long timestamp);

	/**
	 * Gets the transmit port number.
	 *
	 * @return the port number
	 */
	int txPort();

	/**
	 * Sets the transmit port number.
	 *
	 * @param port the port number
	 */
	void setTxPort(int port);

	/**
	 * Gets the packet injection offset.
	 *
	 * @return the byte offset for packet injection
	 */
	int txOffsetInjection();

	/**
	 * Sets the packet injection offset.
	 *
	 * @param offset the byte offset for packet injection
	 */
	void setTxOffsetInjection(int offset);

	/**
	 * Gets the IP checksum field offset.
	 *
	 * @return the byte offset of the IP checksum field
	 */
	int txIpChecksumAtOffset();

	/**
	 * Sets the IP checksum field offset.
	 *
	 * @param offset the byte offset of the IP checksum field
	 */
	void setTxIpChecksumAtOffset(int offset);

	/**
	 * Gets the L4 checksum field offset.
	 *
	 * @return the byte offset of the L4 checksum field
	 */
	int txL4ChecksumAtOffset();

	/**
	 * Sets the L4 checksum field offset.
	 *
	 * @param offset the byte offset of the L4 checksum field
	 */
	void setTxL4ChecksumAtOffset(int offset);

	/**
	 * Checks if transmission is enabled.
	 *
	 * @return true if transmission is enabled
	 */
	boolean isTxEnabled();

	/**
	 * Sets the transmission enabled flag.
	 *
	 * @param enabled true to enable transmission
	 */
	void setTxEnabled(boolean enabled);

	/**
	 * Checks if immediate transmission is requested.
	 *
	 * @return true if immediate transmission is requested
	 */
	boolean isTxImmediate();

	/**
	 * Sets the immediate transmission flag.
	 *
	 * @param immediate true to request immediate transmission
	 */
	void setTxImmediate(boolean immediate);

	/**
	 * Checks if synchronized timestamp transmission is requested.
	 *
	 * @return true if synchronized timestamp transmission is requested
	 */
	boolean isTxSyncTimestamp();

	/**
	 * Sets the synchronized timestamp transmission flag.
	 *
	 * @param sync true to request synchronized timestamp transmission
	 */
	void setTxSyncTimestamp(boolean sync);

	// ========== Convenience flag methods ==========

	/**
	 * Checks if IP checksum offload is requested (inner). Convenience method that
	 * checks the appropriate flag bit.
	 *
	 * @return true if IP checksum offload is requested
	 */
	default boolean isTxIpChecksumRequested() {
		return (flags() & PacketFlag.Constants.PACKET_FLAG_TX_IP_CKSUM) != 0;
	}

	/**
	 * Checks if TCP checksum offload is requested. Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if TCP checksum offload is requested
	 */
	default boolean isTxTcpChecksumRequested() {
		return (flags() & PacketFlag.Constants.PACKET_FLAG_TX_TCP_CKSUM) != 0;
	}

	/**
	 * Checks if UDP checksum offload is requested. Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if UDP checksum offload is requested
	 */
	default boolean isTxUdpChecksumRequested() {
		return (flags() & PacketFlag.Constants.PACKET_FLAG_TX_UDP_CKSUM) != 0;
	}

	/**
	 * Checks if TCP segmentation offload is requested. Convenience method that
	 * checks the appropriate flag bit.
	 *
	 * @return true if TSO is requested
	 */
	default boolean isTxTcpSegmentationRequested() {
		return (flags() & PacketFlag.Constants.PACKET_FLAG_TX_TCP_SEG) != 0;
	}

	/**
	 * Checks if UDP segmentation offload is requested. Convenience method that
	 * checks the appropriate flag bit.
	 *
	 * @return true if USO is requested
	 */
	default boolean isTxUdpSegmentationRequested() {
		return (flags() & PacketFlag.Constants.PACKET_FLAG_TX_UDP_SEG) != 0;
	}

	/**
	 * Checks if VLAN insertion is requested. Convenience method that checks the
	 * appropriate flag bit.
	 *
	 * @return true if VLAN insertion is requested
	 */
	default boolean isTxVlanInsertionRequested() {
		return (flags() & PacketFlag.Constants.PACKET_FLAG_TX_VLAN) != 0;
	}

	/**
	 * Gets the packet flags bitmask. This method is expected to be implemented by
	 * the containing descriptor.
	 *
	 * @return the flags bitmask
	 */
	long flags();
}