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
package com.slytechs.sdk.protocol.core.descriptor;

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
public interface TxCapabilities {

	// @formatter:off
	long TX_NONE                     = 0;
	long TX_ENABLE                   = 1L << 0;
	long TX_PORT                     = 1L << 1;
	long TX_IMMEDIATE                = 1L << 2;
	long TX_TS_SYNC                  = 1L << 3;
	long TX_CRC_RECALC               = 1L << 4;

	long TX_TIMESTAMP                = 1L << 5;
	long TX_OFFSET_INJECTION         = 1L << 6;

	long TX_IPV4                     = 1L << 32;
	long TX_IPV6                     = 1L << 33;
	long TX_OUTER_IP_CKSUM           = 1L << 34;
	long TX_OUTER_UDP_CKSUM          = 1L << 35;
	long TX_OUTER_IPV4               = 1L << 36;
	long TX_OUTER_IPV6               = 1L << 37;

	long TX_TUNNEL_VXLAN             = 1L << 43;
	long TX_TUNNEL_GRE               = 1L << 44;
	long TX_TUNNEL_IPIP              = 1L << 45;
	long TX_TUNNEL_GENEVE            = 1L << 46;
	long TX_TUNNEL_MPLSOUDP          = 1L << 47;
	long TX_TUNNEL_VXLAN_GPE         = 1L << 48;
	long TX_TUNNEL_GTP               = 1L << 49;
	long TX_TUNNEL_ESP               = 1L << 50;
	long TX_TUNNEL_L2TP              = 1L << 51;
	long TX_TUNNEL_UDP               = 1L << 52;

	long TX_MACSEC                   = 1L << 53;
	long TX_SEC_OFFLOAD              = 1L << 54;
	long TX_QINQ                     = 1L << 55;
	long TX_TCP_SEGMENTATION         = 1L << 56;  // TSO
	long TX_UDP_SEGMENTATION         = 1L << 57;  // USO
	long TX_IEEE1588_TMST            = 1L << 58;
	long TX_TCP_CKSUM                = 1L << 59;
	long TX_SCTP_CKSUM               = 1L << 60;
	long TX_UDP_CKSUM                = 1L << 61;
	long TX_IP_CKSUM                 = 1L << 62;
	long TX_VLAN                     = 1L << 63;

	long TX_TSO_SEGMENT_SIZE         = 1L << 30;  // Support for configurable MSS
	// @formatter:on

	/**
	 * Empty/No-Op TxCapabilities instance. All getters return 0 or false, all
	 * setter are no-op
	 */
	TxCapabilities INSTANCE = new TxCapabilities() {

		@Override
		public long txCapabilitiesBitmask() {
			return 0;
		}

	};

	long txCapabilitiesBitmask();

	/**
	 * Checks if transmission is enabled.
	 *
	 * @return true if transmission is enabled
	 */
	default boolean isTxEnabled() {
		return false;
	}

	/**
	 * Checks if immediate transmission is requested.
	 *
	 * @return true if immediate transmission is requested
	 */
	default boolean isTxImmediate() {
		return false;
	}

	/**
	 * Checks if IP checksum offload is requested (inner). Convenience method that
	 * checks the appropriate flag bit.
	 *
	 * @return true if IP checksum offload is requested
	 */
	default boolean isTxIpChecksumRequested() {
		return (txCapabilitiesBitmask() & TX_OUTER_IP_CKSUM) != 0;
	}

	/**
	 * Checks if synchronized timestamp transmission is requested.
	 *
	 * @return true if synchronized timestamp transmission is requested
	 */
	default boolean isTxSyncTimestamp() {
		return false;
	}

	/**
	 * Checks if TCP checksum offload is requested. Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if TCP checksum offload is requested
	 */
	default boolean isTxTcpChecksumRequested() {
		return (txCapabilitiesBitmask() & TX_TCP_CKSUM) != 0;
	}

	/**
	 * Checks if TCP segmentation offload is requested. Convenience method that
	 * checks the appropriate flag bit.
	 *
	 * @return true if TSO is requested
	 */
	default boolean isTxTcpSegmentationRequested() {
		return (txCapabilitiesBitmask() & TX_TCP_SEGMENTATION) != 0;
	}

	/**
	 * Checks if UDP checksum offload is requested. Convenience method that checks
	 * the appropriate flag bit.
	 *
	 * @return true if UDP checksum offload is requested
	 */
	default boolean isTxUdpChecksumRequested() {
		return (txCapabilitiesBitmask() & TX_OUTER_UDP_CKSUM) != 0;
	}

	/**
	 * Checks if UDP segmentation offload is requested. Convenience method that
	 * checks the appropriate flag bit.
	 *
	 * @return true if USO is requested
	 */
	default boolean isTxUdpSegmentationRequested() {
		return (txCapabilitiesBitmask() & TX_UDP_SEGMENTATION) != 0;
	}

	/**
	 * Checks if VLAN insertion is requested. Convenience method that checks the
	 * appropriate flag bit.
	 *
	 * @return true if VLAN insertion is requested
	 */
	default boolean isTxVlanInsertionRequested() {
		return (txCapabilitiesBitmask() & TX_VLAN) != 0;
	}

	/**
	 * Sets the TSO segment size for hardware segmentation.
	 *
	 * @param size the maximum segment size (MSS) in bytes
	 */
	default TxCapabilities setTsoSegmentSize(int size) {
		return this;
	}

	/**
	 * Sets the transmission enabled flag.
	 *
	 * @param enabled true to enable transmission
	 */
	default TxCapabilities setTxEnabled(boolean enabled) {
		return this;
	}

	/**
	 * Sets the immediate transmission flag.
	 *
	 * @param immediate true to request immediate transmission
	 */
	default TxCapabilities setTxImmediate(boolean immediate) {
		return this;
	}

	/**
	 * Sets the IP checksum field offset.
	 *
	 * @param offset the byte offset of the IP checksum field
	 */
	default TxCapabilities setTxIpChecksumAtOffset(int offset) {
		return this;
	}

	/**
	 * Sets the L4 checksum field offset.
	 *
	 * @param offset the byte offset of the L4 checksum field
	 */
	default TxCapabilities setTxL4ChecksumAtOffset(int offset) {
		return this;
	}

	/**
	 * Sets the packet injection offset.
	 *
	 * @param offset the byte offset for packet injection
	 */
	default TxCapabilities setTxOffsetInjection(int offset) {
		return this;
	}

	/**
	 * Sets the transmit port number.
	 *
	 * @param port the port number
	 */
	default TxCapabilities setTxPort(int port) {
		return this;
	}

	/**
	 * Sets the synchronized timestamp transmission flag.
	 *
	 * @param sync true to request synchronized timestamp transmission
	 */
	default TxCapabilities setTxSyncTimestamp(boolean sync) {
		return this;
	}

	// ========== Convenience flag methods ==========

	/**
	 * Sets the transmit timestamp for scheduled transmission.
	 *
	 * @param timestamp the transmit timestamp
	 */
	default TxCapabilities setTxTimestamp(long timestamp) {
		return this;
	}

	/**
	 * Gets the TSO (TCP Segmentation Offload) segment size.
	 *
	 * @return the TSO segment size in bytes, or 0 if TSO is not enabled
	 */
	default int tsoSegmentSize() {
		return 0;
	}

	/**
	 * Gets the IP checksum field offset.
	 *
	 * @return the byte offset of the IP checksum field
	 */
	default int txIpChecksumAtOffset() {
		return 0;
	}

	/**
	 * Gets the L4 checksum field offset.
	 *
	 * @return the byte offset of the L4 checksum field
	 */
	default int txL4ChecksumAtOffset() {
		return 0;
	}

	/**
	 * Gets the packet injection offset.
	 *
	 * @return the byte offset for packet injection
	 */
	default int txOffsetInjection() {
		return 0;
	}

	/**
	 * Gets the transmit port number.
	 *
	 * @return the port number
	 */
	default int txPort() {
		return 0;
	}

	/**
	 * Gets the transmit timestamp.
	 *
	 * @return the scheduled transmit timestamp
	 */
	default long txTimestamp() {
		return 0;
	}
}