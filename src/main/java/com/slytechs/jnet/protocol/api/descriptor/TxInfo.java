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
 * Provides TX-specific properties for packet transmission.
 * Maps to DPDK (rte_mbuf.ol_flags for TX offloads), Napatech (TX descriptor), Pcap (sendpacket settings).
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface TxInfo {
    /**
     * Checks if transmission is enabled for the packet.
     *
     * @return true if enabled
     */
    boolean txEnabled();

    /**
     * Sets whether transmission is enabled.
     *
     * @param enabled true to enable
     */
    void setTxEnabled(boolean enabled);

    /**
     * Checks if the packet should be transmitted immediately.
     *
     * @return true if immediate
     */
    boolean txImmediate();

    /**
     * Sets whether to transmit immediately.
     *
     * @param immediate true for immediate transmission
     */
    void setTxImmediate(boolean immediate);

    /**
     * Checks if the packet requires synchronized timestamp injection.
     *
     * @return true if sync timestamp is required
     */
    boolean txSyncTimestamp();

    /**
     * Sets whether to synchronize timestamp injection.
     *
     * @param sync true to enable sync timestamp
     */
    void setTxSyncTimestamp(boolean sync);

    /**
     * Gets the TX timestamp for injection.
     *
     * @return the TX timestamp
     */
    long txTimestamp();

    /**
     * Sets the TX timestamp for injection.
     *
     * @param timestamp the timestamp
     */
    void setTxTimestamp(long timestamp);

    /**
     * Gets the port index for transmission.
     *
     * @return the TX port index
     */
    int txPort();

    /**
     * Sets the port index for transmission.
     *
     * @param port the port index
     */
    void setTxPort(int port);

    /**
     * Gets the offset for data injection (e.g., timestamp).
     *
     * @return the injection offset
     */
    int txOffsetInjection();

    /**
     * Sets the offset for data injection.
     *
     * @param offset the offset
     */
    void setTxOffsetInjection(int offset);

    /**
     * Gets the offset for IP checksum injection.
     *
     * @return the IP checksum offset
     */
    int txIpChecksumAtOffset();

    /**
     * Sets the offset for IP checksum injection.
     *
     * @param offset the offset
     */
    void setTxIpChecksumAtOffset(int offset);

    /**
     * Gets the offset for L4 checksum injection.
     *
     * @return the L4 checksum offset
     */
    int txL4ChecksumAtOffset();

    /**
     * Sets the offset for L4 checksum injection.
     *
     * @param offset the offset
     */
    void setTxL4ChecksumAtOffset(int offset);
}