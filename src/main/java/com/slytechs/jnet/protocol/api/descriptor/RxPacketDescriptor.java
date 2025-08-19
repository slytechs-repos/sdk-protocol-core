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
 * Provides RX-specific metadata for packets.
 * Maps to DPDK (rte_mbuf.ol_flags for checksums), Napatech (descriptor errors), Pcap (computed).
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface RxPacketDescriptor extends PacketDescriptor {
    /**
     * Checks if the IP checksum is valid.
     *
     * @return true if valid
     */
    boolean isIpChecksumGood();

    /**
     * Checks if the L4 checksum is valid.
     *
     * @return true if valid
     */
    boolean isL4ChecksumGood();

    /**
     * Gets the receive timestamp.
     *
     * @return the timestamp
     */
    long timestamp();

    /**
     * Checks if the FCS is present in the packet data.
     *
     * @return true if FCS is present
     */
    boolean isFcsPresent();
}