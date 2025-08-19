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
 * Provides a bitmask of packet flags (e.g., checksum status, offloads).
 * Maps to DPDK (rte_mbuf.ol_flags), Napatech (descriptor flags), Pcap (none, default 0).
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface FlagInfo {
    /**
     * Gets the bitmask of packet flags (e.g., checksum errors, offload status).
     *
     * @return the flag bitmask
     */
    long packetFlagBitmask();
}