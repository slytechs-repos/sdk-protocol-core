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
 * Provides hash and flow identifier metadata.
 * Maps to DPDK (rte_mbuf.hash), Napatech (color/hash), Pcap (computed or NONE).
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface HashInfo {
    /**
     * Gets the hash value (e.g., RSS or FDIR hash).
     *
     * @return the hash value
     */
    long hash();

    /**
     * Gets the hash type as a binary integer.
     *
     * @return the hash type
     */
    int hashType();

    /**
     * Gets the hash type as an enum.
     *
     * @return the HashType enum
     */
//    HashType hashTypeEnum();

    /**
     * Gets the flow identifier (e.g., FDIR ID).
     *
     * @return the flow ID
     */
    long flowId();
}