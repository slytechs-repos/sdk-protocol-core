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
 * Provides segmentation and TSO metadata for scattered packets.
 * Maps to DPDK (rte_mbuf.nb_segs, tso_segsz), Napatech (multi-segment), Pcap (single segment).
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface SegmentationInfo {
    /**
     * Gets the TSO segment size (for TCP segmentation offload).
     *
     * @return the TSO segment size in bytes
     */
    int tsoSegmentSize();

    /**
     * Gets the number of mbuf segments in the packet.
     *
     * @return the segment count
     */
    int segmentCount();
}