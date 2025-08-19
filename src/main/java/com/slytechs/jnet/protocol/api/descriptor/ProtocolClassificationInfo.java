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
 * Provides protocol classification, offsets, lengths, and VLAN metadata.
 * Maps to DPDK (rte_mbuf.packet_type, l2_offset, vlan_tci), Napatech (descriptor color/offsets), Pcap (computed).
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface ProtocolClassificationInfo {
    /**
     * Gets the packet type bitmask (e.g., L2/L3/L4 protocols).
     *
     * @return the packet type bitmask
     */
    long packetType();

    int l2Offset();
    int l3Offset();
    int l4Offset();
    int l2OffsetOuter();
    int l3OffsetOuter();
    int l2OffsetInner();
    int l3OffsetInner();
    int l4OffsetInner();

    int l2Length();
    int l3Length();
    int l4Length();
    int l2LengthOuter();
    int l3LengthOuter();
    int l2LengthInner();
    int l3LengthInner();
    int l4LengthInner();

    int vlanTci();
    int vlanTciOuter();
}