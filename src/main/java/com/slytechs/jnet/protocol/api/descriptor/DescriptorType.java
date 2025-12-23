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
 * Descriptor type constants.
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public interface DescriptorType {

    /** Pcap file header */
    int PCAP_HDR = 0;
    
    /** Pcap packet - file format (16-byte) */
    int PCAP = 1;

    /** SDK packet descriptor - full protocol table */
    int NET = 2;

    /** Napatech native */
    int NTAPI = 14;
    
    /** DPDK native */
    int DPDK = 15;

    /**
     * Gets the descriptor type constant.
     *
     * @return the descriptor type
     */
    int getDescriptorType();
}