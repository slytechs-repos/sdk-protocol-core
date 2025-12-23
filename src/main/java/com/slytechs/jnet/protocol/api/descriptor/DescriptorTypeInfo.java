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
 * Descriptor type metadata.
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public enum DescriptorTypeInfo implements DescriptorType {

    PCAP_HDR(DescriptorType.PCAP_HDR, "PCAP_HDR"),
    PCAP(DescriptorType.PCAP, "PCAP"),
    NET(DescriptorType.NET, "NET"),
    NTAPI(DescriptorType.NTAPI, "NTAPI"),
    DPDK(DescriptorType.DPDK, "DPDK"),

    ;

    private final int id;
    private final String label;

    DescriptorTypeInfo(int id, String label) {
        this.id = id;
        this.label = label;
    }

    @Override
    public int getDescriptorType() {
        return id;
    }

    public String getLabel() {
        return label;
    }

    public static DescriptorTypeInfo valueOf(int type) {
        for (DescriptorTypeInfo info : values()) {
            if (info.id == type)
                return info;
        }
        throw new IllegalArgumentException("Unknown descriptor type: " + type);
    }
}