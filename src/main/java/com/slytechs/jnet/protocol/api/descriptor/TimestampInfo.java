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

import com.slytechs.jnet.core.api.time.TimestampUnit;

/**
 * Provides timestamp metadata for a packet, including unit for precision.
 * Maps to DPDK (rte_mbuf.timesync), Napatech (descriptor timestamp), Pcap (pcap_pkthdr.ts).
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface TimestampInfo {
    /**
     * Gets the raw timestamp value in native format.
     *
     * @return the timestamp
     */
    long timestamp();

    /**
     * Gets the timestamp unit as a binary integer (e.g., 9 for nanoseconds).
     *
     * @return the unit as an integer
     */
    int timestampUnit();

    /**
     * Gets the timestamp unit as an enum for type safety.
     *
     * @return the TimestampUnit enum
     */
    TimestampUnit timestampUnitEnum();
}