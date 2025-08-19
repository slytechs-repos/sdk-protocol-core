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
 * Provides TX-specific metadata and settings for packet transmission.
 * Maps to DPDK (rte_mbuf.ol_flags for TX offloads), Napatech (TX descriptor), Pcap (sendpacket).
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface TxPacketDescriptor extends PacketDescriptor {
    boolean isTxEnabled();
    void setTxEnabled(boolean enabled);
    boolean isTxImmediate();
    void setTxImmediate(boolean immediate);
    boolean isTxSyncTimestamp();
    void setTxSyncTimestamp(boolean sync);
    long txTimestamp();
    void setTxTimestamp(long timestamp);
    int txPort();
    void setTxPort(int port);
    int txOffsetInjection();
    void setTxOffsetInjection(int offset);
    int txIpChecksumAtOffset();
    void setTxIpChecksumAtOffset(int offset);
    int txL4ChecksumAtOffset();
    void setTxL4ChecksumAtOffset(int offset);
}