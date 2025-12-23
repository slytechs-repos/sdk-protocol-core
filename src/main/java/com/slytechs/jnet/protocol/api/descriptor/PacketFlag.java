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
 * Packet flag constants.
 * 
 * <p>
 * All flags use individual bits (no multi-bit fields) for cleaner operations and
 * context reuse across runtime, capabilities, and emulation contexts.
 * Bit layout is designed to align with DPDK mbuf flag semantics where possible.
 * </p>
 * 
 * <p>
 * Use integer constants for performance-critical code paths.
 * Use {@link PacketFlagInfo} enum for type-safe operations and metadata.
 * </p>
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public interface PacketFlag {

    // ========== RX FLAGS (bits 0-20) ==========
    
    /** VLAN tag present */
    long RX_VLAN = 1L << 0;
    
    /** RSS hash computed */
    long RX_RSS_HASH = 1L << 1;
    
    /** Flow Director match */
    long RX_FDIR = 1L << 2;
    
    /** L4 checksum bad */
    long RX_L4_CKSUM_BAD = 1L << 3;
    
    /** IP checksum bad */
    long RX_IP_CKSUM_BAD = 1L << 4;
    
    /** Outer IP checksum bad */
    long RX_OUTER_IP_CKSUM_BAD = 1L << 5;
    
    /** VLAN tag stripped by hardware */
    long RX_VLAN_STRIPPED = 1L << 6;
    
    /** IP checksum good */
    long RX_IP_CKSUM_GOOD = 1L << 7;
    
    /** L4 checksum good */
    long RX_L4_CKSUM_GOOD = 1L << 8;
    
    /** IEEE1588 PTP packet */
    long RX_IEEE1588_PTP = 1L << 9;
    
    /** IEEE1588 timestamp present */
    long RX_IEEE1588_TMST = 1L << 10;
    
    /** FCS present */
    long RX_FCS = 1L << 11;
    
    /** Outer L4 checksum bad */
    long RX_OUTER_L4_CKSUM_BAD = 1L << 12;
    
    /** Outer L4 checksum good */
    long RX_OUTER_L4_CKSUM_GOOD = 1L << 13;
    
    /** Flow Director ID present */
    long RX_FDIR_ID = 1L << 14;
    
    /** QinQ VLAN stripped */
    long RX_QINQ_STRIPPED = 1L << 15;
    
    /** Large Receive Offload */
    long RX_LRO = 1L << 16;
    
    /** Security offload processed */
    long RX_SEC_OFFLOAD = 1L << 17;
    
    /** Security offload failed */
    long RX_SEC_OFFLOAD_FAILED = 1L << 18;
    
    /** MACsec stripped */
    long RX_MACSEC_STRIPPED = 1L << 19;
    
    /** QinQ VLAN present */
    long RX_QINQ = 1L << 20;

    // ========== RESERVED FOR PROTOCOL DETECTION (bits 21-31) ==========
    // Available for future use: HAS_TCP, HAS_UDP, HAS_ICMP, etc.

    // ========== TX PROTOCOL/VERSION FLAGS (bits 32-37) ==========
    
    /** TX packet is IPv4 */
    long TX_IPV4 = 1L << 32;
    
    /** TX packet is IPv6 */
    long TX_IPV6 = 1L << 33;
    
    /** Compute outer IP checksum */
    long TX_OUTER_IP_CKSUM = 1L << 34;
    
    /** Compute outer UDP checksum */
    long TX_OUTER_UDP_CKSUM = 1L << 35;
    
    /** Outer header is IPv4 */
    long TX_OUTER_IPV4 = 1L << 36;
    
    /** Outer header is IPv6 */
    long TX_OUTER_IPV6 = 1L << 37;

    // ========== RESERVED (bits 38-42) ==========
    // Available for future expansion

    // ========== TX TUNNEL FLAGS (bits 43-52) ==========
    
    /** VXLAN tunnel */
    long TX_TUNNEL_VXLAN = 1L << 43;
    
    /** GRE tunnel */
    long TX_TUNNEL_GRE = 1L << 44;
    
    /** IP-in-IP tunnel */
    long TX_TUNNEL_IPIP = 1L << 45;
    
    /** GENEVE tunnel */
    long TX_TUNNEL_GENEVE = 1L << 46;
    
    /** MPLS over UDP tunnel */
    long TX_TUNNEL_MPLSOUDP = 1L << 47;
    
    /** VXLAN-GPE tunnel */
    long TX_TUNNEL_VXLAN_GPE = 1L << 48;
    
    /** GTP tunnel */
    long TX_TUNNEL_GTP = 1L << 49;
    
    /** ESP tunnel */
    long TX_TUNNEL_ESP = 1L << 50;
    
    /** L2TP tunnel */
    long TX_TUNNEL_L2TP = 1L << 51;
    
    /** Generic UDP tunnel */
    long TX_TUNNEL_UDP = 1L << 52;

    // ========== TX OFFLOAD FLAGS (bits 53-63) ==========
    
    /** MACsec offload */
    long TX_MACSEC = 1L << 53;
    
    /** Security offload */
    long TX_SEC_OFFLOAD = 1L << 54;
    
    /** Insert QinQ VLAN */
    long TX_QINQ = 1L << 55;
    
    /** TCP segmentation offload */
    long TX_TCP_SEG = 1L << 56;
    
    /** UDP segmentation offload */
    long TX_UDP_SEG = 1L << 57;
    
    /** IEEE1588 timestamp insertion */
    long TX_IEEE1588_TMST = 1L << 58;
    
    /** Compute TCP checksum */
    long TX_TCP_CKSUM = 1L << 59;
    
    /** Compute SCTP checksum */
    long TX_SCTP_CKSUM = 1L << 60;
    
    /** Compute UDP checksum */
    long TX_UDP_CKSUM = 1L << 61;
    
    /** Compute IP checksum */
    long TX_IP_CKSUM = 1L << 62;
    
    /** Insert VLAN tag */
    long TX_VLAN = 1L << 63;

    // ========== CONVENIENCE MASKS ==========
    
    /** Mask for RX IP checksum status */
    long MASK_RX_IP_CKSUM = RX_IP_CKSUM_BAD | RX_IP_CKSUM_GOOD;
    
    /** Mask for RX L4 checksum status */
    long MASK_RX_L4_CKSUM = RX_L4_CKSUM_BAD | RX_L4_CKSUM_GOOD;
    
    /** Mask for RX outer L4 checksum status */
    long MASK_RX_OUTER_L4_CKSUM = RX_OUTER_L4_CKSUM_BAD | RX_OUTER_L4_CKSUM_GOOD;

    /** Mask for all good checksum flags */
    long MASK_ALL_GOOD = RX_IP_CKSUM_GOOD | RX_L4_CKSUM_GOOD | RX_OUTER_L4_CKSUM_GOOD;

    /** Mask for all bad checksum flags */
    long MASK_ALL_BAD = RX_IP_CKSUM_BAD | RX_L4_CKSUM_BAD | RX_OUTER_IP_CKSUM_BAD | RX_OUTER_L4_CKSUM_BAD;

    /** Mask for all failed flags */
    long MASK_ALL_FAILED = RX_SEC_OFFLOAD_FAILED;

    /** Mask for all TX tunnel types */
    long MASK_TX_TUNNELS = TX_TUNNEL_VXLAN | TX_TUNNEL_GRE | TX_TUNNEL_IPIP | TX_TUNNEL_GENEVE
            | TX_TUNNEL_MPLSOUDP | TX_TUNNEL_VXLAN_GPE | TX_TUNNEL_GTP | TX_TUNNEL_ESP
            | TX_TUNNEL_L2TP | TX_TUNNEL_UDP;

    /** Mask for TX L4 checksum offloads */
    long MASK_TX_L4_CKSUM = TX_TCP_CKSUM | TX_SCTP_CKSUM | TX_UDP_CKSUM;

    /**
     * Gets the packet flag value.
     *
     * @return the flag value as long
     */
    long getPacketFlag();
}