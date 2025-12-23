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
package com.slytechs.jnet.protocol.api;

/**
 * Internal protocol identifiers with hierarchical family encoding.
 * 
 * <p>
 * This interface defines all protocol, option, and extension identifiers used
 * throughout the protocol sdk. Protocol IDs support hierarchical relationships
 * through family/parent encoding in the upper 16 bits.
 * </p>
 * 
 * <h2>ID Structure (32-bit)</h2>
 * 
 * <pre>
 * [4 flags][4 version][8 parent ordinal][8 pack][8 index]
 *  31---28  27----24   23-----------16   15---8  7----0
 * 
 * Lower 16 bits: Descriptor encoding (pack + protocol ordinal)
 * Upper 16 bits: Meta information (parent family + version + flags)
 * </pre>
 * 
 * <h2>Protocol Packs</h2>
 * <ul>
 * <li><b>BUILTIN (0x00xx):</b> System protocols (PAYLOAD, UNKNOWN, PAD)</li>
 * <li><b>INFRA (0x01xx):</b> Infrastructure (bridge, routing, management)</li>
 * <li><b>TCPIP (0x02xx):</b> Core TCP/IP stack</li>
 * <li><b>WEB (0x03xx):</b> Application layer protocols</li>
 * <li><b>TELCO (0x04xx):</b> Telecommunications protocols</li>
 * <li><b>INDUSTRIAL (0x05xx):</b> Industrial protocols (future)</li>
 * </ul>
 * 
 * <h2>Usage</h2>
 * 
 * <pre>{@code
 * import static com.slytechs.jnet.protocol.api.ProtocolId.*;
 * 
 * // Descriptor stores lower 16 bits only
 * int descriptorValue = IPv4 & MASK_DESCRIPTOR;  // 0x0221
 * 
 * // Generic header binding matches family
 * Ip ip = new Ip();  // Uses IP (0x0220)
 * if (packet.hasHeader(ip)) {
 *     // Matches IPv4 or IPv6 via parent lookup
 * }
 * 
 * // Version extraction
 * int version = versionOf(IPv4);  // Returns 4
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface ProtocolId {

	// @formatter:off
    
    // ════════════════════════════════════════════════════════════════════════════
    // Pack IDs (bits 15-8)
    // ════════════════════════════════════════════════════════════════════════════

    int PACK_BUILTIN    = 0x0000;  // System protocols
    int PACK_INFRA      = 0x0100;  // Infrastructure: bridge, routing, management
    int PACK_TCPIP      = 0x0200;  // Core TCP/IP stack
    int PACK_WEB        = 0x0300;  // Application layer
    int PACK_TELCO      = 0x0400;  // Telecommunications
    int PACK_INDUSTRIAL = 0x0500;  // Industrial (SCADA, Modbus) - future

    // ════════════════════════════════════════════════════════════════════════════
    // Masks and Shifts
    // ════════════════════════════════════════════════════════════════════════════

    // Lower 16 bits - descriptor encoding
    int MASK_INDEX      = 0x0000_00FF;
    int MASK_PACK       = 0x0000_FF00;
    int MASK_DESCRIPTOR = 0x0000_FFFF;

    // Upper 16 bits - meta encoding
    int MASK_PARENT     = 0x00FF_0000;
    int MASK_VERSION    = 0x0F00_0000;
    int MASK_FLAGS      = 0xF000_0000;
    int MASK_META       = 0xFFFF_0000;

    int SHIFT_INDEX   = 0;
    int SHIFT_PACK    = 8;
    int SHIFT_PARENT  = 16;
    int SHIFT_VERSION = 24;
    int SHIFT_FLAGS   = 28;

    // Option/Extension flags (bits 31-28)
    int FLAG_OPTION    = 0x8000_0000;  // Bit 31: In-header option
    int FLAG_EXTENSION = 0x4000_0000;  // Bit 30: External extension header

    // ════════════════════════════════════════════════════════════════════════════
    // BUILTIN PACK (0x00xx) - System protocols
    // Ordinals: 0x00-0x0F
    // ════════════════════════════════════════════════════════════════════════════

    int PAYLOAD = PACK_BUILTIN | 0x00;  // 0x0000 - Generic payload/data
    int UNKNOWN = PACK_BUILTIN | 0x01;  // 0x0001 - Unknown/unrecognized protocol
    int PAD     = PACK_BUILTIN | 0x02;  // 0x0002 - Padding bytes

    // Reserved: 0x0003-0x000F

    // ════════════════════════════════════════════════════════════════════════════
    // INFRA PACK (0x01xx) - Infrastructure Protocols
    // ════════════════════════════════════════════════════════════════════════════

    // ──────────────────────────────────────────────────────────────────────────
    // Bridge Protocols (0x0101-0x011F)
    // ──────────────────────────────────────────────────────────────────────────

    int STP_ORD  = 0x01;
    int STP      = PACK_INFRA | STP_ORD;                                  // 0x0101 - Spanning Tree Protocol (802.1D)
    int RSTP     = PACK_INFRA | 0x02 | (STP_ORD << 16);                   // 0x0102 - Rapid STP (802.1w)
    int MSTP     = PACK_INFRA | 0x03 | (STP_ORD << 16);                   // 0x0103 - Multiple STP (802.1s)
    int PVST     = PACK_INFRA | 0x04 | (STP_ORD << 16);                   // 0x0104 - Per-VLAN STP (Cisco)

    int LACP     = PACK_INFRA | 0x08;                                     // 0x0108 - Link Aggregation (802.3ad)
    int PAGP     = PACK_INFRA | 0x09;                                     // 0x0109 - Port Aggregation (Cisco)
    int MARKER   = PACK_INFRA | 0x0A;                                     // 0x010A - Marker Protocol (802.3ad)

    int CFM      = PACK_INFRA | 0x0C;                                     // 0x010C - Connectivity Fault Mgmt (802.1ag)
    int OAM      = PACK_INFRA | 0x0D;                                     // 0x010D - Operations/Admin/Maint (802.3ah)
    int ELMI     = PACK_INFRA | 0x0E;                                     // 0x010E - E-LMI

    int RESERVED_BRIDGE_1 = PACK_INFRA | 0x1E;                            // Reserved
    int RESERVED_BRIDGE_2 = PACK_INFRA | 0x1F;                            // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Routing Protocols (0x0120-0x013F)
    // ──────────────────────────────────────────────────────────────────────────

    int OSPF     = PACK_INFRA | 0x20;                                     // 0x0120 - Open Shortest Path First
    int OSPFv2   = PACK_INFRA | 0x21 | (0x20 << 16) | (2 << 24);          // 0x0121 - OSPFv2 (IPv4)
    int OSPFv3   = PACK_INFRA | 0x22 | (0x20 << 16) | (3 << 24);          // 0x0122 - OSPFv3 (IPv6)

    int BGP_ORD  = 0x24;
    int BGP      = PACK_INFRA | BGP_ORD;                                  // 0x0124 - Border Gateway Protocol
    int BGP4     = PACK_INFRA | 0x25 | (BGP_ORD << 16) | (4 << 24);       // 0x0125 - BGP-4

    int ISIS_ORD = 0x28;
    int ISIS     = PACK_INFRA | ISIS_ORD;                                 // 0x0128 - Intermediate System to IS
    int ISIS_L1  = PACK_INFRA | 0x29 | (ISIS_ORD << 16) | (1 << 24);      // 0x0129 - IS-IS Level 1
    int ISIS_L2  = PACK_INFRA | 0x2A | (ISIS_ORD << 16) | (2 << 24);      // 0x012A - IS-IS Level 2

    int EIGRP    = PACK_INFRA | 0x2C;                                     // 0x012C - Enhanced IGRP
    int RIP_ORD  = 0x2D;
    int RIP      = PACK_INFRA | RIP_ORD;                                  // 0x012D - Routing Information Protocol
    int RIPv1    = PACK_INFRA | 0x2E | (RIP_ORD << 16) | (1 << 24);       // 0x012E - RIP v1
    int RIPv2    = PACK_INFRA | 0x2F | (RIP_ORD << 16) | (2 << 24);       // 0x012F - RIP v2
    int RIPng    = PACK_INFRA | 0x30 | (RIP_ORD << 16) | (6 << 24);       // 0x0130 - RIPng (IPv6)

    int PIM      = PACK_INFRA | 0x32;                                     // 0x0132 - Protocol Independent Multicast
    int VRRP_ORD = 0x34;
    int VRRP     = PACK_INFRA | VRRP_ORD;                                 // 0x0134 - Virtual Router Redundancy
    int VRRPv2   = PACK_INFRA | 0x35 | (VRRP_ORD << 16) | (2 << 24);      // 0x0135 - VRRPv2
    int VRRPv3   = PACK_INFRA | 0x36 | (VRRP_ORD << 16) | (3 << 24);      // 0x0136 - VRRPv3

    int HSRP     = PACK_INFRA | 0x38;                                     // 0x0138 - Hot Standby Router (Cisco)
    int GLBP     = PACK_INFRA | 0x39;                                     // 0x0139 - Gateway Load Balancing (Cisco)

    int RESERVED_ROUTING_1 = PACK_INFRA | 0x3E;                           // Reserved
    int RESERVED_ROUTING_2 = PACK_INFRA | 0x3F;                           // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Discovery Protocols (0x0140-0x015F)
    // ──────────────────────────────────────────────────────────────────────────

    int LLDP     = PACK_INFRA | 0x40;                                     // 0x0140 - Link Layer Discovery (802.1AB)
    int CDP      = PACK_INFRA | 0x41;                                     // 0x0141 - Cisco Discovery Protocol
    int EDP      = PACK_INFRA | 0x42;                                     // 0x0142 - Extreme Discovery Protocol
    int FDP      = PACK_INFRA | 0x43;                                     // 0x0143 - Foundry Discovery Protocol
    int NDP      = PACK_INFRA | 0x44;                                     // 0x0144 - Nortel Discovery Protocol

    int RESERVED_DISCOVERY_1 = PACK_INFRA | 0x5E;                         // Reserved
    int RESERVED_DISCOVERY_2 = PACK_INFRA | 0x5F;                         // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Management/Monitoring Protocols (0x0160-0x017F)
    // ──────────────────────────────────────────────────────────────────────────

    int SNMP_ORD = 0x60;
    int SNMP     = PACK_INFRA | SNMP_ORD;                                 // 0x0160 - Simple Network Management
    int SNMPv1   = PACK_INFRA | 0x61 | (SNMP_ORD << 16) | (1 << 24);      // 0x0161 - SNMPv1
    int SNMPv2c  = PACK_INFRA | 0x62 | (SNMP_ORD << 16) | (2 << 24);      // 0x0162 - SNMPv2c
    int SNMPv3   = PACK_INFRA | 0x63 | (SNMP_ORD << 16) | (3 << 24);      // 0x0163 - SNMPv3

    int NETFLOW_ORD = 0x68;
    int NETFLOW  = PACK_INFRA | NETFLOW_ORD;                              // 0x0168 - NetFlow
    int NFv5     = PACK_INFRA | 0x69 | (NETFLOW_ORD << 16) | (5 << 24);   // 0x0169 - NetFlow v5
    int NFv9     = PACK_INFRA | 0x6A | (NETFLOW_ORD << 16) | (9 << 24);   // 0x016A - NetFlow v9
    int IPFIX    = PACK_INFRA | 0x6B | (NETFLOW_ORD << 16) | (10 << 24);  // 0x016B - IPFIX (v10)

    int SFLOW    = PACK_INFRA | 0x70;                                     // 0x0170 - sFlow
    int JFLOW    = PACK_INFRA | 0x71;                                     // 0x0171 - J-Flow (Juniper)
    int RFLOW    = PACK_INFRA | 0x72;                                     // 0x0172 - R-Flow (Ericsson)
    int CFLOW    = PACK_INFRA | 0x73;                                     // 0x0173 - cflowd

    int RESERVED_MGMT_1 = PACK_INFRA | 0x7E;                              // Reserved
    int RESERVED_MGMT_2 = PACK_INFRA | 0x7F;                              // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Time Protocols (0x0180-0x018F)
    // ──────────────────────────────────────────────────────────────────────────

    int NTP_ORD  = 0x80;
    int NTP      = PACK_INFRA | NTP_ORD;                                  // 0x0180 - Network Time Protocol
    int NTPv3    = PACK_INFRA | 0x81 | (NTP_ORD << 16) | (3 << 24);       // 0x0181 - NTPv3
    int NTPv4    = PACK_INFRA | 0x82 | (NTP_ORD << 16) | (4 << 24);       // 0x0182 - NTPv4
    int SNTP     = PACK_INFRA | 0x83 | (NTP_ORD << 16);                   // 0x0183 - Simple NTP

    int PTP_ORD  = 0x88;
    int PTP      = PACK_INFRA | PTP_ORD;                                  // 0x0188 - Precision Time (IEEE 1588)
    int PTPv1    = PACK_INFRA | 0x89 | (PTP_ORD << 16) | (1 << 24);       // 0x0189 - PTPv1
    int PTPv2    = PACK_INFRA | 0x8A | (PTP_ORD << 16) | (2 << 24);       // 0x018A - PTPv2

    int RESERVED_TIME_1 = PACK_INFRA | 0x8E;                              // Reserved
    int RESERVED_TIME_2 = PACK_INFRA | 0x8F;                              // Reserved

    // Reserved: 0x0190-0x01FF

    // ════════════════════════════════════════════════════════════════════════════
    // TCPIP PACK (0x02xx) - Core TCP/IP Stack
    // ════════════════════════════════════════════════════════════════════════════

    // ──────────────────────────────────────────────────────────────────────────
    // Layer 2 - Core Data Link (0x0201-0x020F)
    // ──────────────────────────────────────────────────────────────────────────

    int ETHERNET = PACK_TCPIP | 0x01;                                     // 0x0201 - Ethernet II (DIX)
    int LLC      = PACK_TCPIP | 0x02;                                     // 0x0202 - Logical Link Control
    int SNAP     = PACK_TCPIP | 0x03;                                     // 0x0203 - SNAP
    int ARP      = PACK_TCPIP | 0x04;                                     // 0x0204 - Address Resolution Protocol
    int RARP     = PACK_TCPIP | 0x05;                                     // 0x0205 - Reverse ARP
    int SLARP    = PACK_TCPIP | 0x06;                                     // 0x0206 - Serial Line ARP

    int RESERVED_L2_CORE_1 = PACK_TCPIP | 0x0E;                           // Reserved
    int RESERVED_L2_CORE_2 = PACK_TCPIP | 0x0F;                           // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Layer 2 - Reserved (0x0210-0x0217)
    // ──────────────────────────────────────────────────────────────────────────


    // ──────────────────────────────────────────────────────────────────────────
    // Layer 2 - VLAN/MPLS Extensions (0x0218-0x021F)
    // ──────────────────────────────────────────────────────────────────────────

    int VLAN_ORD    = 0x18;
    int VLAN        = PACK_TCPIP | VLAN_ORD;                              // 0x0218 - VLAN Family
    int VLAN_8021Q  = PACK_TCPIP | 0x19 | (VLAN_ORD << 16);               // 0x0219 - 802.1Q
    int VLAN_8021AD = PACK_TCPIP | 0x1A | (VLAN_ORD << 16);               // 0x021A - 802.1ad (QinQ)

    int MPLS     = PACK_TCPIP | 0x1C;                                     // 0x021C - MPLS
    int MPLS_MC  = PACK_TCPIP | 0x1D;                                     // 0x021D - MPLS Multicast

    int RESERVED_L2_EXT_1 = PACK_TCPIP | 0x1E;                            // Reserved
    int RESERVED_L2_EXT_2 = PACK_TCPIP | 0x1F;                            // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Layer 3 - IP Family (0x0220-0x0227)
    // ──────────────────────────────────────────────────────────────────────────

    int IP_ORD   = 0x20;
    int IP       = PACK_TCPIP | IP_ORD;                                   // 0x0220 - IP Family
    int IPv4     = PACK_TCPIP | 0x21 | (IP_ORD << 16) | (4 << 24);        // 0x0221 - IPv4
    int IPv6     = PACK_TCPIP | 0x22 | (IP_ORD << 16) | (6 << 24);        // 0x0222 - IPv6

    int RESERVED_IP_1 = PACK_TCPIP | 0x26;                                // Reserved
    int RESERVED_IP_2 = PACK_TCPIP | 0x27;                                // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Layer 3 - ICMP Family (0x0228-0x022F)
    // ──────────────────────────────────────────────────────────────────────────

    int ICMP_ORD = 0x28;
    int ICMP     = PACK_TCPIP | ICMP_ORD;                                 // 0x0228 - ICMP Family
    int ICMPv4   = PACK_TCPIP | 0x29 | (ICMP_ORD << 16) | (4 << 24);      // 0x0229 - ICMPv4
    int ICMPv6   = PACK_TCPIP | 0x2A | (ICMP_ORD << 16) | (6 << 24);      // 0x022A - ICMPv6
    int IGMP     = PACK_TCPIP | 0x2B;                                     // 0x022B - IGMP
    int MLD      = PACK_TCPIP | 0x2C;                                     // 0x022C - Multicast Listener Discovery

    int RESERVED_ICMP_1 = PACK_TCPIP | 0x2E;                              // Reserved
    int RESERVED_ICMP_2 = PACK_TCPIP | 0x2F;                              // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Layer 3 - IPsec Family (0x0230-0x0237)
    // ──────────────────────────────────────────────────────────────────────────

    int IPSEC_ORD   = 0x30;
    int IPSEC       = PACK_TCPIP | IPSEC_ORD;                             // 0x0230 - IPsec Family
    int AH          = PACK_TCPIP | 0x31 | (IPSEC_ORD << 16);              // 0x0231 - Authentication Header
    int ESP         = PACK_TCPIP | 0x32 | (IPSEC_ORD << 16);              // 0x0232 - Encapsulating Security
    int ESP_TRAILER = PACK_TCPIP | 0x33 | (IPSEC_ORD << 16);              // 0x0233 - ESP Trailer
    int IKE         = PACK_TCPIP | 0x34 | (IPSEC_ORD << 16);              // 0x0234 - IKE
    int IKEv2       = PACK_TCPIP | 0x35 | (IPSEC_ORD << 16) | (2 << 24);  // 0x0235 - IKEv2

    int RESERVED_IPSEC_1 = PACK_TCPIP | 0x36;                             // Reserved
    int RESERVED_IPSEC_2 = PACK_TCPIP | 0x37;                             // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Reserved Layer 3 (0x0238-0x023F)
    // ──────────────────────────────────────────────────────────────────────────

    int RESERVED_L3_1 = PACK_TCPIP | 0x38;                                // Reserved
    int RESERVED_L3_2 = PACK_TCPIP | 0x39;                                // Reserved
    int RESERVED_L3_3 = PACK_TCPIP | 0x3A;                                // Reserved
    int RESERVED_L3_4 = PACK_TCPIP | 0x3B;                                // Reserved
    int RESERVED_L3_5 = PACK_TCPIP | 0x3C;                                // Reserved
    int RESERVED_L3_6 = PACK_TCPIP | 0x3D;                                // Reserved
    int RESERVED_L3_7 = PACK_TCPIP | 0x3E;                                // Reserved
    int RESERVED_L3_8 = PACK_TCPIP | 0x3F;                                // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Layer 4 - Transport (0x0240-0x024F)
    // ──────────────────────────────────────────────────────────────────────────

    int TCP      = PACK_TCPIP | 0x40;                                     // 0x0240 - TCP
    int UDP      = PACK_TCPIP | 0x41;                                     // 0x0241 - UDP
    int SCTP     = PACK_TCPIP | 0x42;                                     // 0x0242 - SCTP
    int DCCP     = PACK_TCPIP | 0x43;                                     // 0x0243 - DCCP
    int UDP_LITE = PACK_TCPIP | 0x44;                                     // 0x0244 - UDP-Lite

    int RESERVED_L4_1 = PACK_TCPIP | 0x4E;                                // Reserved
    int RESERVED_L4_2 = PACK_TCPIP | 0x4F;                                // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Tunneling Protocols (0x0260-0x027F)
    // ──────────────────────────────────────────────────────────────────────────

    int GRE_ORD    = 0x60;
    int GRE        = PACK_TCPIP | GRE_ORD;                                // 0x0260 - GRE Family
    int GREv0      = PACK_TCPIP | 0x61 | (GRE_ORD << 16) | (0 << 24);     // 0x0261 - GREv0
    int GREv1      = PACK_TCPIP | 0x62 | (GRE_ORD << 16) | (1 << 24);     // 0x0262 - GREv1 (PPTP)
    int NVGRE      = PACK_TCPIP | 0x63 | (GRE_ORD << 16);                 // 0x0263 - NVGRE
    int ERSPAN     = PACK_TCPIP | 0x64 | (GRE_ORD << 16);                 // 0x0264 - ERSPAN

    int IP_IN_IP   = PACK_TCPIP | 0x68;                                   // 0x0268 - IP-in-IP (Proto 4)
    int IPv6_IN_IP = PACK_TCPIP | 0x69;                                   // 0x0269 - IPv6-in-IP (Proto 41)
    int IPIP6      = PACK_TCPIP | 0x6A;                                   // 0x026A - IP in IPv6

    int VXLAN      = PACK_TCPIP | 0x6C;                                   // 0x026C - VXLAN
    int VXLAN_GPE  = PACK_TCPIP | 0x6D;                                   // 0x026D - VXLAN-GPE
    int GENEVE     = PACK_TCPIP | 0x6E;                                   // 0x026E - Geneve

    int L2TP_ORD   = 0x70;
    int L2TP       = PACK_TCPIP | L2TP_ORD;                               // 0x0270 - L2TP Family
    int L2TPv2     = PACK_TCPIP | 0x71 | (L2TP_ORD << 16) | (2 << 24);    // 0x0271 - L2TPv2
    int L2TPv3     = PACK_TCPIP | 0x72 | (L2TP_ORD << 16) | (3 << 24);    // 0x0272 - L2TPv3

    int TEREDO     = PACK_TCPIP | 0x74;                                   // 0x0274 - Teredo
    int WIREGUARD  = PACK_TCPIP | 0x75;                                   // 0x0275 - WireGuard

    int RESERVED_TUNNEL_1 = PACK_TCPIP | 0x7E;                            // Reserved
    int RESERVED_TUNNEL_2 = PACK_TCPIP | 0x7F;                            // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // PPP Family (0x0280-0x028F)
    // ──────────────────────────────────────────────────────────────────────────

    int PPP_ORD  = 0x80;
    int PPP      = PACK_TCPIP | PPP_ORD;                                  // 0x0280 - PPP Family
    int PPPoE    = PACK_TCPIP | 0x81 | (PPP_ORD << 16);                   // 0x0281 - PPP over Ethernet
    int PPPoE_D  = PACK_TCPIP | 0x82 | (PPP_ORD << 16);                   // 0x0282 - PPPoE Discovery
    int PPPoE_S  = PACK_TCPIP | 0x83 | (PPP_ORD << 16);                   // 0x0283 - PPPoE Session
    int HDLC     = PACK_TCPIP | 0x84;                                     // 0x0284 - HDLC
    int CHDLC    = PACK_TCPIP | 0x85;                                     // 0x0285 - Cisco HDLC

    int RESERVED_PPP_1 = PACK_TCPIP | 0x8E;                               // Reserved
    int RESERVED_PPP_2 = PACK_TCPIP | 0x8F;                               // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // IPv4 Options (0x02A0-0x02AF) - FLAG_OPTION set
    // ──────────────────────────────────────────────────────────────────────────

    int IPv4_OPT_EOL       = FLAG_OPTION | (0x21 << 16) | PACK_TCPIP | 0xA0;  // End of Options
    int IPv4_OPT_NOP       = FLAG_OPTION | (0x21 << 16) | PACK_TCPIP | 0xA1;  // No Operation
    int IPv4_OPT_SECURITY  = FLAG_OPTION | (0x21 << 16) | PACK_TCPIP | 0xA2;  // Security (RFC 1108)
    int IPv4_OPT_LSRR      = FLAG_OPTION | (0x21 << 16) | PACK_TCPIP | 0xA3;  // Loose Source Route
    int IPv4_OPT_TIMESTAMP = FLAG_OPTION | (0x21 << 16) | PACK_TCPIP | 0xA4;  // Timestamp
    int IPv4_OPT_RR        = FLAG_OPTION | (0x21 << 16) | PACK_TCPIP | 0xA5;  // Record Route
    int IPv4_OPT_SSRR      = FLAG_OPTION | (0x21 << 16) | PACK_TCPIP | 0xA6;  // Strict Source Route
    int IPv4_OPT_RA        = FLAG_OPTION | (0x21 << 16) | PACK_TCPIP | 0xA7;  // Router Alert

    // ──────────────────────────────────────────────────────────────────────────
    // IPv6 Extension Headers (0x02B0-0x02BF) - FLAG_EXTENSION set
    // ──────────────────────────────────────────────────────────────────────────

    int IPv6_HOPOPT   = FLAG_EXTENSION | (0x22 << 16) | PACK_TCPIP | 0xB0;    // Hop-by-Hop Options
    int IPv6_ROUTING  = FLAG_EXTENSION | (0x22 << 16) | PACK_TCPIP | 0xB1;    // Routing Header
    int IPv6_FRAG     = FLAG_EXTENSION | (0x22 << 16) | PACK_TCPIP | 0xB2;    // Fragment Header
    int IPv6_DSTOPT   = FLAG_EXTENSION | (0x22 << 16) | PACK_TCPIP | 0xB3;    // Destination Options
    int IPv6_AUTH     = FLAG_EXTENSION | (0x22 << 16) | PACK_TCPIP | 0xB4;    // Authentication (AH)
    int IPv6_ESP      = FLAG_EXTENSION | (0x22 << 16) | PACK_TCPIP | 0xB5;    // Encapsulating Security
    int IPv6_MOBILITY = FLAG_EXTENSION | (0x22 << 16) | PACK_TCPIP | 0xB6;    // Mobility Header
    int IPv6_HIP      = FLAG_EXTENSION | (0x22 << 16) | PACK_TCPIP | 0xB7;    // Host Identity Protocol
    int IPv6_SHIM6    = FLAG_EXTENSION | (0x22 << 16) | PACK_TCPIP | 0xB8;    // Shim6

    // ──────────────────────────────────────────────────────────────────────────
    // TCP Options (0x02C0-0x02CF) - FLAG_OPTION set
    // ──────────────────────────────────────────────────────────────────────────

    int TCP_OPT_EOL       = FLAG_OPTION | (0x40 << 16) | PACK_TCPIP | 0xC0;   // End of Options
    int TCP_OPT_NOP       = FLAG_OPTION | (0x40 << 16) | PACK_TCPIP | 0xC1;   // No Operation
    int TCP_OPT_MSS       = FLAG_OPTION | (0x40 << 16) | PACK_TCPIP | 0xC2;   // Maximum Segment Size
    int TCP_OPT_WSCALE    = FLAG_OPTION | (0x40 << 16) | PACK_TCPIP | 0xC3;   // Window Scale
    int TCP_OPT_SACK_PERM = FLAG_OPTION | (0x40 << 16) | PACK_TCPIP | 0xC4;   // SACK Permitted
    int TCP_OPT_SACK      = FLAG_OPTION | (0x40 << 16) | PACK_TCPIP | 0xC5;   // SACK
    int TCP_OPT_TIMESTAMP = FLAG_OPTION | (0x40 << 16) | PACK_TCPIP | 0xC8;   // Timestamps
    int TCP_OPT_MD5       = FLAG_OPTION | (0x40 << 16) | PACK_TCPIP | 0xC9;   // MD5 Signature
    int TCP_OPT_FASTOPEN  = FLAG_OPTION | (0x40 << 16) | PACK_TCPIP | 0xCA;   // Fast Open Cookie
    int TCP_OPT_MPTCP     = FLAG_OPTION | (0x40 << 16) | PACK_TCPIP | 0xCB;   // Multipath TCP

    // Reserved: 0x02D0-0x02FF

    // ════════════════════════════════════════════════════════════════════════════
    // WEB PACK (0x03xx) - Application Layer Protocols
    // ════════════════════════════════════════════════════════════════════════════

    // ──────────────────────────────────────────────────────────────────────────
    // TLS/SSL Family (0x0301-0x030F)
    // ──────────────────────────────────────────────────────────────────────────

    int TLS_ORD  = 0x01;
    int TLS      = PACK_WEB | TLS_ORD;                                    // 0x0301 - TLS Family
    int SSL2     = PACK_WEB | 0x02 | (TLS_ORD << 16) | (2 << 24);         // 0x0302 - SSL 2.0
    int SSL3     = PACK_WEB | 0x03 | (TLS_ORD << 16) | (3 << 24);         // 0x0303 - SSL 3.0
    int TLS1_0   = PACK_WEB | 0x04 | (TLS_ORD << 16) | (0x10 << 24);      // 0x0304 - TLS 1.0
    int TLS1_1   = PACK_WEB | 0x05 | (TLS_ORD << 16) | (0x11 << 24);      // 0x0305 - TLS 1.1
    int TLS1_2   = PACK_WEB | 0x06 | (TLS_ORD << 16) | (0x12 << 24);      // 0x0306 - TLS 1.2
    int TLS1_3   = PACK_WEB | 0x07 | (TLS_ORD << 16) | (0x13 << 24);      // 0x0307 - TLS 1.3

    int DTLS_ORD = 0x08;
    int DTLS     = PACK_WEB | DTLS_ORD | (TLS_ORD << 16);                 // 0x0308 - DTLS Family
    int DTLS1_0  = PACK_WEB | 0x09 | (DTLS_ORD << 16) | (0x10 << 24);     // 0x0309 - DTLS 1.0
    int DTLS1_2  = PACK_WEB | 0x0A | (DTLS_ORD << 16) | (0x12 << 24);     // 0x030A - DTLS 1.2
    int DTLS1_3  = PACK_WEB | 0x0B | (DTLS_ORD << 16) | (0x13 << 24);     // 0x030B - DTLS 1.3

    int RESERVED_TLS_1 = PACK_WEB | 0x0E;                                 // Reserved
    int RESERVED_TLS_2 = PACK_WEB | 0x0F;                                 // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // HTTP Family (0x0310-0x031F)
    // ──────────────────────────────────────────────────────────────────────────

    int HTTP_ORD = 0x10;
    int HTTP     = PACK_WEB | HTTP_ORD;                                   // 0x0310 - HTTP Family
    int HTTP0_9  = PACK_WEB | 0x11 | (HTTP_ORD << 16) | (0x09 << 24);     // 0x0311 - HTTP/0.9
    int HTTP1_0  = PACK_WEB | 0x12 | (HTTP_ORD << 16) | (0x10 << 24);     // 0x0312 - HTTP/1.0
    int HTTP1_1  = PACK_WEB | 0x13 | (HTTP_ORD << 16) | (0x11 << 24);     // 0x0313 - HTTP/1.1
    int HTTP2    = PACK_WEB | 0x14 | (HTTP_ORD << 16) | (2 << 24);        // 0x0314 - HTTP/2
    int HTTP3    = PACK_WEB | 0x15 | (HTTP_ORD << 16) | (3 << 24);        // 0x0315 - HTTP/3

    int RESERVED_HTTP_1 = PACK_WEB | 0x1E;                                // Reserved
    int RESERVED_HTTP_2 = PACK_WEB | 0x1F;                                // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // QUIC Family (0x0320-0x032F)
    // ──────────────────────────────────────────────────────────────────────────

    int QUIC_ORD = 0x20;
    int QUIC     = PACK_WEB | QUIC_ORD;                                   // 0x0320 - QUIC Family
    int QUIC_V1  = PACK_WEB | 0x21 | (QUIC_ORD << 16) | (1 << 24);        // 0x0321 - QUIC v1 (RFC 9000)
    int QUIC_V2  = PACK_WEB | 0x22 | (QUIC_ORD << 16) | (2 << 24);        // 0x0322 - QUIC v2 (RFC 9369)

    int RESERVED_QUIC_1 = PACK_WEB | 0x2E;                                // Reserved
    int RESERVED_QUIC_2 = PACK_WEB | 0x2F;                                // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // DNS Family (0x0330-0x033F)
    // ──────────────────────────────────────────────────────────────────────────

    int DNS_ORD  = 0x30;
    int DNS      = PACK_WEB | DNS_ORD;                                    // 0x0330 - DNS Family
    int DNS_UDP  = PACK_WEB | 0x31 | (DNS_ORD << 16);                     // 0x0331 - DNS over UDP
    int DNS_TCP  = PACK_WEB | 0x32 | (DNS_ORD << 16);                     // 0x0332 - DNS over TCP
    int DOH      = PACK_WEB | 0x33 | (DNS_ORD << 16);                     // 0x0333 - DNS over HTTPS
    int DOT      = PACK_WEB | 0x34 | (DNS_ORD << 16);                     // 0x0334 - DNS over TLS
    int DOQ      = PACK_WEB | 0x35 | (DNS_ORD << 16);                     // 0x0335 - DNS over QUIC
    int MDNS     = PACK_WEB | 0x36 | (DNS_ORD << 16);                     // 0x0336 - Multicast DNS
    int LLMNR    = PACK_WEB | 0x37 | (DNS_ORD << 16);                     // 0x0337 - LLMNR

    int RESERVED_DNS_1 = PACK_WEB | 0x3E;                                 // Reserved
    int RESERVED_DNS_2 = PACK_WEB | 0x3F;                                 // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // DHCP Family (0x0340-0x034F)
    // ──────────────────────────────────────────────────────────────────────────

    int DHCP_ORD = 0x40;
    int DHCP     = PACK_WEB | DHCP_ORD;                                   // 0x0340 - DHCP Family
    int DHCPv4   = PACK_WEB | 0x41 | (DHCP_ORD << 16) | (4 << 24);        // 0x0341 - DHCPv4
    int DHCPv6   = PACK_WEB | 0x42 | (DHCP_ORD << 16) | (6 << 24);        // 0x0342 - DHCPv6
    int BOOTP    = PACK_WEB | 0x43;                                       // 0x0343 - BOOTP

    int RESERVED_DHCP_1 = PACK_WEB | 0x4E;                                // Reserved
    int RESERVED_DHCP_2 = PACK_WEB | 0x4F;                                // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Email Protocols (0x0350-0x035F)
    // ──────────────────────────────────────────────────────────────────────────

    int SMTP     = PACK_WEB | 0x50;                                       // 0x0350 - SMTP
    int SMTPS    = PACK_WEB | 0x51;                                       // 0x0351 - SMTP over TLS
    int POP3     = PACK_WEB | 0x52;                                       // 0x0352 - POP3
    int POP3S    = PACK_WEB | 0x53;                                       // 0x0353 - POP3 over TLS
    int IMAP     = PACK_WEB | 0x54;                                       // 0x0354 - IMAP
    int IMAPS    = PACK_WEB | 0x55;                                       // 0x0355 - IMAP over TLS

    int RESERVED_EMAIL_1 = PACK_WEB | 0x5E;                               // Reserved
    int RESERVED_EMAIL_2 = PACK_WEB | 0x5F;                               // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Remote Access Protocols (0x0360-0x036F)
    // ──────────────────────────────────────────────────────────────────────────

    int SSH_ORD  = 0x60;
    int SSH      = PACK_WEB | SSH_ORD;                                    // 0x0360 - SSH Family
    int SSHv1    = PACK_WEB | 0x61 | (SSH_ORD << 16) | (1 << 24);         // 0x0361 - SSHv1
    int SSHv2    = PACK_WEB | 0x62 | (SSH_ORD << 16) | (2 << 24);         // 0x0362 - SSHv2

    int TELNET   = PACK_WEB | 0x64;                                       // 0x0364 - Telnet
    int FTP      = PACK_WEB | 0x65;                                       // 0x0365 - FTP
    int FTPS     = PACK_WEB | 0x66;                                       // 0x0366 - FTP over TLS
    int SFTP     = PACK_WEB | 0x67;                                       // 0x0367 - SFTP (SSH)
    int TFTP     = PACK_WEB | 0x68;                                       // 0x0368 - TFTP
    int RDP      = PACK_WEB | 0x69;                                       // 0x0369 - Remote Desktop
    int VNC      = PACK_WEB | 0x6A;                                       // 0x036A - VNC

    int RESERVED_REMOTE_1 = PACK_WEB | 0x6E;                              // Reserved
    int RESERVED_REMOTE_2 = PACK_WEB | 0x6F;                              // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // VoIP/RTP Family (0x0370-0x037F)
    // ──────────────────────────────────────────────────────────────────────────

    int RTP_ORD  = 0x70;
    int RTP      = PACK_WEB | RTP_ORD;                                    // 0x0370 - RTP Family
    int RTCP     = PACK_WEB | 0x71 | (RTP_ORD << 16);                     // 0x0371 - RTCP
    int SRTP     = PACK_WEB | 0x72 | (RTP_ORD << 16);                     // 0x0372 - Secure RTP
    int SRTCP    = PACK_WEB | 0x73 | (RTP_ORD << 16);                     // 0x0373 - Secure RTCP
    int RTSP     = PACK_WEB | 0x74;                                       // 0x0374 - RTSP

    int SIP_ORD  = 0x78;
    int SIP      = PACK_WEB | SIP_ORD;                                    // 0x0378 - SIP Family
    int SIP_UDP  = PACK_WEB | 0x79 | (SIP_ORD << 16);                     // 0x0379 - SIP over UDP
    int SIP_TCP  = PACK_WEB | 0x7A | (SIP_ORD << 16);                     // 0x037A - SIP over TCP
    int SIP_TLS  = PACK_WEB | 0x7B | (SIP_ORD << 16);                     // 0x037B - SIP over TLS
    int SIP_WS   = PACK_WEB | 0x7C | (SIP_ORD << 16);                     // 0x037C - SIP over WebSocket

    int RESERVED_VOIP_1 = PACK_WEB | 0x7E;                                // Reserved
    int RESERVED_VOIP_2 = PACK_WEB | 0x7F;                                // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Web Services/Modern Protocols (0x0380-0x038F)
    // ──────────────────────────────────────────────────────────────────────────

    int WEBSOCKET = PACK_WEB | 0x80;                                      // 0x0380 - WebSocket
    int GRPC      = PACK_WEB | 0x81;                                      // 0x0381 - gRPC
    int GRAPHQL   = PACK_WEB | 0x82;                                      // 0x0382 - GraphQL
    int MQTT_ORD  = 0x84;
    int MQTT      = PACK_WEB | MQTT_ORD;                                  // 0x0384 - MQTT Family
    int MQTTv3    = PACK_WEB | 0x85 | (MQTT_ORD << 16) | (3 << 24);       // 0x0385 - MQTT v3
    int MQTTv5    = PACK_WEB | 0x86 | (MQTT_ORD << 16) | (5 << 24);       // 0x0386 - MQTT v5
    int AMQP      = PACK_WEB | 0x88;                                      // 0x0388 - AMQP
    int COAP      = PACK_WEB | 0x89;                                      // 0x0389 - CoAP

    int RESERVED_WS_1 = PACK_WEB | 0x8E;                                  // Reserved
    int RESERVED_WS_2 = PACK_WEB | 0x8F;                                  // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Directory/Authentication (0x0390-0x039F)
    // ──────────────────────────────────────────────────────────────────────────

    int LDAP_ORD = 0x90;
    int LDAP     = PACK_WEB | LDAP_ORD;                                   // 0x0390 - LDAP Family
    int LDAPv2   = PACK_WEB | 0x91 | (LDAP_ORD << 16) | (2 << 24);        // 0x0391 - LDAPv2
    int LDAPv3   = PACK_WEB | 0x92 | (LDAP_ORD << 16) | (3 << 24);        // 0x0392 - LDAPv3
    int LDAPS    = PACK_WEB | 0x93 | (LDAP_ORD << 16);                    // 0x0393 - LDAP over TLS

    int KERBEROS = PACK_WEB | 0x98;                                       // 0x0398 - Kerberos
    int RADIUS   = PACK_WEB | 0x99;                                       // 0x0399 - RADIUS
    int DIAMETER = PACK_WEB | 0x9A;                                       // 0x039A - Diameter
    int TACACS   = PACK_WEB | 0x9B;                                       // 0x039B - TACACS+

    int RESERVED_AUTH_1 = PACK_WEB | 0x9E;                                // Reserved
    int RESERVED_AUTH_2 = PACK_WEB | 0x9F;                                // Reserved

    // Reserved: 0x03A0-0x03FF

    // ════════════════════════════════════════════════════════════════════════════
    // TELCO PACK (0x04xx) - Telecommunications Protocols
    // ════════════════════════════════════════════════════════════════════════════

    // ──────────────────────────────────────────────────────────────────────────
    // GTP Family (0x0401-0x040F)
    // ──────────────────────────────────────────────────────────────────────────

    int GTP_ORD  = 0x01;
    int GTP      = PACK_TELCO | GTP_ORD;                                  // 0x0401 - GTP Family
    int GTPv0    = PACK_TELCO | 0x02 | (GTP_ORD << 16) | (0 << 24);       // 0x0402 - GTPv0
    int GTPv1_C  = PACK_TELCO | 0x03 | (GTP_ORD << 16) | (1 << 24);       // 0x0403 - GTPv1-C
    int GTPv1_U  = PACK_TELCO | 0x04 | (GTP_ORD << 16) | (1 << 24);       // 0x0404 - GTPv1-U
    int GTPv2_C  = PACK_TELCO | 0x05 | (GTP_ORD << 16) | (2 << 24);       // 0x0405 - GTPv2-C
    int GTP_PRIME = PACK_TELCO | 0x06 | (GTP_ORD << 16);                  // 0x0406 - GTP' (charging)

    int RESERVED_GTP_1 = PACK_TELCO | 0x0E;                               // Reserved
    int RESERVED_GTP_2 = PACK_TELCO | 0x0F;                               // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // SS7/SIGTRAN Family (0x0410-0x042F)
    // ──────────────────────────────────────────────────────────────────────────

    int M3UA     = PACK_TELCO | 0x10;                                     // 0x0410 - MTP3 User Adaptation
    int M2UA     = PACK_TELCO | 0x11;                                     // 0x0411 - MTP2 User Adaptation
    int M2PA     = PACK_TELCO | 0x12;                                     // 0x0412 - MTP2 Peer Adaptation
    int SUA      = PACK_TELCO | 0x13;                                     // 0x0413 - SCCP User Adaptation

    int SCCP     = PACK_TELCO | 0x18;                                     // 0x0418 - SCCP
    int TCAP     = PACK_TELCO | 0x19;                                     // 0x0419 - TCAP
    int MAP      = PACK_TELCO | 0x1A;                                     // 0x041A - MAP
    int CAP      = PACK_TELCO | 0x1B;                                     // 0x041B - CAMEL Application Part
    int INAP     = PACK_TELCO | 0x1C;                                     // 0x041C - INAP
    int ISUP     = PACK_TELCO | 0x1D;                                     // 0x041D - ISUP
    int BICC     = PACK_TELCO | 0x1E;                                     // 0x041E - BICC

    int RESERVED_SS7_1 = PACK_TELCO | 0x2E;                               // Reserved
    int RESERVED_SS7_2 = PACK_TELCO | 0x2F;                               // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Mobile Network Protocols (0x0430-0x044F)
    // ──────────────────────────────────────────────────────────────────────────

    int PFCP     = PACK_TELCO | 0x30;                                     // 0x0430 - Packet Forwarding Control
    int NGAP     = PACK_TELCO | 0x31;                                     // 0x0431 - NG Application Protocol
    int S1AP     = PACK_TELCO | 0x32;                                     // 0x0432 - S1 Application Protocol
    int X2AP     = PACK_TELCO | 0x33;                                     // 0x0433 - X2 Application Protocol
    int NAS_5G   = PACK_TELCO | 0x34;                                     // 0x0434 - 5G NAS
    int NAS_EPS  = PACK_TELCO | 0x35;                                     // 0x0435 - EPS NAS (LTE)

    int RESERVED_MOBILE_1 = PACK_TELCO | 0x4E;                            // Reserved
    int RESERVED_MOBILE_2 = PACK_TELCO | 0x4F;                            // Reserved

    // Reserved: 0x0450-0x04FF

    // ════════════════════════════════════════════════════════════════════════════
    // INDUSTRIAL PACK (0x05xx) - Industrial Protocols (Future)
    // Reserved: 0x0500-0x05FF for SCADA, Modbus, DNP3, etc.
    // ════════════════════════════════════════════════════════════════════════════

 // ════════════════════════════════════════════════════════════════════════════
    // CAPTURE PACK (0x06xx) - Pseudo-headers, Capture Formats, Specialty Links
    // ════════════════════════════════════════════════════════════════════════════

    int PACK_CAPTURE = 0x0600;

    // ──────────────────────────────────────────────────────────────────────────
    // Wireless Capture Headers (0x0601-0x061F)
    // ──────────────────────────────────────────────────────────────────────────

    int IEEE80211  = PACK_CAPTURE | 0x01;                              // 0x0601 - 802.11 wireless
    int RADIOTAP   = PACK_CAPTURE | 0x02;                              // 0x0602 - Radiotap header
    int AVS        = PACK_CAPTURE | 0x03;                              // 0x0603 - AVS WLAN header
    int PRISM      = PACK_CAPTURE | 0x04;                              // 0x0604 - Prism monitor mode
    int PPI        = PACK_CAPTURE | 0x05;                              // 0x0605 - Per-Packet Information

    int RESERVED_WIRELESS_1 = PACK_CAPTURE | 0x1E;                     // Reserved
    int RESERVED_WIRELESS_2 = PACK_CAPTURE | 0x1F;                     // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Linux Capture Headers (0x0620-0x063F)
    // ──────────────────────────────────────────────────────────────────────────

    int NETLINK    = PACK_CAPTURE | 0x20;                              // 0x0620 - Linux Netlink
    int NFLOG      = PACK_CAPTURE | 0x21;                              // 0x0621 - Linux Netfilter log
    int NFQUEUE    = PACK_CAPTURE | 0x22;                              // 0x0622 - Linux Netfilter queue
    int LINUX_CAN  = PACK_CAPTURE | 0x23;                              // 0x0623 - Linux SocketCAN
    int LINUX_USB  = PACK_CAPTURE | 0x24;                              // 0x0624 - Linux USB capture
    int VSOCK      = PACK_CAPTURE | 0x25;                              // 0x0625 - VM Sockets
    int LAPD       = PACK_CAPTURE | 0x26;                              // 0x0626 - Linux LAPD (ISDN)

    int RESERVED_LINUX_1 = PACK_CAPTURE | 0x3E;                        // Reserved
    int RESERVED_LINUX_2 = PACK_CAPTURE | 0x3F;                        // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Bluetooth (0x0640-0x065F)
    // ──────────────────────────────────────────────────────────────────────────

    int BLUETOOTH_ORD = 0x40;
    int BLUETOOTH     = PACK_CAPTURE | BLUETOOTH_ORD;                  // 0x0640 - Bluetooth family
    int BLUETOOTH_HCI = PACK_CAPTURE | 0x41 | (BLUETOOTH_ORD << 16);   // 0x0641 - HCI H4
    int BLUETOOTH_LE  = PACK_CAPTURE | 0x42 | (BLUETOOTH_ORD << 16);   // 0x0642 - BLE Link Layer
    int BLUETOOTH_MON = PACK_CAPTURE | 0x43 | (BLUETOOTH_ORD << 16);   // 0x0643 - BlueZ monitor

    int RESERVED_BT_1 = PACK_CAPTURE | 0x5E;                           // Reserved
    int RESERVED_BT_2 = PACK_CAPTURE | 0x5F;                           // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // Legacy/Specialty Links (0x0660-0x067F)
    // ──────────────────────────────────────────────────────────────────────────

    int FDDI       = PACK_CAPTURE | 0x60;                              // 0x0660 - FDDI
    int TOKEN_RING = PACK_CAPTURE | 0x61;                              // 0x0661 - Token Ring
    int ARCNET     = PACK_CAPTURE | 0x62;                              // 0x0662 - ARCNET
    int ATM        = PACK_CAPTURE | 0x63;                              // 0x0663 - ATM
    int IPOIB      = PACK_CAPTURE | 0x64;                              // 0x0664 - IP over InfiniBand
    int DOCSIS     = PACK_CAPTURE | 0x65;                              // 0x0665 - DOCSIS
    int FRELAY     = PACK_CAPTURE | 0x66;                              // 0x0666 - Frame Relay
    int SLIP       = PACK_CAPTURE | 0x67;                              // 0x0667 - SLIP
    int CHAOS      = PACK_CAPTURE | 0x68;                              // 0x0668 - Chaosnet

    int RESERVED_LEGACY_1 = PACK_CAPTURE | 0x7E;                       // Reserved
    int RESERVED_LEGACY_2 = PACK_CAPTURE | 0x7F;                       // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // IoT/Embedded (0x0680-0x069F)
    // ──────────────────────────────────────────────────────────────────────────

    int IEEE802_15_4     = PACK_CAPTURE | 0x80;                        // 0x0680 - ZigBee/802.15.4
    int IEEE802_15_4_TAP = PACK_CAPTURE | 0x81;                        // 0x0681 - 802.15.4 + TAP
    int AX25             = PACK_CAPTURE | 0x82;                        // 0x0682 - Amateur radio AX.25
    int DECT             = PACK_CAPTURE | 0x83;                        // 0x0683 - DECT

    int RESERVED_IOT_1 = PACK_CAPTURE | 0x9E;                          // Reserved
    int RESERVED_IOT_2 = PACK_CAPTURE | 0x9F;                          // Reserved

    // ──────────────────────────────────────────────────────────────────────────
    // BSD Capture Headers (0x06A0-0x06AF)
    // ──────────────────────────────────────────────────────────────────────────

    int PFLOG      = PACK_CAPTURE | 0xA0;                              // 0x06A0 - OpenBSD pflog
    int PFSYNC     = PACK_CAPTURE | 0xA1;                              // 0x06A1 - OpenBSD pfsync
    int ENC        = PACK_CAPTURE | 0xA2;                              // 0x06A2 - OpenBSD enc
    int LOOPBACK   = PACK_CAPTURE | 0xA3;                              // 0x0210 - BSD Loopback
    int SLL        = PACK_CAPTURE | 0xA4;                              // 0x0211 - Linux Cooked v1
    int SLL2       = PACK_CAPTURE | 0xA5;                              // 0x0212 - Linux Cooked v2

    int RESERVED_BSD_1 = PACK_CAPTURE | 0xAE;                          // Reserved
    int RESERVED_BSD_2 = PACK_CAPTURE | 0xAF;                          // Reserved

    // Reserved: 0x06B0-0x06FF
    // @formatter:on

	// ════════════════════════════════════════════════════════════════════════════
	// Static Helper Methods
	// ════════════════════════════════════════════════════════════════════════════

	/**
	 * Creates meta bits from parent ordinal (for runtime ID construction). Note: Do
	 * NOT use in constant definitions - use inline shifts instead.
	 */
	static int meta(int parentOrdinal) {
		return parentOrdinal << SHIFT_PARENT;
	}

	/**
	 * Creates meta bits from parent ordinal and version (for runtime ID
	 * construction). Note: Do NOT use in constant definitions - use inline shifts
	 * instead.
	 */
	static int meta(int parentOrdinal, int version) {
		return (parentOrdinal << SHIFT_PARENT) | (version << SHIFT_VERSION);
	}

	/**
	 * Extracts the descriptor-compatible ID (lower 16 bits). This is what gets
	 * stored in packet descriptors.
	 */
	static int descriptorId(int id) {
		return id & MASK_DESCRIPTOR;
	}

	/**
	 * Extracts the pack ID.
	 */
	static int packOf(int id) {
		return id & MASK_PACK;
	}

	/**
	 * Extracts the protocol index within the pack.
	 */
	static int indexOf(int id) {
		return id & MASK_INDEX;
	}

	/**
	 * Extracts the parent ordinal from meta bits.
	 */
	static int parentOrdinal(int id) {
		return (id & MASK_PARENT) >>> SHIFT_PARENT;
	}

	/**
	 * Gets the full parent protocol ID.
	 */
	static int parentOf(int id) {
		int parentOrd = parentOrdinal(id);
		return (parentOrd != 0) ? (id & MASK_PACK) | parentOrd : 0;
	}

	/**
	 * Extracts the version from meta bits.
	 */
	static int versionOf(int id) {
		return (id & MASK_VERSION) >>> SHIFT_VERSION;
	}

	/**
	 * Checks if the protocol has a parent family.
	 */
	static boolean hasParent(int id) {
		return (id & MASK_PARENT) != 0;
	}

	/**
	 * Checks if two IDs are in the same family.
	 */
	static boolean sameFamily(int id1, int id2) {
		if (packOf(id1) != packOf(id2))
			return false;

		int parent1 = parentOrdinal(id1);
		int parent2 = parentOrdinal(id2);
		int idx1 = indexOf(id1);
		int idx2 = indexOf(id2);

		return (parent1 == parent2) ||
				(parent1 != 0 && parent1 == idx2) ||
				(parent2 != 0 && parent2 == idx1);
	}

	/**
	 * Checks if the protocol ID represents an in-header option.
	 */
	static boolean isOption(int id) {
		return (id & FLAG_OPTION) != 0;
	}

	/**
	 * Checks if the protocol ID represents an external extension.
	 */
	static boolean isExtension(int id) {
		return (id & FLAG_EXTENSION) != 0;
	}

	/**
	 * Checks if the protocol ID represents a family parent.
	 */
	static boolean isFamily(int id) {
		return !isOption(id) && !isExtension(id) && !hasParent(id);
	}

	/**
	 * Formats a protocol ID for debugging.
	 */
	static String format(int id) {
		String name = nameOf(id);
		int version = versionOf(id);
		if (version != 0) {
			return String.format("0x%08X (%s v%d)", id, name, version);
		}
		return String.format("0x%08X (%s)", id, name);
	}

	/**
	 * Gets the human-readable name for a protocol ID.
	 */
	static String nameOf(int id) {
		int descId = descriptorId(id);
		int pack = packOf(id);
		int idx = indexOf(id);

		// Handle by pack for efficiency
		if (pack == PACK_BUILTIN) {
			return switch (idx) {
			case 0x00 -> "PAYLOAD";
			case 0x01 -> "UNKNOWN";
			case 0x02 -> "PAD";
			default -> "BUILTIN_" + Integer.toHexString(idx);
			};
		}

		if (pack == PACK_INFRA) {
			return switch (idx) {
			case 0x01 -> "STP";
			case 0x02 -> "RSTP";
			case 0x03 -> "MSTP";
			case 0x08 -> "LACP";
			case 0x0C -> "CFM";
			case 0x20 -> "OSPF";
			case 0x24 -> "BGP";
			case 0x28 -> "IS-IS";
			case 0x2C -> "EIGRP";
			case 0x2D -> "RIP";
			case 0x34 -> "VRRP";
			case 0x40 -> "LLDP";
			case 0x41 -> "CDP";
			case 0x60 -> "SNMP";
			case 0x68 -> "NetFlow";
			case 0x70 -> "sFlow";
			case 0x80 -> "NTP";
			case 0x88 -> "PTP";
			default -> "INFRA_" + Integer.toHexString(idx);
			};
		}

		if (pack == PACK_TCPIP) {
			return switch (idx) {
			case 0x01 -> "ETHERNET";
			case 0x02 -> "LLC";
			case 0x03 -> "SNAP";
			case 0x04 -> "ARP";
			case 0x05 -> "RARP";
			case 0x10 -> "LOOPBACK";
			case 0x11 -> "SLL";
			case 0x12 -> "SLL2";
			case 0x18 -> "VLAN";
			case 0x19 -> "802.1Q";
			case 0x1A -> "802.1ad";
			case 0x1C -> "MPLS";
			case 0x20 -> "IP";
			case 0x21 -> "IPv4";
			case 0x22 -> "IPv6";
			case 0x28 -> "ICMP";
			case 0x29 -> "ICMPv4";
			case 0x2A -> "ICMPv6";
			case 0x2B -> "IGMP";
			case 0x30 -> "IPSEC";
			case 0x31 -> "AH";
			case 0x32 -> "ESP";
			case 0x40 -> "TCP";
			case 0x41 -> "UDP";
			case 0x42 -> "SCTP";
			case 0x60 -> "GRE";
			case 0x6C -> "VXLAN";
			case 0x6E -> "GENEVE";
			case 0x70 -> "L2TP";
			case 0x80 -> "PPP";
			case 0x81 -> "PPPoE";
			default -> "TCPIP_" + Integer.toHexString(idx);
			};
		}

		if (pack == PACK_WEB) {
			return switch (idx) {
			case 0x01 -> "TLS";
			case 0x07 -> "TLS1.3";
			case 0x10 -> "HTTP";
			case 0x13 -> "HTTP/1.1";
			case 0x14 -> "HTTP/2";
			case 0x15 -> "HTTP/3";
			case 0x20 -> "QUIC";
			case 0x30 -> "DNS";
			case 0x40 -> "DHCP";
			case 0x50 -> "SMTP";
			case 0x60 -> "SSH";
			case 0x65 -> "FTP";
			case 0x70 -> "RTP";
			case 0x78 -> "SIP";
			case 0x80 -> "WebSocket";
			case 0x90 -> "LDAP";
			default -> "WEB_" + Integer.toHexString(idx);
			};
		}

		if (pack == PACK_TELCO) {
			return switch (idx) {
			case 0x01 -> "GTP";
			case 0x10 -> "M3UA";
			case 0x18 -> "SCCP";
			case 0x30 -> "PFCP";
			default -> "TELCO_" + Integer.toHexString(idx);
			};
		}

		return "UNKNOWN_" + Integer.toHexString(descId);
	}
}