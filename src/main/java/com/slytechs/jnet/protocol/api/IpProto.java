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
 * IP Protocol field values (wire format).
 * 
 * <p>
 * These are the values found in the IPv4 Protocol field (byte 9) and the IPv6
 * Next Header field. They identify the next protocol encapsulated in the IP
 * datagram.
 * </p>
 * 
 * <p>
 * Note: These are wire-level values, not internal protocol IDs. Use
 * {@link ProtocolId} for internal identification.
 * </p>
 * 
 * <h2>Usage</h2>
 * <pre>{@code
 * import static com.slytechs.jnet.protocol.api.IpProto.*;
 * 
 * int protocol = ipHeader.get(9) & 0xFF;
 * switch (protocol) {
 *     case TCP    -> dissectTcp(buffer, offset);
 *     case UDP    -> dissectUdp(buffer, offset);
 *     case ICMPv4 -> dissectIcmp(buffer, offset);
 * }
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see <a href="https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml">
 *      IANA Protocol Numbers</a>
 */
public interface IpProto {

    // ════════════════════════════════════════════════════════════════════════
    // IPv6 Extension Headers (also used as Next Header values)
    // ════════════════════════════════════════════════════════════════════════

    int HOPOPT = 0;    // IPv6 Hop-by-Hop Option
    int IPv6   = 41;   // IPv6 encapsulation
    int ROUTE  = 43;   // Routing Header for IPv6
    int FRAG   = 44;   // Fragment Header for IPv6
    int ESP    = 50;   // Encapsulating Security Payload
    int AH     = 51;   // Authentication Header
    int ICMPV6 = 58;   // ICMP for IPv6
    int NONEXT = 59;   // No Next Header for IPv6
    int DSTOPT = 60;   // Destination Options for IPv6
    int MH     = 135;  // Mobility Header
    int HIP    = 139;  // Host Identity Protocol
    int SHIM6  = 140;  // Shim6 Protocol

    // ════════════════════════════════════════════════════════════════════════
    // Core Protocols
    // ════════════════════════════════════════════════════════════════════════

    int ICMPV4 = 1;    // Internet Control Message Protocol (v4)
    int IGMP   = 2;    // Internet Group Management Protocol
    int IPIP   = 4;    // IPv4 encapsulation (IP-in-IP)
    int TCP    = 6;    // Transmission Control Protocol
    int EGP    = 8;    // Exterior Gateway Protocol
    int UDP    = 17;   // User Datagram Protocol
    int DCCP   = 33;   // Datagram Congestion Control Protocol
    int GRE    = 47;   // Generic Routing Encapsulation
    int OSPF   = 89;   // Open Shortest Path First
    int IPCOMP = 108;  // IP Payload Compression Protocol
    int SCTP   = 132;  // Stream Control Transmission Protocol
    int UDPLITE= 136;  // UDP-Lite

    // ════════════════════════════════════════════════════════════════════════
    // Other Protocols
    // ════════════════════════════════════════════════════════════════════════

    int ST     = 5;    // Stream
    int CBT    = 7;    // CBT
    int IGP    = 9;    // Interior Gateway Protocol
    int PUP    = 12;   // PARC Universal Packet
    int ARGUS  = 13;   // ARGUS
    int EMCON  = 14;   // EMCON
    int XNET   = 15;   // Cross Net Debugger
    int CHAOS  = 16;   // Chaos
    int MUX    = 18;   // Multiplexing
    int HMP    = 20;   // Host Monitoring
    int PRM    = 21;   // Packet Radio Measurement
    int TRUNK1 = 23;   // Trunk-1
    int TRUNK2 = 24;   // Trunk-2
    int LEAF1  = 25;   // Leaf-1
    int LEAF2  = 26;   // Leaf-2
    int RDP    = 27;   // Reliable Data Protocol
    int IRTP   = 28;   // Internet Reliable Transaction
    int NETBLT = 30;   // Bulk Data Transfer Protocol
    int MFE    = 31;   // MFE Network Services Protocol
    int MERIT  = 32;   // MERIT Internodal Protocol
    int IDPR   = 35;   // Inter-Domain Policy Routing
    int XTP    = 36;   // XTP
    int DDP    = 37;   // Datagram Delivery Protocol
    int IDRP   = 45;   // Inter-Domain Routing Protocol
    int RSVP   = 46;   // Reservation Protocol
    int NARP   = 54;   // NBMA Address Resolution Protocol
    int MOBILE = 55;   // IP Mobility
    int SKIP   = 57;   // SKIP
    int IGRP   = 88;   // IGRP
    int EIGRP  = 88;   // EIGRP (same as IGRP)
    int PIM    = 103;  // Protocol Independent Multicast
    int VRRP   = 112;  // Virtual Router Redundancy Protocol
    int L2TP   = 115;  // Layer 2 Tunneling Protocol
    int ISIS   = 124;  // IS-IS over IPv4
    int FC     = 133;  // Fibre Channel
    int MANET  = 138;  // MANET Protocols
    int WESP   = 141;  // Wrapped ESP
    int ROHC   = 142;  // Robust Header Compression
    int ETHERNET = 143; // Ethernet (experimental)

    // ════════════════════════════════════════════════════════════════════════
    // Reserved/Experimental
    // ════════════════════════════════════════════════════════════════════════

    int RAW    = 255;  // Raw IP packets

    // ════════════════════════════════════════════════════════════════════════
    // Helper Methods
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Checks if the protocol number is an IPv6 extension header.
     * 
     * @param proto the IP protocol number
     * @return true if this is an IPv6 extension header type
     */
    static boolean isIPv6Extension(int proto) {
        return switch (proto) {
            case HOPOPT, ROUTE, FRAG, DSTOPT, MH, HIP, SHIM6 -> true;
            default -> false;
        };
    }

    /**
     * Checks if the protocol number terminates extension header processing.
     * 
     * @param proto the IP protocol number (Next Header value)
     * @return true if this is a terminal protocol (not an extension)
     */
    static boolean isTerminal(int proto) {
        return switch (proto) {
            case HOPOPT, ROUTE, FRAG, DSTOPT, MH, HIP, SHIM6 -> false;
            case ESP, AH -> false;  // Technically extensions but handled specially
            default -> true;
        };
    }

    /**
     * Gets the name of an IP protocol for debugging.
     * 
     * @param proto the IP protocol number
     * @return human-readable name
     */
    static String nameOf(int proto) {
        return switch (proto) {
            case HOPOPT -> "HOPOPT";
            case ICMPV4 -> "ICMP";
            case IGMP   -> "IGMP";
            case IPIP   -> "IPIP";
            case TCP    -> "TCP";
            case UDP    -> "UDP";
            case IPv6   -> "IPv6";
            case ROUTE  -> "ROUTE";
            case FRAG   -> "FRAG";
            case GRE    -> "GRE";
            case ESP    -> "ESP";
            case AH     -> "AH";
            case ICMPV6 -> "ICMPv6";
            case NONEXT -> "NONEXT";
            case DSTOPT -> "DSTOPT";
            case OSPF   -> "OSPF";
            case SCTP   -> "SCTP";
            case VRRP   -> "VRRP";
            case L2TP   -> "L2TP";
            default -> String.format("%d", proto);
        };
    }
}