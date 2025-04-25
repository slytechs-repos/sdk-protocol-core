/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
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
package com.slytechs.jnet.protocol.api.core;

import static com.slytechs.jnet.protocol.api.pack.ProtocolPackTable.*;

import java.util.EnumSet;
import java.util.Set;
import java.util.function.IntFunction;
import java.util.function.Supplier;

import com.slytechs.jnet.platform.api.util.format.BitFormat;
import com.slytechs.jnet.protocol.api.common.Frame;
import com.slytechs.jnet.protocol.api.common.Header;
import com.slytechs.jnet.protocol.api.common.HeaderInfo;
import com.slytechs.jnet.protocol.api.common.HeaderOptionInfo;
import com.slytechs.jnet.protocol.api.common.HeaderSupplier;
import com.slytechs.jnet.protocol.api.common.Other;
import com.slytechs.jnet.protocol.api.common.Payload;
import com.slytechs.jnet.protocol.api.pack.PackId;
import com.slytechs.jnet.protocol.api.pack.ProtocolPackTable;
import com.slytechs.jnet.protocol.tcpip.arp.Arp;
import com.slytechs.jnet.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp4;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp4Echo;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp6;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp6Echo;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp6IdNsOptions;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp6Mlr2;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp6Mlr2RecordType;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp6NeighborAdvertisement;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp6NeighborSolicitation;
import com.slytechs.jnet.protocol.tcpip.ip.Ip4;
import com.slytechs.jnet.protocol.tcpip.ip.Ip4IdOptions;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6AuthHeaderExtension;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6DestinationExtension;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6EcapsSecPayloadExtension;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6ExtensionHeader;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6FragmentExtension;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6HopByHopExtension;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6HostIdentityExtension;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6IdOption;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6RoutingExtension;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6Shim6Extension;
import com.slytechs.jnet.protocol.tcpip.ipx.Ipx;
import com.slytechs.jnet.protocol.tcpip.ppp.Ppp;
import com.slytechs.jnet.protocol.tcpip.tcp.Tcp;
import com.slytechs.jnet.protocol.tcpip.tcp.TcpOptionId;
import com.slytechs.jnet.protocol.tcpip.udp.Udp;

/**
 * Core protocol pack. Table of all protocols included in the core protocol
 * pack.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public enum CoreId implements HeaderInfo, PackId {

	/** The payload. */
	PACK(),

	/** The payload. */
	PAYLOAD(Payload::new),

	/** The frame. */
	FRAME(Frame::new),

	/** The ether. */
	ETHER(Ethernet::new),

	/** The ip. */
	IP(Ip4::new),

	/** The I pv 4. */
	IPv4("IPv4", Ip4::new, Ip4IdOptions::values),

	/** The I pv 6. */
	IPv6(Ip6::new),

	/** The udp. */
	UDP(Udp::new),

	/** The tcp. */
	TCP("TCP", Tcp::new, TcpOptionId::values),

	/** The sctp. */
	SCTP,

	/** The llc. */
	LLC,

	/** The snap. */
	SNAP,

	/** The vlan. */
	VLAN,

	/** The mpls. */
	MPLS,

	/** The ipx. */
	IPX(Ipx::new),

	/** The gre. */
	GRE,

	/** The ppp. */
	PPP(Ppp::new),

	/** The fddi. */
	FDDI,

	/** The atm. */
	ATM,

	/** The arp. */
	ARP(Arp::new),

	/** The stp. */
	STP,

	/** The dhcp. */
	DHCP,

	/** The DHC pv 4. */
	DHCPv4,

	/** The DHC pv 6. */
	DHCPv6,

	/** The igmp. */
	IGMP,

	ICMP(Icmp::new),
	ICMPv4(Icmp4::new),
	ICMPv6(Icmp6::new),
	ICMPv4_ECHO(Icmp4Echo::new),
	ICMPv4_ECHO_REQUEST("ICMPv4:ECHO:REQ", Icmp4Echo.Request::new),
	ICMPv4_ECHO_REPLY("ICMPv4:ECHO:REP", Icmp4Echo.Reply::new),
	ICMPv4_UNREACHABLE("ICMPv4:UNREACH", Icmp4::new),
	ICMPv4_SOURCE_QUENCH("ICMPv4:SRC_Q", Icmp4::new),
	ICMPv4_REDIRECT("ICMPv4:REDIRECT", Icmp4::new),
	ICMPv4_TIME_EXEEDED("ICMPv4:TIME_EXP", Icmp4::new),
	ICMPv4_PARAMETER("ICMPv4:PARAM", Icmp4::new),
	ICMPv4_TIMESTAMP_REQUEST("ICMPv4:TS:REQ", Icmp4::new),
	ICMPv4_TIMESTAMP_REPLY("ICMPv4:TS:REP", Icmp4::new),

	ICMPv6_ECHO(Icmp6Echo::new),
	ICMPv6_ECHO_REQUEST("ICMPv6:ECHO:REQ", Icmp6Echo.Request::new),
	ICMPv6_ECHO_REPLY("ICMPv6:ECHO:REP", Icmp6Echo.Reply::new),
	ICMPv6_UNREACHABLE("ICMPv6:UNREACH", Icmp6::new),
	ICMPv6_PACKET_TOO_BIG("ICMPv6:TOO_BIG", Icmp6::new),
	ICMPv6_TIME_EXEEDED("ICMPv6:TIME_EXP", Icmp6::new),
	ICMPv6_PARAMETER("ICMPv6:PARAM", Icmp6::new),

	ICMPv6_MULTICAST_LISTENER_QUERY("ICMPv6:MLQ", Icmp6::new),
	ICMPv6_MULTICAST_LISTENER_REPORTv1("ICMPv6:MLRv1", Icmp6::new),
	ICMPv6_MULTICAST_LISTENER_DONE("ICMPv6:MLD", Icmp6::new),
	ICMPv6_ROUTER_SOLICITATION("ICMPv6:RS", Icmp6::new),
	ICMPv6_ROUTER_ADVERTISEMENT("ICMPv6:RA", Icmp6::new),
	ICMPv6_NEIGHBOR_SOLICITATION("ICMPv6:NS", Icmp6NeighborSolicitation::new, Icmp6IdNsOptions::values),
	ICMPv6_NEIGHBOR_ADVERTISEMENT("ICMPv6:NA", Icmp6NeighborAdvertisement::new),
	ICMPv6_REDIRECT("ICMPv6:REDIRECT", Icmp6::new),
	ICMPv6_ROUTER_NUMBER("ICMPv6:RN", Icmp6::new),
	ICMPv6_NODE_INFO_QUERY("ICMPv6:NIQ", Icmp6::new),
	ICMPv6_NODE_INFO_RESPONSE("ICMPv6:NIR", Icmp6::new),
	ICMPv6_INVERSE_NEIGHBOR_SOLICITATION("ICMPv6:INS", Icmp6::new),
	ICMPv6_MULTICAST_LISTENER_REPORTv2("ICMPv6:MLRv2", Icmp6Mlr2::new, Icmp6Mlr2RecordType::values),
	ICMPv6_HOME_AGENT_REQUEST("ICMPv6:THA:REQ", Icmp6::new),
	ICMPv6_HOME_AGENT_REPLY("ICMPv6:THA:REP", Icmp6::new),
	ICMPv6_MOBILE_PREFIX_SOLICITATION("ICMPv6:MPS", Icmp6::new),
	ICMPv6_MOBILE_PREFIX_ADVERTISEMENT("ICMPv6:MPA", Icmp6::new),
	ICMPv6_FMIPv6_MESSAGE("ICMPv6:FMIPv6", Icmp6::new),
	ICMPv6_RPL_CONTROL_MESSAGE("ICMPv6:RPL:CM", Icmp6::new),
	ICMPv6_ILNPv6_LOCATOR_UPDATE_MESSAGE("ICMPv6:ILNPv6:LUM", Icmp6::new),
	ICMPv6_DUPLICATE_ADDRESS_REQUEST("ICMPv6:DAR", Icmp6::new),
	ICMPv6_DUPLICATE_ADDRESS_CONFIRMATION("ICMPv6:DAC", Icmp6::new),
	ICMPv6_MPL_CONTROL_MESSAGE("ICMPv6:NPL:CM", Icmp6::new),
	ICMPv6_EXTENDED_ECHO_REQUEST("ICMPv6:EXTECHO:REQ", Icmp6::new),
	ICMPv6_EXTENDED_ECHO_REPLY("ICMPv6:EXTECHO:REP", Icmp6::new),

	IPv6_EXTENSION(Ip6ExtensionHeader::new),
	IPv6_EXT_HOP_BY_HOP_OPTIONS("IPv6:HOP", Ip6HopByHopExtension::new, Ip6IdOption::values),
	IPv6_EXT_ROUTING("IPv6:ROUTING", Ip6RoutingExtension::new),
	IPv6_EXT_FRAGMENT("IPv6:FRAGMENT", Ip6FragmentExtension::new),
	IPv6_EXT_AUTH_HEADER("IPv6:AH", Ip6AuthHeaderExtension::new),
	IPv6_EXT_ECAPS_SEC_PAYLOAD("IPv6:ESP", Ip6EcapsSecPayloadExtension::new),
	IPv6_EXT_DEST_OPTIONS("IPv6:DEST", Ip6DestinationExtension::new),
	IPv6_EXT_MOBILITY("IPv6:MOBILITY", Ip6DestinationExtension::new),
	IPv6_EXT_HOST_IDENTITY("IPv6:HID", Ip6HostIdentityExtension::new),
	IPv6_EXT_SHIMv6("IPv6:SHIMv6", Ip6Shim6Extension::new),
	;

	/** The Constant CORE_CLASS_BIT_FORMAT. */
	public static final BitFormat CORE_CLASS_BIT_FORMAT = new BitFormat("tDhcCxiI64", '.');

	/** The Constant CORE_CLASS_BIT_STRING. */
	public static final IntFunction<String> CORE_CLASS_BIT_STRING = v -> "0b%5s"
			.formatted(Integer.toBinaryString(v))
			.replace(' ', '0');

	// @formatter:off
	/** The Constant CORE_CLASS_V4. */
	public static final int CORE_CLASS_V4     = 1 << (0 + PACK_SHIFT_CLASSBITMASK);
	
	/** The Constant CORE_CLASS_V6. */
	public static final int CORE_CLASS_V6     = 1 << (1 + PACK_SHIFT_CLASSBITMASK);
	
	/** The Constant CORE_CLASS_IP. */
	public static final int CORE_CLASS_IP     = 1 << (2 + PACK_SHIFT_CLASSBITMASK);
	
	/** The Constant CORE_CLASS_IP_OPT. */
	public static final int CORE_CLASS_IP_OPTION = 1 << (3 + PACK_SHIFT_CLASSBITMASK);
	
	/** The Constant CORE_CLASS_IP_EXTENSION. */
	public static final int CORE_CLASS_IPv6_EXTENSION = 1 << (4 + PACK_SHIFT_CLASSBITMASK) | CORE_CLASS_V6;
	
	/** The Constant CORE_CLASS_ICMP. */
	public static final int CORE_CLASS_ICMP   = 1 << (5 + PACK_SHIFT_CLASSBITMASK);
	
	/** The Constant CORE_CLASS_ICMP_OPT. */
	public static final int CORE_CLASS_ICMP_OPT = 1 << (6 + PACK_SHIFT_CLASSBITMASK);

	/** The Constant CORE_CLASS_ICMP_ECHO. */
	public static final int CORE_CLASS_ICMP_ECHO   = 1 << (7 + PACK_SHIFT_CLASSBITMASK);
	
	/** The Constant CORE_CLASS_DHCP. */
	public static final int CORE_CLASS_DHCP   = 1 << (8 + PACK_SHIFT_CLASSBITMASK);
	
	/** The Constant CORE_CLASS_TCP_OPT. */
	public static final int CORE_CLASS_TCP_OPT = 1 << (9 + PACK_SHIFT_CLASSBITMASK);
	
	/** The Constant CORE_CLASS_IPv4. */
	public static final int CORE_CLASS_IPv4   = CORE_CLASS_IP | CORE_CLASS_V4;
	
	/** The Constant CORE_CLASS_IPv4_OPT. */
	public static final int CORE_CLASS_IPv4_OPTION   = CORE_CLASS_IP_OPTION | CORE_CLASS_V4 ;
	
	/** The Constant CORE_CLASS_IPv6. */
	public static final int CORE_CLASS_IPv6   = CORE_CLASS_IP | CORE_CLASS_V6;
	
	/** The Constant CORE_CLASS_IPv6_OPT. */
	public static final int CORE_CLASS_IPv6_OPTION   = CORE_CLASS_IP_OPTION | CORE_CLASS_V6;
	
	/** The Constant CORE_CLASS_ICMPv4. */
	public static final int CORE_CLASS_ICMPv4 = CORE_CLASS_ICMP | CORE_CLASS_V4;
	
	/** The Constant CORE_CLASS_ICMPv6. */
	public static final int CORE_CLASS_ICMPv6 = CORE_CLASS_ICMP | CORE_CLASS_V6;
	
	/** The Constant CORE_CLASS_DHCPv4. */
	public static final int CORE_CLASS_DHCPv4 = CORE_CLASS_DHCP | CORE_CLASS_V4;
	
	/** The Constant CORE_CLASS_DHCPv6. */
	public static final int CORE_CLASS_DHCPv6 = CORE_CLASS_DHCP | CORE_CLASS_V6;
	// @formatter:on

	// @formatter:off
	/** The Constant CORE_ID_PACK. */
	public static final int CORE_ID_PACK     = 0  | PACK_ID_CORE;
	
	/** The Constant CORE_ID_PAYLOAD. */
	public static final int CORE_ID_PAYLOAD  = 1  | PACK_ID_CORE;
	
	/** The Constant CORE_ID_FRAME. */
	public static final int CORE_ID_FRAME    = 2  | PACK_ID_CORE;
	
	/** The Constant CORE_ID_ETHER. */
	public static final int CORE_ID_ETHER    = 3  | PACK_ID_CORE;
	
	/** The Constant CORE_ID_IP. */
	public static final int CORE_ID_IP       = ID_ORDINAL_CLASS | PACK_ID_CORE | CORE_CLASS_IP;

	/** The Constant CORE_ID_IPv4. */
	public static final int CORE_ID_IPv4     = 5 | PACK_ID_CORE | CORE_CLASS_IPv4;
	
	/** The Constant CORE_ID_IPv6. */
	public static final int CORE_ID_IPv6     = 6 | PACK_ID_CORE | CORE_CLASS_IPv6;
	
	/** The Constant CORE_ID_UDP. */
	public static final int CORE_ID_UDP      = 7  | PACK_ID_CORE;
	
	/** The Constant CORE_ID_TCP. */
	public static final int CORE_ID_TCP      = 8  | PACK_ID_CORE;
	
	/** The Constant CORE_ID_SCTP. */
	public static final int CORE_ID_SCTP     = 9  | PACK_ID_CORE;
	
	/** The Constant CORE_ID_LLC. */
	public static final int CORE_ID_LLC      = 10 | PACK_ID_CORE;
	
	/** The Constant CORE_ID_SNAP. */
	public static final int CORE_ID_SNAP     = 11 | PACK_ID_CORE;
	
	/** The Constant CORE_ID_VLAN. */
	public static final int CORE_ID_VLAN     = 12 | PACK_ID_CORE;
	
	/** The Constant CORE_ID_MPLS. */
	public static final int CORE_ID_MPLS     = 13 | PACK_ID_CORE;
	
	/** The Constant CORE_ID_IPX. */
	public static final int CORE_ID_IPX      = 14 | PACK_ID_CORE;
	
	/** The Constant CORE_ID_GRE. */
	public static final int CORE_ID_GRE      = 15 | PACK_ID_CORE;
	
	/** The Constant CORE_ID_PPP. */
	public static final int CORE_ID_PPP      = 16 | PACK_ID_CORE;
	
	/** The Constant CORE_ID_FDDI. */
	public static final int CORE_ID_FDDI     = 17 | PACK_ID_CORE;
	
	/** The Constant CORE_ID_ATM. */
	public static final int CORE_ID_ATM      = 18 | PACK_ID_CORE;
	
	/** The Constant CORE_ID_ARP. */
	public static final int CORE_ID_ARP      = 19 | PACK_ID_CORE;
	
	/** The Constant CORE_ID_STP. */
	public static final int CORE_ID_STP      = 20 | PACK_ID_CORE;
	
	/** The Constant CORE_ID_DHCP. */
	public static final int CORE_ID_DHCP     = ID_ORDINAL_CLASS | PACK_ID_CORE | CORE_CLASS_DHCP;
	
	/** The Constant CORE_ID_DHCPv4. */
	public static final int CORE_ID_DHCPv4   = 22 | PACK_ID_CORE | CORE_CLASS_DHCPv4;
	
	/** The Constant CORE_ID_DHCPv6. */
	public static final int CORE_ID_DHCPv6   = 23 | PACK_ID_CORE | CORE_CLASS_DHCPv6;
	
	/** The Constant CORE_ID_IGMP. */
	public static final int CORE_ID_IGMP     = 24 | PACK_ID_CORE;
	
	/** The Constant CORE_ID_ICMP. */
	public static final int CORE_ID_ICMP     = ID_ORDINAL_CLASS | PACK_ID_CORE | CORE_CLASS_ICMP;
	
	/** The Constant CORE_ID_ICMPv4. */
	public static final int CORE_ID_ICMPv4   = 26 | PACK_ID_CORE | CORE_CLASS_ICMPv4 |  CORE_CLASS_ICMP_ECHO;
	
	/** The Constant CORE_ID_ICMPv6. */
	public static final int CORE_ID_ICMPv6   = 27 | PACK_ID_CORE | CORE_CLASS_ICMPv6; 
	
	public static final int CORE_ID_ICMPv4_ECHO                           = ID_ORDINAL_CLASS | PACK_ID_CORE | CORE_CLASS_ICMPv4 | CORE_CLASS_ICMP_ECHO;
	public static final int CORE_ID_ICMPv4_ECHO_REQUEST                   = 29 | PACK_ID_CORE | CORE_CLASS_ICMPv4 | CORE_CLASS_ICMP_ECHO;
	public static final int CORE_ID_ICMPv4_ECHO_REPLY                     = 30 | PACK_ID_CORE | CORE_CLASS_ICMPv4 | CORE_CLASS_ICMP_ECHO;
	public static final int CORE_ID_ICMPv4_UNREACHABLE                    = 31 | PACK_ID_CORE | CORE_CLASS_ICMPv4;
	public static final int CORE_ID_ICMPv4_SOURCE_QUENCH                  = 32 | PACK_ID_CORE | CORE_CLASS_ICMPv4;
	public static final int CORE_ID_ICMPv4_REDIRECT                       = 33 | PACK_ID_CORE | CORE_CLASS_ICMPv4;
	public static final int CORE_ID_ICMPv4_TIME_EXEEDED                   = 34 | PACK_ID_CORE | CORE_CLASS_ICMPv4;
	public static final int CORE_ID_ICMPv4_PARAMETER                      = 35 | PACK_ID_CORE | CORE_CLASS_ICMPv4;
	public static final int CORE_ID_ICMPv4_TIMESTAMP_REQUEST              = 36 | PACK_ID_CORE | CORE_CLASS_ICMPv4;
	public static final int CORE_ID_ICMPv4_TIMESTAMP_REPLY                = 37 | PACK_ID_CORE | CORE_CLASS_ICMPv4;

	public static final int CORE_ID_ICMPv6_ECHO                           = ID_ORDINAL_CLASS | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_ECHO_REQUEST                   = 39 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_ECHO_REPLY                     = 40 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_UNREACHABLE                    = 41 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_PACKET_TOO_BIG                 = 42 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_TIME_EXEEDED                   = 43 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_PARAMETER                      = 44 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	
	public static final int CORE_ID_ICMPv6_MULTICAST_LISTENER_QUERY       = 45 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_MULTICAST_LISTENER_REPORTv1    = 46 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_MULTICAST_LISTENER_DONE        = 47 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_ROUTER_SOLICITATION            = 48 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_ROUTER_ADVERTISEMENT           = 49 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_NEIGHBOR_SOLICITATION          = 50 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_NEIGHBOR_ADVERTISEMENT         = 51 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_REDIRECT                       = 52 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_ROUTER_NUMBER                  = 53 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	
	public static final int CORE_ID_ICMPv6_NODE_INFO_QUERY                = 54 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_NODE_INFO_RESPONSE             = 55 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_INVERSE_NEIGHBOR_SOLICITATION  = 56 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_MULTICAST_LISTENER_REPORTv2    = 57 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_HOME_AGENT_REQUEST             = 58 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_HOME_AGENT_REPLY               = 59 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_MOBILE_PREFIX_SOLICITATION     = 60 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_MOBILE_PREFIX_ADVERTISEMENT    = 61 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_FMIPv6_MESSAGE                 = 62 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_RPL_CONTROL_MESSAGE            = 63 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_ILNPv6_LOCATOR_UPDATE_MESSAGE  = 64 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_DUPLICATE_ADDRESS_REQUEST      = 65 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_DUPLICATE_ADDRESS_CONFIRMATION = 66 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_MPL_CONTROL_MESSAGE            = 67 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_EXTENDED_ECHO_REQUEST          = 68 | PACK_ID_CORE | CORE_CLASS_ICMPv6;
	public static final int CORE_ID_ICMPv6_EXTENDED_ECHO_REPLY            = 69 | PACK_ID_CORE | CORE_CLASS_ICMPv6;

	public static final int CORE_ID_IPv6_EXTENSION                        = ID_ORDINAL_CLASS | PACK_ID_CORE | CORE_CLASS_IPv6_EXTENSION;
	public static final int CORE_ID_IPv6_EXT_HOP_BY_HOP_OPTIONS           = 71 | PACK_ID_CORE | CORE_CLASS_IPv6_EXTENSION;
	public static final int CORE_ID_IPv6_EXT_ROUTING                      = 72 | PACK_ID_CORE | CORE_CLASS_IPv6_EXTENSION;
	public static final int CORE_ID_IPv6_EXT_FRAGMENT                     = 73 | PACK_ID_CORE | CORE_CLASS_IPv6_EXTENSION;
	public static final int CORE_ID_IPv6_EXT_AUTH_HEADER                  = 74 | PACK_ID_CORE | CORE_CLASS_IPv6_EXTENSION;
	public static final int CORE_ID_IPv6_EXT_ENCAPS_SEC_PAYLOAD           = 75 | PACK_ID_CORE | CORE_CLASS_IPv6_EXTENSION;
	public static final int CORE_ID_IPv6_EXT_DEST_OPTIONS                 = 76 | PACK_ID_CORE | CORE_CLASS_IPv6_EXTENSION;
	public static final int CORE_ID_IPv6_EXT_MOBILITY                     = 77 | PACK_ID_CORE | CORE_CLASS_IPv6_EXTENSION;
	public static final int CORE_ID_IPv6_EXT_HOST_IDENTITY                = 78 | PACK_ID_CORE | CORE_CLASS_IPv6_EXTENSION;
	public static final int CORE_ID_IPv6_EXT_SHIMv6                       = 79 | PACK_ID_CORE | CORE_CLASS_IPv6_EXTENSION;
	
	// @formatter:on

	/**
	 * To string id.
	 *
	 * @param id the id
	 * @return the core header info
	 */
	public static CoreId toStringId(int id) {
		return values()[PackId.decodeIdOrdinal(id)];
	}

	/**
	 * To set from bitmask.
	 *
	 * @param bitmask the bitmask
	 * @return the sets the
	 */
	public static Set<CoreId> toSetFromBitmask(long bitmask) {
		var set = EnumSet.noneOf(CoreId.class);

		for (CoreId e : values()) {
			if (PackId.bitmaskCheck(bitmask & 0x0F, e.id))
				set.add(e);
		}

		return set;
	}

	/**
	 * Value of.
	 *
	 * @param id the id
	 * @return the core header info
	 */
	public static CoreId valueOf(int id) {
		int pack = PackId.decodePackId(id);
		if (pack != ProtocolPackTable.PACK_ID_CORE)
			return null;

		int ordinal = PackId.decodeIdOrdinal(id);
		return values()[ordinal];
	}

	/** The id. */
	private final int id;

	/** The supplier. */
	private final HeaderSupplier supplier;

	/** The extensions supplier. */
	private final Supplier<HeaderOptionInfo[]> extensionsSupplier;

	/** The abbr. */
	private final String abbr;

	/**
	 * Instantiates a new core header info.
	 */
	CoreId() {
		this.id = PackId.encodeId(ProtocolPackTable.CORE, ordinal());
		this.supplier = Other::new;
		this.extensionsSupplier = () -> HeaderOptionInfo.EMPTY_ARRAY;
		this.abbr = null;
	}

	/**
	 * Instantiates a new core header info.
	 *
	 * @param supplier the supplier
	 */
	CoreId(HeaderSupplier supplier) {
		this.id = PackId.encodeId(ProtocolPackTable.CORE, ordinal());
		this.supplier = supplier;
		this.extensionsSupplier = () -> HeaderOptionInfo.EMPTY_ARRAY;
		this.abbr = null;
	}

	/**
	 * Instantiates a new core header info.
	 *
	 * @param supplier the supplier
	 */
	CoreId(String abbr, HeaderSupplier supplier) {
		this.id = PackId.encodeId(ProtocolPackTable.CORE, ordinal());
		this.supplier = supplier;
		this.extensionsSupplier = () -> HeaderOptionInfo.EMPTY_ARRAY;
		this.abbr = abbr;
	}

	/**
	 * Instantiates a new core header info.
	 *
	 * @param supplier           the supplier
	 * @param extensionsSupplier the extensions supplier
	 */
	CoreId(String abbr, HeaderSupplier supplier, Supplier<HeaderOptionInfo[]> extensionsSupplier) {
		this.id = PackId.encodeId(ProtocolPackTable.CORE, ordinal());
		this.supplier = supplier;
		this.extensionsSupplier = extensionsSupplier;
		this.abbr = abbr;
	}

	/**
	 * Gets the extension infos.
	 *
	 * @return the extension infos
	 * @see com.slytechs.jnet.protocol.api.common.HeaderInfo#getOptionInfos()
	 */
	@Override
	public HeaderOptionInfo[] getOptionInfos() {
		return extensionsSupplier.get();
	}

	/**
	 * Gets the header id.
	 *
	 * @return the header id
	 * @see com.slytechs.jnet.protocol.api.common.HeaderInfo#id()
	 */
	@Override
	public int id() {
		return id;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.common.HeaderInfo#abbr()
	 */
	@Override
	public String abbr() {
		return (abbr == null)
				? name()
				: this.abbr;
	}

	/**
	 * New header instance.
	 *
	 * @return the header
	 * @see com.slytechs.jnet.protocol.api.common.HeaderSupplier#newHeaderInstance()
	 */
	@Override
	public Header newHeaderInstance() {
		return (supplier != null)
				? supplier.newHeaderInstance()
				: null;
	}

}
