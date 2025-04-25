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
package com.slytechs.jnet.protocol.tcpip.impl;

import java.util.HashMap;
import java.util.Map;

import com.slytechs.jnet.protocol.api.meta.MetaValue.ValueResolver;
import com.slytechs.jnet.protocol.api.meta.spi.ValueResolverService;
import com.slytechs.jnet.protocol.tcpip.arp.ArpHardwareType;
import com.slytechs.jnet.protocol.tcpip.arp.ArpOp;
import com.slytechs.jnet.protocol.tcpip.ethernet.EtherType;
import com.slytechs.jnet.protocol.tcpip.ethernet.impl.MacOuiAssignments;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp4Code;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp4Type;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp6Mlr2RecordType;
import com.slytechs.jnet.protocol.tcpip.icmp.Icmp6Type;
import com.slytechs.jnet.protocol.tcpip.ip.Ip4IdOptions;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6IdOption;
import com.slytechs.jnet.protocol.tcpip.ip.IpType;
import com.slytechs.jnet.protocol.tcpip.ipx.IpxType;
import com.slytechs.jnet.protocol.tcpip.ppp.PppProtocol;
import com.slytechs.jnet.protocol.tcpip.tcp.TcpFlag;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class TcpipResolverService implements ValueResolverService {

	/**
	 * 
	 */
	public TcpipResolverService() {}

	/**
	 * @see com.slytechs.jnet.protocol.api.meta.spi.ValueResolverService#getResolvers()
	 */
	@Override
	public Map<String, ValueResolver> getResolvers() {
		var map = new HashMap<String, ValueResolver>();

		map.put("ETHER_TYPE", EtherType::resolve);
		map.put("IP_TYPE", IpType::resolve);
		map.put("IPv4_OPT_TYPE", Ip4IdOptions::resolve);
		map.put("IPv6_OPT_TYPE", Ip6IdOption::resolve);
		map.put("ARP_OP", ArpOp::resolve);
		map.put("ARP_HWTYPE", ArpHardwareType::resolve);
		map.put("ETHER_MAC_OUI_NAME", MacOuiAssignments::resolveMacOuiName);
		map.put("ETHER_MAC_OUI_NAME_PREFIXED", MacOuiAssignments::formatMacPrefixWithOuiName);
		map.put("ETHER_MAC_OUI_DESCRIPTION", MacOuiAssignments::resolveMacOuiDescription);
		map.put("ICMPv4_TYPE", Icmp4Type::resolve);
		map.put("ICMPv6_TYPE", Icmp6Type::resolve);
		map.put("ICMPv4_CODE", ValueResolver.of(Icmp4Code::resolve));
		map.put("TCP_FLAGS", TcpFlag::resolve);
		map.put("TCP_BITS", TcpFlag::resolveBitFormat);
		map.put("PORT_LOOKUP", o -> "UNKNOWN");
		map.put("MLRv2_TYPE", Icmp6Mlr2RecordType::resolve);
		map.put("PPP_PROTOCOL", PppProtocol::resolveProtocol);
		map.put("IPX_TYPE", IpxType::resolveType);

		return map;
	}

}
