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
package com.slytechs.jnet.protocol.api.address;

/**
 * Base class for IP addresses (IPv4 and IPv6).
 */
public interface IpAddress extends Address {

	/**
	 * Returns true if this is a loopback address.
	 */
	boolean isLoopback();

	/**
	 * Returns true if this is a private/non-routable address.
	 */
	boolean isPrivate();

	/**
	 * Returns true if this is a link-local address.
	 */
	boolean isLinkLocal();

	/**
	 * Parse an IP address from string (auto-detects IPv4 vs IPv6).
	 */
	static IpAddress parse(String addr) {
		if (addr.contains(":")) {
			return new Ip6AddressRecord(addr);
		} else {
			return new Ip4AddressRecord(addr);
		}
	}

	static String format(byte[] bytes) {
		return bytes.length == 4
				? Ip4Address.formatIpv4Address(bytes)
				: Ip6Address.formatIpv6Address(bytes);
	}
}