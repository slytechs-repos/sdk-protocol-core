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
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface VlanId extends Address {

	int LENGTH = 2;
	int MIN_VLAN_ID = 1;
	int MAX_VLAN_ID = 4094;

	VlanId DEFAULT = new VlanIdRecord(1);
	VlanId NATIVE = new VlanIdRecord(0); // Special case for native VLAN
	VlanId RESERVED = new VlanIdRecord(4095); // Reserved VLAN ID

	static String formatVlanId(int vlanId) {
		return String.valueOf(vlanId);
	}

	static int parseVlanId(String vlanIdStr) {
		try {
			return Integer.parseInt(vlanIdStr);
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid VLAN ID format: " + vlanIdStr, e);
		}
	}

	int vlanId();

	int pcp();

	boolean dei();

	int vid();

	void setPcp(int pcp);

	void setDei(boolean dei);

	void setVid(int vid);

	void setTci(int pcp, boolean dei, int vid);

	@Override
	default AddressFamily family() {
		return AddressFamily.VLAN;
	}

	@Override
	default boolean isBroadcast() {
		return false; // VLAN IDs don't have broadcast concept
	}

	@Override
	default boolean isMulticast() {
		return false; // VLAN IDs don't have multicast concept
	}

	default boolean isNative() {
		return vlanId() == 0;
	}

	default boolean isReserved() {
		return vlanId() == 0 || vlanId() == 4095;
	}

	default boolean isValid() {
		return vlanId() >= MIN_VLAN_ID && vlanId() <= MAX_VLAN_ID;
	}

	default boolean isDefault() {
		return vlanId() == 1;
	}

	/**
	 * Returns true if this is a management VLAN (typically VLAN 1).
	 */
	default boolean isManagement() {
		return vlanId() == 1;
	}

	/**
	 * Returns the VLAN priority (3 bits from 802.1p). Note: This would typically
	 * come from the full 802.1Q tag, not just the VLAN ID.
	 */
	default int priority() {
		return pcp();
	}

	@Override
	default int length() {
		return LENGTH;
	}
}