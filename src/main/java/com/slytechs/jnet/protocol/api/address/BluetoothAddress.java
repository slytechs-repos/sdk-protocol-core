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
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface BluetoothAddress extends Address {

	int LENGTH = 6; // 48-bit address
	BluetoothAddress ANY = new BluetoothAddressRecord(new byte[6]);
	BluetoothAddress LOCAL = new BluetoothAddressRecord(new byte[] {
			0,
			0,
			0,
			(byte) 0xFF,
			(byte) 0xFF,
			(byte) 0xFF
	});

	long asLong();

	@Override
	default AddressFamily family() {
		return AddressFamily.BLUETOOTH;
	}

	@Override
	default boolean isBroadcast() {
		return false; // Bluetooth doesn't use traditional broadcast
	}

	@Override
	default boolean isMulticast() {
		return false; // Bluetooth doesn't use traditional multicast
	}

	/**
	 * Returns true if this is the ANY address (all zeros).
	 */
	default boolean isAny() {
		return equals(ANY);
	}

	/**
	 * Returns true if this is a local address.
	 */
	default boolean isLocal() {
		return equals(LOCAL);
	}

	/**
	 * Returns the Company Assigned portion (upper 24 bits). This identifies the
	 * manufacturer/vendor.
	 */
	int getCompanyAssigned();

	/**
	 * Returns the Company Assigned portion as a hex string.
	 */
	String getCompanyAssignedAsString();

	/**
	 * Returns the Company Defined portion (lower 24 bits). This is the
	 * device-specific part assigned by the manufacturer.
	 */
	int getCompanyDefined();

	/**
	 * Returns the Company Defined portion as a hex string.
	 */
	String getCompanyDefinedAsString();

	/**
	 * Returns the address in colon-separated lowercase format.
	 */
	String toLowerCaseString();

	/**
	 * Returns the address in dash-separated format.
	 */
	String toDashString();

	@Override
	default int length() {
		return LENGTH;
	}

}