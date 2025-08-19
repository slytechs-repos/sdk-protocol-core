package com.slytechs.jnet.protocol.api.address;

/**
 * Bluetooth device address (BD_ADDR). Represents a 48-bit Bluetooth device
 * address similar to MAC addresses.
 */
public record BluetoothAddressRecord(byte[] bytes, long asLongValue) implements BluetoothAddress {
	public BluetoothAddressRecord(byte[] bytes) {
		this(Addresses.validateLength(bytes, LENGTH), Addresses.toLongFromBytes(bytes));
	}

	public BluetoothAddressRecord(long address) {
		this(parseFromLong(address));
	}

	public BluetoothAddressRecord(String address) {
		this(parseFromString(address));
	}

	private static byte[] parseFromLong(long address) {
		var bytes = new byte[LENGTH];
		if (address < 0 || address > 0xFFFFFFFFFFFFL) {
			throw new IllegalArgumentException("Bluetooth address out of range");
		}
		for (int i = 5; i >= 0; i--) {
			bytes[i] = (byte) (address & 0xFF);
			address >>>= 8;
		}

		return bytes;
	}

	private static byte[] parseFromString(String address) {
		String[] parts = address.split("[:-]");
		if (parts.length != 6) {
			throw new IllegalArgumentException("Invalid Bluetooth address format: " + address);
		}

		byte[] bytes = new byte[6];
		for (int i = 0; i < 6; i++) {
			bytes[i] = (byte) Integer.parseInt(parts[i], 16);
		}
		return bytes;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.BluetoothAddress#asLong()
	 */
	@Override
	public long asLong() {
		long result = 0;
		for (int i = 0; i < 6; i++) {
			result = (result << 8) | (byteAt(i) & 0xFF);
		}
		return result;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.BluetoothAddress#getCompanyAssigned()
	 */
	@Override
	public int getCompanyAssigned() {
		return ((byteAt(0) & 0xFF) << 16) |
				((byteAt(1) & 0xFF) << 8) |
				(byteAt(2) & 0xFF);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.BluetoothAddress#getCompanyAssignedAsString()
	 */
	@Override
	public String getCompanyAssignedAsString() {
		return String.format("%02X:%02X:%02X", byteAt(0) & 0xFF,
				byteAt(1) & 0xFF, byteAt(2) & 0xFF);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.BluetoothAddress#getCompanyDefined()
	 */
	@Override
	public int getCompanyDefined() {
		return ((byteAt(3) & 0xFF) << 16) |
				((byteAt(4) & 0xFF) << 8) |
				(byteAt(5) & 0xFF);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.BluetoothAddress#getCompanyDefinedAsString()
	 */
	@Override
	public String getCompanyDefinedAsString() {
		var bytes = bytes();
		return String.format("%02X:%02X:%02X",
				bytes[3] & 0xFF, bytes[4] & 0xFF, bytes[5] & 0xFF);
	}

	/**
	 * Returns true if this address uses a valid Company Assigned portion. Note:
	 * This is a simplified check - a complete implementation would validate against
	 * the IEEE Registration Authority database.
	 */
	public boolean hasValidCompanyAssigned() {
		int ca = getCompanyAssigned();
		return ca != 0x000000 && ca != 0xFFFFFF;
	}

	@Override
	public String toString() {
		var bytes = bytes();
		return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
				bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF,
				bytes[3] & 0xFF, bytes[4] & 0xFF, bytes[5] & 0xFF);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.BluetoothAddress#toLowerCaseString()
	 */
	@Override
	public String toLowerCaseString() {
		var bytes = bytes();
		return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
				bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF,
				bytes[3] & 0xFF, bytes[4] & 0xFF, bytes[5] & 0xFF);
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.BluetoothAddress#toDashString()
	 */
	@Override
	public String toDashString() {
		var bytes = bytes();
		return String.format("%02X-%02X-%02X-%02X-%02X-%02X",
				bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF,
				bytes[3] & 0xFF, bytes[4] & 0xFF, bytes[5] & 0xFF);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;

		return (obj instanceof BluetoothAddress ba)
				&& this.asLong() == ba.asLong();
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Address#bytes(byte[])
	 */
	@Override
	public byte[] bytes(byte[] dst, int offset) {
		System.arraycopy(bytes, 0, dst, offset, LENGTH);

		return dst;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.Address#byteAt(int)
	 */
	@Override
	public byte byteAt(int index) {
		return bytes[index];
	}

}