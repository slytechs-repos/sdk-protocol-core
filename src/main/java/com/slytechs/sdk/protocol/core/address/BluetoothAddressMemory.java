package com.slytechs.sdk.protocol.core.address;

import java.lang.foreign.MemoryLayout;

import com.slytechs.sdk.common.memory.MemoryHandle.ByteHandle;
import com.slytechs.sdk.common.memory.MemoryHandle.ShortHandle;

import static java.lang.foreign.MemoryLayout.*;

/**
 * Bluetooth device address (BD_ADDR). Represents a 48-bit Bluetooth device
 * address similar to MAC addresses.
 */
public final class BluetoothAddressMemory extends AddressMemory implements BluetoothAddress {
	public static final MemoryLayout LAYOUT$BIG$SIZE_6 = unionLayout(
			sequenceLayout(LENGTH, U8_BE).withName("byte_array"),
			structLayout(
					U16_BE.withName("high"),
					U32_BE.withName("low")

			).withName("fast_path")

	);

	public static final MemoryLayout LAYOUT = LAYOUT$BIG$SIZE_6;

	private static final ByteHandle BYTE_ARRAY = new ByteHandle(LAYOUT, "byte_array[]");
	private static final ShortHandle HIGH = new ShortHandle(LAYOUT, "fast_path[]", "high");
	private static final ShortHandle LOW = new ShortHandle(LAYOUT, "fast_path[]", "low");

	public BluetoothAddressMemory() {
		super(LAYOUT);
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

	private static byte[] validateLength(byte[] bytes, int expectedLength) {
		if (bytes.length != expectedLength) {
			throw new IllegalArgumentException(
					"Expected " + expectedLength + " bytes, got " + bytes.length);
		}
		return bytes;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.BluetoothAddress#family()
	 */
	@Override
	public AddressFamily family() {
		return AddressFamily.BLUETOOTH;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.BluetoothAddress#isBroadcast()
	 */
	@Override
	public boolean isBroadcast() {
		return false; // Bluetooth doesn't use traditional broadcast
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.BluetoothAddress#isMulticast()
	 */
	@Override
	public boolean isMulticast() {
		return false; // Bluetooth doesn't use traditional multicast
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.BluetoothAddress#isAny()
	 */
	@Override
	public boolean isAny() {
		return equals(ANY);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.BluetoothAddress#isLocal()
	 */
	@Override
	public boolean isLocal() {
		return equals(LOCAL);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.BluetoothAddress#getCompanyAssigned()
	 */
	@Override
	public int getCompanyAssigned() {
		return ((byteAt(0) & 0xFF) << 16) |
				((byteAt(1) & 0xFF) << 8) |
				(byteAt(2) & 0xFF);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.BluetoothAddress#getCompanyAssignedAsString()
	 */
	@Override
	public String getCompanyAssignedAsString() {
		var bytes = bytes();
		return String.format("%02X:%02X:%02X",
				bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.BluetoothAddress#getCompanyDefined()
	 */
	@Override
	public int getCompanyDefined() {
		return ((byteAt(3) & 0xFF) << 16) |
				((byteAt(4) & 0xFF) << 8) |
				(byteAt(5) & 0xFF);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.BluetoothAddress#getCompanyDefinedAsString()
	 */
	@Override
	public String getCompanyDefinedAsString() {
		var bytes = bytes();
		return String.format("%02X:%02X:%02X", bytes[3] & 0xFF, bytes[4] & 0xFF, bytes[5] & 0xFF);
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
	 * @see com.slytechs.sdk.protocol.core.address.BluetoothAddress#toLowerCaseString()
	 */
	@Override
	public String toLowerCaseString() {
		var bytes = bytes();
		return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
				bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF,
				bytes[3] & 0xFF, bytes[4] & 0xFF, bytes[5] & 0xFF);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.BluetoothAddress#toDashString()
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
		if (!(obj instanceof BluetoothAddressMemory))
			return false;
		return super.equals(obj);
	}

	@Override
	public int hashCode() {
		return super.hashCode();
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Address#bytes(byte[], int)
	 */
	@Override
	public byte[] bytes(byte[] dst, int offset) {
		return bytesUsingVarHandle(BYTE_ARRAY.varHandle(), dst, offset);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.Address#byteAt(int)
	 */
	@Override
	public byte byteAt(int index) {
		return BYTE_ARRAY.getByteAtIndex(view(), index);
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.address.BluetoothAddress#asLong()
	 */
	@Override
	public long asLong() {
		short high = HIGH.getShort(view());
		short low = LOW.getShort(view());

		return high << 32 | low;
	}
}