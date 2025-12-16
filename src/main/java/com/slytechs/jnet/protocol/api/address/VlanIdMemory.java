package com.slytechs.jnet.protocol.api.address;

import java.lang.foreign.MemoryLayout;

import com.slytechs.jnet.core.api.memory.MemoryHandle.ByteHandle;
import com.slytechs.jnet.core.api.memory.MemoryHandle.ShortHandle;

import static java.lang.foreign.MemoryLayout.*;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class VlanIdMemory extends AddressMemory implements VlanId {

	public static final MemoryLayout LAYOUT = unionLayout(
			sequenceLayout(LENGTH, U8_BE).withName("byte_array"),
			U16_BE.withName("short_value"));

	// Use MemoryHandle instead of VarHandle
	private static final ByteHandle BYTE_ARRAY = new ByteHandle(LAYOUT, "byte_array[]");
	private static final ShortHandle SHORT_VALUE = new ShortHandle(LAYOUT, "short_value");

	public VlanIdMemory() {
		super(LAYOUT);
	}

	@Override
	public byte[] bytes(byte[] dst, int offset) {
		dst[0 + offset] = (byte) (byteAt(0) & 0xFF); // Preserve full byte, including PCP and DEI
		dst[1 + offset] = byteAt(1);
		return dst;
	}

	@Override
	public byte byteAt(int index) {
		return BYTE_ARRAY.getByteAtIndex(view(), index);
	}

	@Override
	public int vlanId() {
		return SHORT_VALUE.getShort(view()) & 0x0FFF; // 12-bit VID
	}

	@Override
	public int pcp() {
		return (SHORT_VALUE.getShort(view()) >>> 13) & 0x07; // 3-bit PCP (bits 15-13)
	}

	@Override
	public boolean dei() {
		return (SHORT_VALUE.getShort(view()) & 0x1000) != 0; // 1-bit DEI (bit 12)
	}

	@Override
	public int vid() {
		return vlanId(); // VID is the same as vlanId()
	}

	@Override
	public void setPcp(int pcp) {
		if (pcp < 0 || pcp > 7) {
			throw new IllegalArgumentException("PCP must be between 0 and 7, got: " + pcp);
		}
		short current = SHORT_VALUE.getShort(view());
		short newValue = (short) ((current & 0x1FFF) | (pcp << 13)); // Clear PCP bits, set new PCP
		SHORT_VALUE.setShort(view(), 0, newValue);
	}

	@Override
	public void setDei(boolean dei) {
		short current = SHORT_VALUE.getShort(view());
		short newValue = dei ? (short) (current | 0x1000) : (short) (current & ~0x1000); // Set or clear DEI bit
		SHORT_VALUE.setShort(view(), 0, newValue);
	}

	@Override
	public void setVid(int vid) {
		if (vid < 0 || vid > 4095) {
			throw new IllegalArgumentException("VLAN ID must be between 0 and 4095, got: " + vid);
		}
		short current = SHORT_VALUE.getShort(view());
		short newValue = (short) ((current & 0xF000) | (vid & 0x0FFF)); // Clear VID bits, set new VID
		SHORT_VALUE.setShort(view(), 0, newValue);
	}

	@Override
	public void setTci(int pcp, boolean dei, int vid) {
		if (pcp < 0 || pcp > 7) {
			throw new IllegalArgumentException("PCP must be between 0 and 7, got: " + pcp);
		}
		if (vid < 0 || vid > 4095) {
			throw new IllegalArgumentException("VLAN ID must be between 0 and 4095, got: " + vid);
		}
		short newValue = (short) ((pcp << 13) | (dei ? 0x1000 : 0) | (vid & 0x0FFF)); // Combine PCP, DEI, VID
		SHORT_VALUE.setShort(view(), 0, newValue);
	}

	@Override
	public void setBytes(byte[] addr) {
		if (addr.length != LENGTH) {
			throw new IllegalArgumentException("VLAN ID must be " + LENGTH + " bytes");
		}
		for (int i = 0; i < LENGTH; i++) {
			BYTE_ARRAY.setByteAtIndex(view(), i, addr[i]);
		}
	}
}