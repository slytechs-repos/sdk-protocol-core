package com.slytechs.jnet.protocol.api.address;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;
import static java.lang.foreign.ValueLayout.*;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class VlanIdMemory extends AddressMemory implements VlanId {

	public static final MemoryLayout LAYOUT$BIG$SIZE_2 = unionLayout(
			sequenceLayout(LENGTH, JAVA_BYTE).withName("byte_array"),
			BIG_SHORT.withName("short_value"));

	public static final MemoryLayout LAYOUT = LAYOUT$BIG$SIZE_2;

	private static final VarHandle BYTE_ARRAY = LAYOUT.varHandle(groupElement("byte_array"), sequenceElement());
	private static final VarHandle SHORT_VALUE = LAYOUT.varHandle(groupElement("short_value"));

	public VlanIdMemory(Arena arena) {
		super(LAYOUT, arena);
	}

	public VlanIdMemory() {
		super(LAYOUT);
	}

	public VlanIdMemory(MemorySegment pointer, Arena arena) {
		super(LAYOUT, pointer, arena);
	}

	public VlanIdMemory(MemorySegment segment, long offset) {
		super(LAYOUT, segment, offset);
	}

	public VlanIdMemory(MemorySegment pointer) {
		super(LAYOUT, pointer);
	}

	@Override
	public byte[] bytes(byte[] dst, int offset) {
		dst[0 + offset] = (byte) (byteAt(0) & 0xFF); // Preserve full byte, including PCP and DEI
		dst[1 + offset] = byteAt(1);

		return dst;
	}

	@Override
	public byte byteAt(int index) {
		return (byte) BYTE_ARRAY.get(asMemorySegment(), activeBytesStart(), index);
	}

	@Override
	public int vlanId() {
		return ((short) SHORT_VALUE.get(asMemorySegment(), activeBytesStart())) & 0x0FFF; // 12-bit VID
	}

	@Override
	public int pcp() {
		return (((short) SHORT_VALUE.get(asMemorySegment(), activeBytesStart())) >>> 13) & 0x07; // 3-bit PCP (bits
																									// 15–13)
	}

	@Override
	public boolean dei() {
		return (((short) SHORT_VALUE.get(asMemorySegment(), activeBytesStart())) & 0x1000) != 0; // 1-bit DEI (bit 12)
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
		short current = (short) SHORT_VALUE.get(asMemorySegment(), activeBytesStart());
		short newValue = (short) ((current & 0x1FFF) | (pcp << 13)); // Clear PCP bits, set new PCP
		SHORT_VALUE.set(asMemorySegment(), activeBytesStart(), newValue);
	}

	@Override
	public void setDei(boolean dei) {
		short current = (short) SHORT_VALUE.get(asMemorySegment(), activeBytesStart());
		short newValue = dei ? (short) (current | 0x1000) : (short) (current & ~0x1000); // Set or clear DEI bit
		SHORT_VALUE.set(asMemorySegment(), activeBytesStart(), newValue);
	}

	@Override
	public void setVid(int vid) {
		if (vid < 0 || vid > 4095) {
			throw new IllegalArgumentException("VLAN ID must be between 0 and 4095, got: " + vid);
		}
		short current = (short) SHORT_VALUE.get(asMemorySegment(), activeBytesStart());
		short newValue = (short) ((current & 0xF000) | (vid & 0x0FFF)); // Clear VID bits, set new VID
		SHORT_VALUE.set(asMemorySegment(), activeBytesStart(), newValue);
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
		SHORT_VALUE.set(asMemorySegment(), activeBytesStart(), newValue);
	}
}