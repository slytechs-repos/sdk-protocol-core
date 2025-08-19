package com.slytechs.jnet.protocol.api.address;

import static com.slytechs.jnet.protocol.api.address.Addresses.*;

/**
 * VLAN (Virtual LAN) identifier. Represents a 12-bit VLAN ID as defined in IEEE
 * 802.1Q.
 */
public record VlanIdRecord(byte[] bytes, int vlanId) implements VlanId {
	public VlanIdRecord(int vlanId) {
		this(packBytes(vlanId), validateVlanId(vlanId));
	}

	public VlanIdRecord(byte[] bytes) {
		this(bytes, ((bytes[0] & 0x0F) << 8) | (bytes[1] & 0xFF));
	}

	public VlanIdRecord(String vlanIdStr) {
		this(VlanId.parseVlanId(vlanIdStr));
	}

	public VlanIdRecord(int pcp, boolean dei, int vid) {
		this(packBytes(pcp, dei, vid), validateVlanId(vid));
	}

	private static byte[] packBytes(int vlanId) {
		byte[] bytes = new byte[2];
		bytes[0] = (byte) (vlanId >>> 8);
		bytes[1] = (byte) vlanId;
		return bytes;
	}

	private static byte[] packBytes(int pcp, boolean dei, int vid) {
		if (pcp < 0 || pcp > 7) {
			throw new IllegalArgumentException("PCP must be between 0 and 7, got: " + pcp);
		}
		if (vid < 0 || vid > 4095) {
			throw new IllegalArgumentException("VLAN ID must be between 0 and 4095, got: " + vid);
		}
		byte[] bytes = new byte[2];
		short tci = (short) ((pcp << 13) | (dei ? 0x1000 : 0) | (vid & 0x0FFF));
		bytes[0] = (byte) (tci >>> 8);
		bytes[1] = (byte) tci;
		return bytes;
	}

	private static int validateVlanId(int vlanId) {
		if (vlanId < 0 || vlanId > 4095) {
			throw new IllegalArgumentException("VLAN ID must be between 0 and 4095, got: " + vlanId);
		}
		return vlanId;
	}

	@Override
	public int vlanId() {
		return vlanId;
	}

	@Override
	public int pcp() {
		return (bytes[0] >>> 5) & 0x07; // PCP: bits 7–5 of first byte
	}

	@Override
	public boolean dei() {
		return (bytes[0] & 0x10) != 0; // DEI: bit 4 of first byte
	}

	@Override
	public int vid() {
		return vlanId(); // VID is the same as vlanId()
	}

	@Override
	public byte[] bytes(byte[] dst, int offset) {
		dst[0 + offset] = bytes[0];
		dst[1 + offset] = bytes[1];
		return dst;
	}

	@Override
	public byte[] bytes() {
		return bytes;
	}

	@Override
	public byte byteAt(int index) {
		return bytes[index];
	}

	@Override
	public String toString() {
		return VlanId.formatVlanId(vlanId);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!(obj instanceof VlanIdRecord))
			return false;
		VlanIdRecord other = (VlanIdRecord) obj;
		return vlanId == other.vlanId && pcp() == other.pcp() && dei() == other.dei();
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.VlanId#setPcp(int)
	 */
	@Override
	public void setPcp(int pcp) {
		throw new UnsupportedOperationException(unsupportedMessage(getClass().getSimpleName()));
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.VlanId#setDei(boolean)
	 */
	@Override
	public void setDei(boolean dei) {
		throw new UnsupportedOperationException(unsupportedMessage(getClass().getSimpleName()));
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.VlanId#setVid(int)
	 */
	@Override
	public void setVid(int vid) {
		throw new UnsupportedOperationException(unsupportedMessage(getClass().getSimpleName()));
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.address.VlanId#setTci(int, boolean, int)
	 */
	@Override
	public void setTci(int pcp, boolean dei, int vid) {
		throw new UnsupportedOperationException(unsupportedMessage(getClass().getSimpleName()));
	}
}