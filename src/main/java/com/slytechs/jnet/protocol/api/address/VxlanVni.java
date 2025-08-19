package com.slytechs.jnet.protocol.api.address;

/**
 * VXLAN Network Identifier (VNI).
 * Represents a 24-bit VXLAN Network Identifier as defined in RFC 7348.
 */
public final class VxlanVni extends Address {
    public static final int LENGTH = 3; // 24-bit value stored in 3 bytes
    public static final int MAX_VNI_VALUE = 0xFFFFFF; // 24-bit max value (16,777,215)
    
    public static final VxlanVni DEFAULT = new VxlanVni(0);
    public static final VxlanVni RESERVED_MAX = new VxlanVni(MAX_VNI_VALUE);
    
    private final int vni;
    
    public VxlanVni(int vni) {
        super(LENGTH);
        this.vni = validateVni(vni);
        packBytes();
    }
    
    public VxlanVni(byte[] bytes) {
        super(validateLength(bytes, LENGTH));
        this.vni = ((bytes[0] & 0xFF) << 16) |
                   ((bytes[1] & 0xFF) << 8) |
                   (bytes[2] & 0xFF);
        packBytes();
    }
    
    public VxlanVni(String vniStr) {
        this(parseFromString(vniStr));
    }
    
    private static int parseFromString(String vniStr) {
        try {
            return Integer.parseInt(vniStr);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid VXLAN VNI format: " + vniStr, e);
        }
    }
    
    private void packBytes() {
        bytes[0] = (byte)(vni >>> 16);
        bytes[1] = (byte)(vni >>> 8);
        bytes[2] = (byte)vni;
    }
    
    private static int validateVni(int vni) {
        if (vni < 0 || vni > MAX_VNI_VALUE) {
            throw new IllegalArgumentException("VXLAN VNI must be between 0 and " + MAX_VNI_VALUE + ", got: " + vni);
        }
        return vni;
    }
    
    private static byte[] validateLength(byte[] bytes, int expectedLength) {
        if (bytes.length != expectedLength) {
            throw new IllegalArgumentException(
                "Expected " + expectedLength + " bytes, got " + bytes.length);
        }
        return bytes;
    }
    
    public int vni() {
        return vni;
    }
    
    public int asInt() {
        return vni;
    }
    
    @Override
    public AddressFamily family() {
        return AddressFamily.VXLAN;
    }
    
    @Override
    public boolean isBroadcast() {
        return false; // VNI doesn't have broadcast concept
    }
    
    @Override
    public boolean isMulticast() {
        return false; // VNI doesn't have multicast concept
    }
    
    public boolean isDefault() {
        return vni == 0;
    }
    
    public boolean isReserved() {
        return vni == MAX_VNI_VALUE;
    }
    
    /**
     * Returns true if this VNI is in the valid range for tenant networks.
     * Some implementations reserve certain ranges for special purposes.
     */
    public boolean isValidTenant() {
        return vni > 0 && vni < MAX_VNI_VALUE;
    }
    
    /**
     * Returns true if this VNI might be used for management purposes.
     * This is implementation-specific, but VNI 0 is often reserved.
     */
    public boolean isManagement() {
        return vni == 0;
    }
    
    @Override
    public String toString() {
        return String.valueOf(vni);
    }
    
    public String toHexString() {
        return String.format("0x%06X", vni);
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof VxlanVni)) return false;
        VxlanVni other = (VxlanVni) obj;
        return vni == other.vni;
    }
    
    @Override
    public int hashCode() {
        return Integer.hashCode(vni);
    }
    
    @Override
    public int compareTo(Address other) {
        if (!(other instanceof VxlanVni)) {
            return super.compareTo(other);
        }
        VxlanVni otherVni = (VxlanVni) other;
        return Integer.compare(this.vni, otherVni.vni);
    }
}