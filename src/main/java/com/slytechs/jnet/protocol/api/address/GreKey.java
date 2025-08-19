package com.slytechs.jnet.protocol.api.address;

/**
 * GRE (Generic Routing Encapsulation) tunnel key.
 * Represents a 32-bit GRE key as defined in RFC 2784 and RFC 2890.
 */
public final class GreKey extends Address {
    public static final int LENGTH = 4; // 32-bit key
    
    public static final GreKey NONE = new GreKey(0);
    
    private final int key;
    
    public GreKey(int key) {
        super(LENGTH);
        this.key = key; // GRE keys can use the full 32-bit range
        packBytes();
    }
    
    public GreKey(long key) {
        this((int) key); // Cast to int, allowing for negative values
    }
    
    public GreKey(byte[] bytes) {
        super(validateLength(bytes, LENGTH));
        this.key = ((bytes[0] & 0xFF) << 24) |
                   ((bytes[1] & 0xFF) << 16) |
                   ((bytes[2] & 0xFF) << 8) |
                   (bytes[3] & 0xFF);
        packBytes();
    }
    
    public GreKey(String keyStr) {
        this(parseFromString(keyStr));
    }
    
    private static int parseFromString(String keyStr) {
        try {
            // Support both decimal and hex formats
            if (keyStr.startsWith("0x") || keyStr.startsWith("0X")) {
                return (int) Long.parseLong(keyStr.substring(2), 16);
            } else {
                return (int) Long.parseLong(keyStr);
            }
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid GRE key format: " + keyStr, e);
        }
    }
    
    private void packBytes() {
        bytes[0] = (byte)(key >>> 24);
        bytes[1] = (byte)(key >>> 16);
        bytes[2] = (byte)(key >>> 8);
        bytes[3] = (byte)key;
    }
    
    private static byte[] validateLength(byte[] bytes, int expectedLength) {
        if (bytes.length != expectedLength) {
            throw new IllegalArgumentException(
                "Expected " + expectedLength + " bytes, got " + bytes.length);
        }
        return bytes;
    }
    
    public int key() {
        return key;
    }
    
    public int asInt() {
        return key;
    }
    
    public long asLong() {
        return key & 0xFFFFFFFFL; // Convert to unsigned long
    }
    
    @Override
    public AddressFamily family() {
        return AddressFamily.GRE;
    }
    
    @Override
    public boolean isBroadcast() {
        return false; // GRE keys don't have broadcast concept
    }
    
    @Override
    public boolean isMulticast() {
        return false; // GRE keys don't have multicast concept
    }
    
    public boolean isNone() {
        return key == 0;
    }
    
    /**
     * Returns true if this is a commonly used key value.
     * Some GRE implementations use specific key ranges for different purposes.
     */
    public boolean isWellKnown() {
        // This is implementation-specific, but some common patterns:
        return key == 0 || key == 1 || key == 0xFFFFFFFF;
    }
    
    /**
     * Returns true if this key might be used for management tunnels.
     * This is implementation-specific.
     */
    public boolean isManagement() {
        return key == 1;
    }
    
    @Override
    public String toString() {
        return String.valueOf(key & 0xFFFFFFFFL); // Display as unsigned
    }
    
    public String toHexString() {
        return String.format("0x%08X", key);
    }
    
    public String toSignedString() {
        return String.valueOf(key); // Display as signed
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof GreKey)) return false;
        GreKey other = (GreKey) obj;
        return key == other.key;
    }
    
    @Override
    public int hashCode() {
        return Integer.hashCode(key);
    }
    
    @Override
    public int compareTo(Address other) {
        if (!(other instanceof GreKey)) {
            return super.compareTo(other);
        }
        GreKey otherKey = (GreKey) other;
        return Integer.compareUnsigned(this.key, otherKey.key);
    }
}