package com.slytechs.jnet.protocol.api.address;

/**
 * IEEE EUI-64 (Extended Unique Identifier) address.
 * Represents a 64-bit IEEE EUI-64 identifier used in various protocols.
 */
public final class Eui64Address  {
    public static final int LENGTH = 8; // 64-bit address
    
    public static final Eui64Address ZERO = new Eui64Address(new byte[8]);
    
    public Eui64Address(byte[] bytes) {
        super(validateLength(bytes, LENGTH));
    }
    
    public Eui64Address(long address) {
        super(LENGTH);
        for (int i = 7; i >= 0; i--) {
            bytes[i] = (byte)(address & 0xFF);
            address >>>= 8;
        }
    }
    
    public Eui64Address(String address) {
        this(parseFromString(address));
    }
    
    /**
     * Creates an EUI-64 from a 48-bit MAC address using the standard mapping.
     * Inserts FF-FE in the middle and flips the U/L bit.
     */
    public Eui64Address(MacAddressRecord macAddress) {
        this(convertFromMac(macAddress));
    }
    
    private static byte[] convertFromMac(MacAddressRecord macAddress) {
        byte[] macBytes = macAddress.bytes();
        byte[] eui64 = new byte[8];
        
        // Copy first 3 bytes
        System.arraycopy(macBytes, 0, eui64, 0, 3);
        
        // Insert FF-FE
        eui64[3] = (byte) 0xFF;
        eui64[4] = (byte) 0xFE;
        
        // Copy last 3 bytes
        System.arraycopy(macBytes, 3, eui64, 5, 3);
        
        // Flip the Universal/Local bit (bit 1 of first byte)
        eui64[0] ^= 0x02;
        
        return eui64;
    }
    
    private static byte[] parseFromString(String address) {
        String[] parts = address.split("[:-]");
        if (parts.length != 8) {
            throw new IllegalArgumentException("Invalid EUI-64 address format: " + address);
        }
        
        byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
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
    
    public long asLong() {
        long result = 0;
        for (int i = 0; i < 8; i++) {
            result = (result << 8) | (bytes[i] & 0xFF);
        }
        return result;
    }
    
    @Override
    public AddressFamily family() {
        return AddressFamily.EUI64;
    }
    
    @Override
    public boolean isBroadcast() {
        return false; // EUI-64 doesn't have broadcast concept
    }
    
    @Override
    public boolean isMulticast() {
        return (bytes[0] & 0x01) != 0; // Multicast bit (LSB of first byte)
    }
    
    /**
     * Returns true if this is a locally administered address.
     */
    public boolean isLocallyAdministered() {
        return (bytes[0] & 0x02) != 0; // U/L bit (bit 1 of first byte)
    }
    
    /**
     * Returns true if this is a universally administered address.
     */
    public boolean isUniversallyAdministered() {
        return !isLocallyAdministered();
    }
    
    /**
     * Returns true if this appears to be converted from a MAC address.
     * Checks for the FF-FE insertion pattern.
     */
    public boolean isConvertedFromMac() {
        return (bytes[3] & 0xFF) == 0xFF && (bytes[4] & 0xFF) == 0xFE;
    }
    
    /**
     * Returns the Company ID (OUI) portion if this is a converted MAC address.
     */
    public int getCompanyId() {
        if (!isConvertedFromMac()) {
            throw new IllegalStateException("Not a MAC-derived EUI-64");
        }
        return ((bytes[0] & 0xFF) << 16) |
               ((bytes[1] & 0xFF) << 8) |
               (bytes[2] & 0xFF);
    }
    
    /**
     * Returns the device-specific portion if this is a converted MAC address.
     */
    public int getDeviceId() {
        if (!isConvertedFromMac()) {
            throw new IllegalStateException("Not a MAC-derived EUI-64");
        }
        return ((bytes[5] & 0xFF) << 16) |
               ((bytes[6] & 0xFF) << 8) |
               (bytes[7] & 0xFF);
    }
    
    /**
     * Converts this EUI-64 back to a MAC address if it was derived from one.
     */
    public MacAddress toMacAddress() {
        if (!isConvertedFromMac()) {
            throw new IllegalStateException("Cannot convert non-MAC-derived EUI-64 to MAC");
        }
        
        byte[] macBytes = new byte[6];
        
        // Copy first 3 bytes and flip U/L bit back
        System.arraycopy(bytes, 0, macBytes, 0, 3);
        macBytes[0] ^= 0x02;
        
        // Copy last 3 bytes (skip FF-FE)
        System.arraycopy(bytes, 5, macBytes, 3, 3);
        
        return new MacAddressRecord(macBytes);
    }
    
    @Override
    public String toString() {
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
            bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF, bytes[3] & 0xFF,
            bytes[4] & 0xFF, bytes[5] & 0xFF, bytes[6] & 0xFF, bytes[7] & 0xFF);
    }
    
    /**
     * Returns the address in dash-separated format.
     */
    public String toDashString() {
        return String.format("%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X",
            bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF, bytes[3] & 0xFF,
            bytes[4] & 0xFF, bytes[5] & 0xFF, bytes[6] & 0xFF, bytes[7] & 0xFF);
    }
    
    /**
     * Returns the address in dot-separated 16-bit groups format.
     */
    public String toDotString() {
        return String.format("%02X%02X.%02X%02X.%02X%02X.%02X%02X",
            bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF, bytes[3] & 0xFF,
            bytes[4] & 0xFF, bytes[5] & 0xFF, bytes[6] & 0xFF, bytes[7] & 0xFF);
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof Eui64Address)) return false;
        return super.equals(obj);
    }
    
    @Override
    public int hashCode() {
        return super.hashCode();
    }
}