package com.slytechs.jnet.protocol.api.address;

/**
 * MPLS (Multiprotocol Label Switching) label.
 * Represents a 20-bit MPLS label as defined in RFC 3032.
 */
public final class MplsLabel extends Address {
    public static final int LENGTH = 4; // 32-bit MPLS header (20-bit label + 3-bit TC + 1-bit S + 8-bit TTL)
    public static final int MAX_LABEL_VALUE = 0xFFFFF; // 20-bit max value (1,048,575)
    
    // Reserved label values (RFC 3032)
    public static final MplsLabel IPV4_EXPLICIT_NULL = new MplsLabel(0);
    public static final MplsLabel ROUTER_ALERT = new MplsLabel(1);
    public static final MplsLabel IPV6_EXPLICIT_NULL = new MplsLabel(2);
    public static final MplsLabel IMPLICIT_NULL = new MplsLabel(3);
    
    private final int label;
    private final int trafficClass;
    private final boolean bottomOfStack;
    private final int ttl;
    
    public MplsLabel(int label) {
        this(label, 0, true, 64);
    }
    
    public MplsLabel(int label, int trafficClass, boolean bottomOfStack, int ttl) {
        super(LENGTH);
        this.label = validateLabel(label);
        this.trafficClass = validateTrafficClass(trafficClass);
        this.bottomOfStack = bottomOfStack;
        this.ttl = validateTtl(ttl);
        packBytes();
    }
    
    public MplsLabel(byte[] bytes) {
        super(validateLength(bytes, LENGTH));
        int fullValue = ((bytes[0] & 0xFF) << 24) |
                       ((bytes[1] & 0xFF) << 16) |
                       ((bytes[2] & 0xFF) << 8) |
                       (bytes[3] & 0xFF);
        
        this.label = (fullValue >>> 12) & 0xFFFFF;
        this.trafficClass = (fullValue >>> 9) & 0x07;
        this.bottomOfStack = (fullValue & 0x100) != 0;
        this.ttl = fullValue & 0xFF;
    }
    
    public MplsLabel(String labelStr) {
        this(parseFromString(labelStr));
    }
    
    private static int parseFromString(String labelStr) {
        try {
            return Integer.parseInt(labelStr);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid MPLS label format: " + labelStr, e);
        }
    }
    
    private void packBytes() {
        int packed = (label << 12) |
                    (trafficClass << 9) |
                    (bottomOfStack ? 0x100 : 0) |
                    ttl;
        
        bytes[0] = (byte)(packed >>> 24);
        bytes[1] = (byte)(packed >>> 16);
        bytes[2] = (byte)(packed >>> 8);
        bytes[3] = (byte)packed;
    }
    
    private static int validateLabel(int label) {
        if (label < 0 || label > MAX_LABEL_VALUE) {
            throw new IllegalArgumentException("MPLS label must be between 0 and " + MAX_LABEL_VALUE + ", got: " + label);
        }
        return label;
    }
    
    private static int validateTrafficClass(int tc) {
        if (tc < 0 || tc > 7) {
            throw new IllegalArgumentException("Traffic class must be between 0 and 7, got: " + tc);
        }
        return tc;
    }
    
    private static int validateTtl(int ttl) {
        if (ttl < 0 || ttl > 255) {
            throw new IllegalArgumentException("TTL must be between 0 and 255, got: " + ttl);
        }
        return ttl;
    }
    
    private static byte[] validateLength(byte[] bytes, int expectedLength) {
        if (bytes.length != expectedLength) {
            throw new IllegalArgumentException(
                "Expected " + expectedLength + " bytes, got " + bytes.length);
        }
        return bytes;
    }
    
    public int label() {
        return label;
    }
    
    public int trafficClass() {
        return trafficClass;
    }
    
    public boolean bottomOfStack() {
        return bottomOfStack;
    }
    
    public int ttl() {
        return ttl;
    }
    
    public int asInt() {
        return label;
    }
    
    @Override
    public AddressFamily family() {
        return AddressFamily.MPLS;
    }
    
    @Override
    public boolean isBroadcast() {
        return false; // MPLS labels don't have broadcast concept
    }
    
    @Override
    public boolean isMulticast() {
        return false; // MPLS labels don't have multicast concept
    }
    
    public boolean isReserved() {
        return label >= 0 && label <= 15; // RFC 3032 reserved range
    }
    
    public boolean isExplicitNull() {
        return label == 0 || label == 2;
    }
    
    public boolean isImplicitNull() {
        return label == 3;
    }
    
    public boolean isRouterAlert() {
        return label == 1;
    }
    
    /**
     * Returns true if this is a valid user-assignable label.
     */
    public boolean isUserAssignable() {
        return label >= 16 && label <= MAX_LABEL_VALUE;
    }
    
    /**
     * Creates a new MplsLabel with the same label but different stack position.
     */
    public MplsLabel withBottomOfStack(boolean bottom) {
        if (this.bottomOfStack == bottom) {
            return this;
        }
        return new MplsLabel(label, trafficClass, bottom, ttl);
    }
    
    /**
     * Creates a new MplsLabel with the same label but different TTL.
     */
    public MplsLabel withTtl(int newTtl) {
        if (this.ttl == newTtl) {
            return this;
        }
        return new MplsLabel(label, trafficClass, bottomOfStack, newTtl);
    }
    
    @Override
    public String toString() {
        return String.valueOf(label);
    }
    
    public String toDetailedString() {
        return String.format("MPLS[label=%d, tc=%d, bos=%s, ttl=%d]", 
                           label, trafficClass, bottomOfStack, ttl);
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MplsLabel)) return false;
        MplsLabel other = (MplsLabel) obj;
        return label == other.label &&
               trafficClass == other.trafficClass &&
               bottomOfStack == other.bottomOfStack &&
               ttl == other.ttl;
    }
    
    @Override
    public int hashCode() {
        return label * 31 + trafficClass * 7 + (bottomOfStack ? 1 : 0) + ttl;
    }
    
    @Override
    public int compareTo(Address other) {
        if (!(other instanceof MplsLabel)) {
            return super.compareTo(other);
        }
        MplsLabel otherLabel = (MplsLabel) other;
        return Integer.compare(this.label, otherLabel.label);
    }
}