package com.slytechs.jnet.protocol.api.address;

/**
 * IPv6 socket address combining an IPv6 address with a port number.
 * Represents endpoints for TCP/UDP connections over IPv6.
 */
public final class Ip6SocketAddress extends Address {
    public static final int LENGTH = 18; // 16 bytes IP + 2 bytes port
    
    private final Ip6AddressRecord address;
    private final int port;
    
    public Ip6SocketAddress(Ip6AddressRecord address, int port) {
        super(LENGTH);
        this.address = address;
        this.port = validatePort(port);
        packBytes();
    }
    
    public Ip6SocketAddress(String address, int port) {
        this(new Ip6AddressRecord(address), port);
    }
    
    public Ip6SocketAddress(byte[] addressBytes, int port) {
        this(new Ip6AddressRecord(addressBytes), port);
    }
    
    public Ip6SocketAddress(String socketAddress) {
        this(parseFromString(socketAddress));
    }
    
    private Ip6SocketAddress(Ip6SocketAddress other) {
        super(LENGTH);
        this.address = other.address;
        this.port = other.port;
        System.arraycopy(other.bytes, 0, this.bytes, 0, LENGTH);
    }
    
    private static Ip6SocketAddress parseFromString(String socketAddr) {
        // IPv6 socket addresses are formatted as [IPv6]:port
        if (!socketAddr.startsWith("[")) {
            throw new IllegalArgumentException("IPv6 socket address must be in [IPv6]:port format: " + socketAddr);
        }
        
        int closeBracket = socketAddr.indexOf(']');
        if (closeBracket == -1) {
            throw new IllegalArgumentException("Missing closing bracket in IPv6 socket address: " + socketAddr);
        }
        
        String ipStr = socketAddr.substring(1, closeBracket);
        
        if (closeBracket + 1 >= socketAddr.length() || socketAddr.charAt(closeBracket + 1) != ':') {
            throw new IllegalArgumentException("Missing colon after IPv6 address: " + socketAddr);
        }
        
        String portStr = socketAddr.substring(closeBracket + 2);
        
        try {
            int port = Integer.parseInt(portStr);
            return new Ip6SocketAddress(ipStr, port);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid port number: " + portStr, e);
        }
    }
    
    private void packBytes() {
        byte[] addrBytes = address.bytes();
        System.arraycopy(addrBytes, 0, bytes, 0, 16);
        bytes[16] = (byte)(port >>> 8);
        bytes[17] = (byte)port;
    }
    
    private static int validatePort(int port) {
        if (port < 0 || port > 65535) {
            throw new IllegalArgumentException("Port must be between 0 and 65535, got: " + port);
        }
        return port;
    }
    
    public Ip6Address address() {
        return address;
    }
    
    public int port() {
        return port;
    }
    
    @Override
    public AddressFamily family() {
        return AddressFamily.IPv6;
    }
    
    @Override
    public boolean isBroadcast() {
        return false; // IPv6 doesn't have broadcast
    }
    
    @Override
    public boolean isMulticast() {
        return address.isMulticast();
    }
    
    public boolean isLoopback() {
        return address.isLoopback();
    }
    
    public boolean isPrivate() {
        return address.isPrivate();
    }
    
    public boolean isLinkLocal() {
        return address.isLinkLocal();
    }
    
    public boolean isWellKnownPort() {
        return port >= 0 && port <= 1023;
    }
    
    public boolean isRegisteredPort() {
        return port >= 1024 && port <= 49151;
    }
    
    public boolean isDynamicPort() {
        return port >= 49152 && port <= 65535;
    }
    
    @Override
    public String toString() {
        return "[" + address + "]:" + port;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof Ip6SocketAddress)) return false;
        Ip6SocketAddress other = (Ip6SocketAddress) obj;
        return port == other.port && address.equals(other.address);
    }
    
    @Override
    public int hashCode() {
        return address.hashCode() * 31 + port;
    }
}