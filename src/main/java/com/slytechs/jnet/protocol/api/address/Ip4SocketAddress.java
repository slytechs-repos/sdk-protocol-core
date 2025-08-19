package com.slytechs.jnet.protocol.api.address;

/**
 * IPv4 socket address combining an IPv4 address with a port number.
 * Represents endpoints for TCP/UDP connections.
 */
public final class Ip4SocketAddress implements Address {
    public static final int LENGTH = 6; // 4 bytes IP + 2 bytes port
    
    private final Ip4AddressRecord address;
    private final int port;
    
    public Ip4SocketAddress(Ip4AddressRecord address, int port) {
        super(LENGTH);
        this.address = address;
        this.port = validatePort(port);
        packBytes();
    }
    
    public Ip4SocketAddress(String address, int port) {
        this(new Ip4AddressRecord(address), port);
    }
    
    public Ip4SocketAddress(int address, int port) {
        this(new Ip4AddressRecord(address), port);
    }
    
    public Ip4SocketAddress(byte[] addressBytes, int port) {
        this(new Ip4AddressRecord(addressBytes), port);
    }
    
    public Ip4SocketAddress(String socketAddress) {
        this(parseFromString(socketAddress));
    }
    
    private Ip4SocketAddress(Ip4SocketAddress other) {
        super(LENGTH);
        this.address = other.address;
        this.port = other.port;
        System.arraycopy(other.bytes, 0, this.bytes, 0, LENGTH);
    }
    
    private static Ip4SocketAddress parseFromString(String socketAddr) {
        int colonIndex = socketAddr.lastIndexOf(':');
        if (colonIndex == -1) {
            throw new IllegalArgumentException("Invalid socket address format: " + socketAddr);
        }
        
        String ipStr = socketAddr.substring(0, colonIndex);
        String portStr = socketAddr.substring(colonIndex + 1);
        
        try {
            int port = Integer.parseInt(portStr);
            return new Ip4SocketAddress(ipStr, port);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid port number: " + portStr, e);
        }
    }
    
    private void packBytes() {
        byte[] addrBytes = address.bytes();
        System.arraycopy(addrBytes, 0, bytes, 0, 4);
        bytes[4] = (byte)(port >>> 8);
        bytes[5] = (byte)port;
    }
    
    private static int validatePort(int port) {
        if (port < 0 || port > 65535) {
            throw new IllegalArgumentException("Port must be between 0 and 65535, got: " + port);
        }
        return port;
    }
    
    public Ip4Address address() {
        return address;
    }
    
    public int port() {
        return port;
    }
    
    @Override
    public AddressFamily family() {
        return AddressFamily.IPv4;
    }
    
    @Override
    public boolean isBroadcast() {
        return address.isBroadcast();
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
        return address + ":" + port;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof Ip4SocketAddress)) return false;
        Ip4SocketAddress other = (Ip4SocketAddress) obj;
        return port == other.port && address.equals(other.address);
    }
    
    @Override
    public int hashCode() {
        return address.hashCode() * 31 + port;
    }
}