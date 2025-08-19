package com.slytechs.jnet.protocol.api.address;

/**
 * Enumeration of network address families/types.
 * Defines the different types of network addresses supported.
 */
public enum AddressFamily {
    // Layer 2 (Data Link) Addresses
    ETHERNET(6, "Ethernet MAC Address"),
    EUI64(8, "IEEE EUI-64 Address"),
    BLUETOOTH(6, "Bluetooth Device Address"),
    
    // Layer 3 (Network) Addresses  
    IPv4(4, "Internet Protocol version 4"),
    IPv6(16, "Internet Protocol version 6"),
    IPX(10, "Internetwork Packet Exchange"),
    APPLETALK(3, "AppleTalk Address"),
    
    // Layer 4 (Transport) Socket Addresses
    IPv4_SOCKET(6, "IPv4 Socket Address (IP + Port)"),
    IPv6_SOCKET(18, "IPv6 Socket Address (IP + Port)"),
    UNIX_SOCKET(-1, "Unix Domain Socket"), // Variable length
    
    // Virtual/Logical Addresses
    VLAN(2, "VLAN Identifier"),
    VRF(4, "VPN Routing and Forwarding ID"),
    
    // Tunneling/Encapsulation
    MPLS(4, "MPLS Label"),
    VXLAN(3, "VXLAN Network Identifier"),
    GRE(4, "GRE Tunnel Key"),
    
    // Wireless/Mobile
    IEEE802_11(6, "WiFi BSSID/MAC Address"),
    IMSI(8, "International Mobile Subscriber Identity"),
    IMEI(8, "International Mobile Equipment Identity"),
    
    // Routing Protocol Addresses
    OSPF_ROUTER_ID(4, "OSPF Router ID"),
    BGP_AS_NUMBER(4, "BGP AS Number"),
    
    // Hardware/Physical
    PCI(4, "PCI Device Address"),
    USB(4, "USB Device Address"),
    
    // Application Layer
    URL(-1, "URL/URI Address"), // Variable length
    EMAIL(-1, "Email Address"), // Variable length
    DNS(-1, "DNS Name/FQDN"), // Variable length
    SIP(-1, "SIP URI"), // Variable length
    
    // Security/Crypto
    PUBLIC_KEY(-1, "Public Key Address"), // Variable length
    CERTIFICATE(-1, "Certificate Identifier"), // Variable length
    SSH_KEY(-1, "SSH Key Fingerprint"), // Variable length
    
    // InfiniBand
    INFINIBAND(16, "InfiniBand GID"),
    
    // Generic/Unknown
    UNKNOWN(-1, "Unknown Address Type");
    
    private final int length;
    private final String description;
    
    AddressFamily(int length, String description) {
        this.length = length;
        this.description = description;
    }
    
    /**
     * Returns the typical length of addresses of this family in bytes.
     * Returns -1 for variable-length address types.
     */
    public int length() {
        return length;
    }
    
    /**
     * Returns a human-readable description of this address family.
     */
    public String description() {
        return description;
    }
    
    /**
     * Returns true if this address family has a fixed length.
     */
    public boolean isFixedLength() {
        return length > 0;
    }
    
    /**
     * Returns true if this address family has variable length.
     */
    public boolean isVariableLength() {
        return length == -1;
    }
    
    /**
     * Returns true if this is a Layer 2 (Data Link) address family.
     */
    public boolean isLayer2() {
        return this == ETHERNET || this == EUI64 || this == BLUETOOTH || 
               this == IEEE802_11;
    }
    
    /**
     * Returns true if this is a Layer 3 (Network) address family.
     */
    public boolean isLayer3() {
        return this == IPv4 || this == IPv6 || this == IPX || this == APPLETALK;
    }
    
    /**
     * Returns true if this is a Layer 4 (Transport) address family.
     */
    public boolean isLayer4() {
        return this == IPv4_SOCKET || this == IPv6_SOCKET || this == UNIX_SOCKET;
    }
    
    /**
     * Returns true if this is an IP-based address family.
     */
    public boolean isIpBased() {
        return this == IPv4 || this == IPv6 || this == IPv4_SOCKET || this == IPv6_SOCKET;
    }
    
    /**
     * Returns true if this is a tunneling/encapsulation address family.
     */
    public boolean isTunneling() {
        return this == MPLS || this == VXLAN || this == GRE;
    }
    
    /**
     * Returns true if this is a virtual/logical address family.
     */
    public boolean isVirtual() {
        return this == VLAN || this == VRF || isTunneling();
    }
    
    /**
     * Returns true if this is a wireless/mobile address family.
     */
    public boolean isWireless() {
        return this == IEEE802_11 || this == BLUETOOTH || this == IMSI || this == IMEI;
    }
    
    /**
     * Returns true if this is an application-layer address family.
     */
    public boolean isApplicationLayer() {
        return this == URL || this == EMAIL || this == DNS || this == SIP;
    }
    
    /**
     * Returns true if this is a security/crypto address family.
     */
    public boolean isSecurity() {
        return this == PUBLIC_KEY || this == CERTIFICATE || this == SSH_KEY;
    }
}