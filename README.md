# SDK Protocol Core

[![Java](https://img.shields.io/badge/Java-22%2B-orange.svg)](https://openjdk.java.net/projects/jdk/22/) [![Maven Central](https://img.shields.io/badge/Maven-Central-blue.svg)](https://search.maven.org/artifact/com.slytechs.sdk/sdk-protocol-core) [![License](https://img.shields.io/badge/License-Apache%20v2-green.svg)](https://claude.ai/chat/LICENSE)

Protocol dissection framework and runtime support for the Sly Technologies Network SDK.

**sdk-protocol-core** provides the foundation for packet dissection, protocol header access, and descriptor management. It serves as the base for all protocol packs (tcpip, web, infra).

------

## Table of Contents

1. [Overview](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#overview)
2. [Features](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#features)
3. [Architecture](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#architecture)
4. [Quick Start](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#quick-start)
5. [Protocol Packs](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#protocol-packs)
6. [Packet Descriptors](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#packet-descriptors)
7. [Installation](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#installation)
8. [Documentation](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#documentation)

------

## Overview

sdk-protocol-core provides:

- **Dissection Framework** - Extensible protocol parsing infrastructure
- **Packet Descriptors** - Efficient storage of dissection results
- **Header Binding** - Zero-allocation header access pattern
- **Runtime Services** - Shared implementation for all protocol packs

This module is typically used indirectly through protocol packs like [sdk-protocol-tcpip](https://github.com/slytechs-repos/sdk-protocol-tcpip).

------

## Features

### Dissection Framework

- Pluggable protocol dissectors
- Automatic protocol detection
- Layered dissection (L2 → L7)
- Extension point for custom protocols

### Packet Descriptors

- Compact binary format
- Protocol presence bitmap for fast lookup
- Inline protocol table with offsets/lengths
- Support for tunneled protocols (depth tracking)

### Zero-Allocation Header Access

- Pre-allocated header objects
- Memory binding without copying
- Type-safe field access
- Reusable across packets

### Runtime Services

- Timestamp handling (multiple formats)
- Protocol registry
- Detail builders for formatted output
- Packet formatters (text, JSON, XML)

------

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Protocol Packs                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ sdk-protocol │  │ sdk-protocol │  │ sdk-protocol │       │
│  │    -tcpip    │  │     -web     │  │    -infra    │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                   sdk-protocol-core                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Dissection  │  │   Packet    │  │     Runtime         │  │
│  │ Framework   │  │ Descriptors │  │     Services        │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                      sdk-common                             │
│              (Memory, Buffers, Utilities)                   │
└─────────────────────────────────────────────────────────────┘
```

------

## Quick Start

Most users should use a protocol pack rather than sdk-protocol-core directly:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.slytechs.sdk</groupId>
            <artifactId>sdk-bom</artifactId>
            <version>3.0.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <!-- Use a protocol pack instead of sdk-protocol-core directly -->
    <dependency>
        <groupId>com.slytechs.sdk</groupId>
        <artifactId>sdk-protocol-tcpip</artifactId>
    </dependency>
</dependencies>
```

### Direct Usage (Advanced)

For framework developers or custom protocol implementations:

```xml
<dependency>
    <groupId>com.slytechs.sdk</groupId>
    <artifactId>sdk-protocol-core</artifactId>
</dependency>
```

------

## Protocol Packs

Protocol packs extend sdk-protocol-core with specific protocol implementations:

| Pack                                                         | Protocols                                         | Use Case                   |
| ------------------------------------------------------------ | ------------------------------------------------- | -------------------------- |
| [sdk-protocol-tcpip](https://github.com/slytechs-repos/sdk-protocol-tcpip) | Ethernet, IPv4/6, TCP, UDP, ICMP, ARP, VLAN, MPLS | Network layer analysis     |
| [sdk-protocol-web](https://github.com/slytechs-repos/sdk-protocol-web) | HTTP, TLS, DNS, QUIC, WebSocket                   | Application layer analysis |
| [sdk-protocol-infra](https://github.com/slytechs-repos/sdk-protocol-infra) | BGP, OSPF, STP, VRRP, LACP, LLDP                  | Infrastructure monitoring  |

------

## Packet Descriptors

The packet descriptor stores dissection results in a compact binary format:

```java
// Access descriptor from packet
PacketDescriptor desc = packet.getPacketDescriptor();

// Check protocol presence via bitmap (O(1) lookup)
if (desc.hasProtocol(CoreProtocol.TCP)) {
    // Get protocol info from inline table
    int tcpOffset = desc.getProtocolOffset(CoreProtocol.TCP);
    int tcpLength = desc.getProtocolLength(CoreProtocol.TCP);
}

// Print descriptor details
System.out.println(desc);
// Output:
// Net Packet Descriptor: cap=74 wire=74 ts=1299012579821
//   Protocol Bitmap = 0x00000015 (ETH IPv4 TCP)
//   Protocol Count = 3
//   Inline Protocol Table:
//     Ethernet: offset=0 length=14
//     IPv4: offset=14 length=20
//     TCP: offset=34 length=40
```

### Descriptor Features

- **Protocol Bitmap** - Fast presence check for common protocols
- **Inline Protocol Table** - Up to 8 protocols without extension
- **Extended Table** - Support for complex packets with 8+ protocols
- **Tunnel Depth** - Track nested protocols (IP-in-IP, Q-in-Q)
- **Timestamp** - Capture timestamp with configurable precision

------

## Core Classes

### Header

Base class for all protocol headers:

```java
public abstract class Header {
    // Bind header to packet data at offset
    void bind(MemorySegment segment, int offset, int length);
    
    // Protocol identification
    int id();
    String name();
    
    // Common operations
    int offset();
    int length();
    byte[] toArray();
}
```

### HeaderAccessor

Interface for accessing headers from packets:

```java
public interface HeaderAccessor {
    // Check presence and bind header
    boolean hasHeader(Header header);
    boolean hasHeader(Header header, int depth);
    
    // Check presence by protocol ID (faster)
    boolean isPresent(int protocolId);
    boolean isPresent(int protocolId, int depth);
    
    // Get header (throws if not present)
    <T extends Header> T getHeader(T header);
    <T extends Header> T getHeader(T header, int depth);
}
```

### Packet

Main packet class implementing HeaderAccessor:

```java
// Pre-allocate headers outside hot path
Ip4 ip4 = new Ip4();
Tcp tcp = new Tcp();

pcap.dispatch(count, packet -> {
    // hasHeader() checks AND binds in one call
    if (packet.hasHeader(ip4)) {
        System.out.println("Source: " + ip4.src());
    }
    
    if (packet.hasHeader(tcp)) {
        System.out.println("Port: " + tcp.dstPort());
    }
});
```

------

## Timestamp Handling

Multiple timestamp formats supported:

```java
// Get timestamp from descriptor
long timestamp = desc.timestamp();
TimestampUnit unit = desc.timestampUnit();

// Convert to different formats
Instant instant = unit.toInstant(timestamp);
long epochMillis = unit.toEpochMilli(timestamp);
long epochMicros = unit.toEpochMicro(timestamp);
long epochNanos = unit.toEpochNano(timestamp);
```

### Supported Units

| Unit          | Resolution   | Use Case            |
| ------------- | ------------ | ------------------- |
| `EPOCH_MILLI` | Milliseconds | Standard captures   |
| `EPOCH_MICRO` | Microseconds | Precise timing      |
| `EPOCH_NANO`  | Nanoseconds  | Hardware timestamps |
| `PCAP_MICRO`  | Microseconds | PCAP file format    |
| `PCAP_NANO`   | Nanoseconds  | PCAPNG file format  |

------

## Installation

### With BOM (Recommended)

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.slytechs.sdk</groupId>
            <artifactId>sdk-bom</artifactId>
            <version>3.0.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>com.slytechs.sdk</groupId>
        <artifactId>sdk-protocol-core</artifactId>
    </dependency>
</dependencies>
```

### Standalone

```xml
<dependency>
    <groupId>com.slytechs.sdk</groupId>
    <artifactId>sdk-protocol-core</artifactId>
    <version>3.0.0</version>
</dependency>
```

------

## Documentation

- [GitHub Wiki](https://github.com/slytechs-repos/sdk-protocol-core/wiki) - User guides
- [Javadocs](https://slytechs-repos.github.io/sdk-protocol-core/) - API documentation
- [SDK BOM](https://github.com/slytechs-repos/sdk-bom) - Version management

------

## Related Projects

| Module                                                       | Description                  |
| ------------------------------------------------------------ | ---------------------------- |
| [sdk-common](https://github.com/slytechs-repos/sdk-common)   | Core memory and utilities    |
| [sdk-protocol-tcpip](https://github.com/slytechs-repos/sdk-protocol-tcpip) | TCP/IP protocol pack         |
| [sdk-protocol-web](https://github.com/slytechs-repos/sdk-protocol-web) | Web protocol pack            |
| [sdk-protocol-infra](https://github.com/slytechs-repos/sdk-protocol-infra) | Infrastructure protocol pack |
| [jnetpcap-api](https://github.com/slytechs-repos/jnetpcap-api) | Packet capture API           |
| [jnetpcap-sdk](https://github.com/slytechs-repos/jnetpcap-sdk) | Complete SDK starter         |

------

## Requirements

- **Java 22+** - Required for Panama FFM
- **sdk-common** - Core utilities (transitive dependency)

------

## License

Licensed under Apache License v2.0. See [LICENSE](https://claude.ai/chat/LICENSE) for details.

------

**Sly Technologies Inc.** - High-performance network analysis solutions

Website: [www.slytechs.com](https://www.slytechs.com/)

------
