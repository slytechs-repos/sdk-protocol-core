package com.slytechs.sdk.protocol.core.filter;

import java.util.function.Consumer;

import com.slytechs.sdk.common.util.Registration;

public interface FilterBuilder {

    enum Op { EQ, NE, LT, LE, GT, GE, MASK, IN }
    
    // Host/Network
    FilterBuilder host(String ip);
    FilterBuilder host(byte[] ip);
    FilterBuilder srcHost(String ip);
    FilterBuilder dstHost(String ip);
    FilterBuilder net(String cidr);
    FilterBuilder srcNet(String cidr);
    FilterBuilder dstNet(String cidr);

    // Port (protocol-agnostic)
    FilterBuilder port(int port);
    FilterBuilder srcPort(int port);
    FilterBuilder dstPort(int port);
    FilterBuilder portRange(int start, int end);

    // Length
    FilterBuilder length(Op op, int len);

    // Traffic type
    FilterBuilder broadcast();
    FilterBuilder multicast();
    // Protocol presence
    FilterBuilder protocol(String protocol);
    FilterBuilder protocol(String protocol, int depth);

    // Field comparisons
    FilterBuilder field(String name, int offset, int bits, Op op, long value);
    FilterBuilder field(String name, int offset, int bits, Op op, byte[] value);

    // Logical structure
    FilterBuilder and();
    FilterBuilder or();
    FilterBuilder group();
    FilterBuilder endGroup();
    
    FilterBuilder onExpressionAction(Consumer<String> debugAction, Consumer<Registration> registration);

    // Build result
    String expression();
}