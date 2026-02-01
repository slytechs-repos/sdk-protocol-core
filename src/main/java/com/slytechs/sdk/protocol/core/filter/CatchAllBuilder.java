package com.slytechs.sdk.protocol.core.filter;

import java.util.function.Consumer;

import com.slytechs.sdk.common.util.Registration;

// Package-private
final class CatchAllBuilder implements FilterBuilder {

    private static final String MSG = 
        "PacketFilter.ALL cannot be combined with other filters";

    @Override public FilterBuilder protocol(String protocol) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder field(String name, int offset, int bits, Op op, long value) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder field(String name, int offset, int bits, Op op, byte[] value) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder and() { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder or() { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder group() { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder endGroup() { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder host(String ip) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder host(byte[] ip) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder srcHost(String ip) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder dstHost(String ip) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder net(String cidr) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder srcNet(String cidr) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder dstNet(String cidr) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder port(int port) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder srcPort(int port) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder dstPort(int port) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder portRange(int start, int end) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder length(Op op, int len) { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder broadcast() { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder multicast() { throw new UnsupportedOperationException(MSG); }
    @Override public FilterBuilder protocol(String protocol, int depth) { throw new UnsupportedOperationException(MSG); }

    @Override
    public FilterBuilder onExpressionAction(Consumer<String> debugAction, Consumer<Registration> registration) {
        throw new UnsupportedOperationException(MSG);
    }

    @Override
    public String expression() {
        return PacketFilter.KEYWORD_ALL;
    }
}