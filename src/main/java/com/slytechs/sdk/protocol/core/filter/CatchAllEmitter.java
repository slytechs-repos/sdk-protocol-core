package com.slytechs.sdk.protocol.core.filter;

import java.util.function.Consumer;

import com.slytechs.sdk.common.util.Registration;
import com.slytechs.sdk.protocol.core.filter.FilterDsl.Emitter;

// Package-private
final class CatchAllEmitter implements Emitter {

    private static final String MSG = 
        "PacketFilter.ALL cannot be combined with other filters";

    @Override public Emitter protocol(String protocol) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter field(String name, int offset, int bits, Op op, long value) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter field(String name, int offset, int bits, Op op, byte[] value) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter and() { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter or() { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter group() { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter endGroup() { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter host(String ip) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter host(byte[] ip) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter srcHost(String ip) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter dstHost(String ip) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter net(String cidr) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter srcNet(String cidr) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter dstNet(String cidr) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter port(int port) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter srcPort(int port) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter dstPort(int port) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter portRange(int start, int end) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter length(Op op, int len) { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter broadcast() { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter multicast() { throw new UnsupportedOperationException(MSG); }
    @Override public Emitter protocol(String protocol, int depth) { throw new UnsupportedOperationException(MSG); }

    @Override
    public Emitter onExpressionAction(Consumer<String> debugAction, Consumer<Registration> registration) {
        throw new UnsupportedOperationException(MSG);
    }

    @Override
    public String expression() {
        return PacketFilter.KEYWORD_ALL;
    }
}