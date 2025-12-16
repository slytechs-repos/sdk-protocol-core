package com.slytechs.jnet.protocol.api;

import com.slytechs.jnet.protocol.api.descriptor.TransmitControl;

enum NoOpTransmitControl implements TransmitControl {
    INSTANCE;
    
    @Override
    public TransmitControl setTxPort(int port) { return this; }
    @Override
    public TransmitControl setTxEnabled(boolean enabled) { return this; }
    @Override
    public TransmitControl setTxImmediate(boolean immediate) { return this; }
    @Override
    public TransmitControl setTxCrcRecalc(boolean recalc) { return this; }
    @Override
    public TransmitControl setTxTimestampSync(boolean sync) { return this; }
    
    @Override
    public int txPort() { return 0; }
    @Override
    public boolean isTxEnabled() { return false; }
    @Override
    public boolean isTxImmediate() { return false; }
    @Override
    public boolean isTxCrcRecalc() { return false; }
    @Override
    public boolean isTxTimestampSync() { return false; }
}