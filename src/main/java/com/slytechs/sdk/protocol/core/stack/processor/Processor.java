package com.slytechs.sdk.protocol.core.stack.processor;

import java.util.function.Consumer;

import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.ProtocolObject;
import com.slytechs.sdk.protocol.core.stack.Analyzer;
import com.slytechs.sdk.protocol.core.stack.LayerContext;
import com.slytechs.sdk.protocol.core.stack.ProcessorContext;
import com.slytechs.sdk.protocol.core.stack.ProcessorStats;

public interface Processor {
    
    /**
     * Packet-centric processing path.
     * 
     * Lower layers: Parse header, add context, route to next, return Packet
     * Upper layers: Return passed packet (processing stops at packet boundary)
     * 
     * @param packet The packet being processed
     * @param ctx Processing context with advancing payload view
     * @param layer Layer context from previous processor (may be null for root)
     * @return Packet if processing complete, null if consumed/buffered
     */
    Packet processPacket(Packet packet, ProcessorContext ctx, LayerContext layer);
    
    /**
     * Protocol-centric processing path.
     * 
     * Returns protocol-specific object based on this processor's output type.
     * 
     * @param ctx Processing context with advancing payload view
     * @param layer Layer context from previous processor (may be null for root)
     * @return ProtocolObject if processing complete, null if consumed/buffered
     */
    ProtocolObject processProtocol(ProcessorContext ctx, LayerContext layer);
    
    /**
     * Attach analyzer for token emission.
     * Null disables analysis (fully pruned).
     */
    void setAnalyzer(Analyzer analyzer);
    
    /**
     * Timer callback for timeout eviction.
     */
    void tick(long nowNs);
    
    /**
     * Drain any buffered state (end of capture).
     */
    void flush(Consumer<ProtocolObject> emit);
    
    /**
     * Statistics.
     */
    ProcessorStats stats();
}