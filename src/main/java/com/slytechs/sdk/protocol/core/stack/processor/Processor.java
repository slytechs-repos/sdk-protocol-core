/*
 * Sly Technologies Free License
 * 
 * Copyright 2025 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.sdk.protocol.core.stack.processor;

import java.util.function.Consumer;

import com.slytechs.sdk.protocol.core.Packet;
import com.slytechs.sdk.protocol.core.ProtocolObject;
import com.slytechs.sdk.protocol.core.stack.Analyzer;
import com.slytechs.sdk.protocol.core.stack.LayerContext;
import com.slytechs.sdk.protocol.core.stack.ProcessorContext;
import com.slytechs.sdk.protocol.core.stack.ProcessorStats;

/**
 * Protocol processor in the processing tree.
 * 
 * <p>
 * Processors form a tree structure with routing branches. Each processor
 * handles a specific protocol, parsing headers, managing state (flow tables,
 * reassembly buffers), and routing to downstream processors.
 * </p>
 * 
 * <h2>Dual Processing Paths</h2>
 * <ul>
 * <li>{@link #processPacket} - Returns Packet (jNetPcap, PacketStreams)</li>
 * <li>{@link #processProtocol} - Returns ProtocolObject (ProtocolStreams)</li>
 * </ul>
 * 
 * <h2>Hot Path Rules</h2>
 * <ul>
 * <li>No object allocation - rebind, freeListPool, reuse</li>
 * <li>No exceptions - increment counters for errors</li>
 * <li>No callbacks - direct method calls only</li>
 * <li>No locks - single-threaded per ProcessorTree</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface Processor {

    // =========================================================================
    // Processing Methods
    // =========================================================================
    
    /**
     * Packet-centric processing path.
     * 
     * <p>
     * Used by jNetPcap (always) and jNetWorks PacketStreams.
     * </p>
     * <ul>
     * <li>Lower layers: Parse header, add context, route to next, return Packet</li>
     * <li>Upper layers: Return passed packet (processing stops at packet boundary)</li>
     * </ul>
     * 
     * @param packet The packet being processed
     * @param ctx    Processing context with advancing payload view
     * @param layer  Layer context from previous processor (may be null for root)
     * @return Packet if processing complete, null if consumed/buffered
     */
    Packet processPacket(Packet packet, ProcessorContext ctx, LayerContext layer);
    
    /**
     * Protocol-centric processing path.
     * 
     * <p>
     * Used by jNetWorks DataStreams and ProtocolStreams.
     * Returns protocol-specific object based on this processor's output type.
     * </p>
     * 
     * @param ctx   Processing context with advancing payload view
     * @param layer Layer context from previous processor (may be null for root)
     * @return ProtocolObject if processing complete, null if consumed/buffered
     */
    ProtocolObject processProtocol(ProcessorContext ctx, LayerContext layer);

    // =========================================================================
    // Analyzer Attachment
    // =========================================================================
    
    /**
     * Attaches an analyzer for token emission.
     * 
     * <p>
     * If analyzer is null, analysis is fully pruned (zero cost).
     * The analyzer is called after header parsing, before routing.
     * </p>
     *
     * @param analyzer the analyzer, or null to disable
     */
    void setAnalyzer(Analyzer analyzer);

    // =========================================================================
    // Timer and Flush
    // =========================================================================
    
    /**
     * Timer callback for timeout eviction.
     * 
     * <p>
     * Called periodically to evict stale entries from state tables
     * (flow tables, reassembly buffers, etc.).
     * </p>
     *
     * @param nowNs current timestamp in nanoseconds
     */
    void tick(long nowNs);
    
    /**
     * Drains any buffered state (end of capture).
     * 
     * <p>
     * Called when capture ends to emit any incomplete reassembly,
     * pending flows, etc.
     * </p>
     *
     * @param emit consumer for emitted protocol objects
     */
    void flush(Consumer<ProtocolObject> emit);

    // =========================================================================
    // State Management
    // =========================================================================
    
    /**
     * Clears all processor state.
     * 
     * <p>
     * Resets flow tables, reassembly buffers, and any other stateful data.
     * Use when jumping to a new position in a capture file.
     * </p>
     */
    void clearState();
    
    /**
     * Clears state for a specific flow.
     *
     * @param flowHash the flow hash to clear
     */
    default void clearFlow(long flowHash) {
        // Default: no-op, override in stateful processors
    }
    
    /**
     * Clears state older than the specified timestamp.
     * 
     * <p>
     * Age-based eviction for state tables.
     * </p>
     *
     * @param timestampNs cutoff timestamp in nanoseconds
     */
    default void clearOlderThan(long timestampNs) {
        // Default: no-op, override in stateful processors
    }

    // =========================================================================
    // Statistics
    // =========================================================================
    
    /**
     * Gets processor statistics.
     *
     * @return the statistics
     */
    ProcessorStats stats();
}