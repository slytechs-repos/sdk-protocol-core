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
package com.slytechs.sdk.protocol.core.stack;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * Functional interface for memory allocation.
 * 
 * <p>
 * Used by {@link FactoryCopyPacketPolicy} to allow custom memory allocation
 * strategies. Can be implemented with Arena, direct buffers, or any other
 * memory source.
 * </p>
 * 
 * <h2>Example Implementations</h2>
 * <pre>{@code
 * // Arena-based (confined)
 * MemoryAllocator confined = size -> Arena.ofConfined().allocate(size);
 * 
 * // Arena-based (shared)
 * Arena sharedArena = Arena.ofShared();
 * MemoryAllocator shared = sharedArena::allocate;
 * 
 * // Global arena
 * MemoryAllocator global = size -> Arena.global().allocate(size);
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
@FunctionalInterface
public interface MemoryAllocator {

    /**
     * Allocates a memory segment of the specified size.
     *
     * @param size the size in bytes
     * @return allocated memory segment
     */
    MemorySegment allocate(long size);

    /**
     * Returns an allocator that uses the global arena.
     * Memory persists for the lifetime of the JVM.
     *
     * @return global arena allocator
     */
    static MemoryAllocator global() {
        return size -> Arena.global().allocate(size);
    }

    /**
     * Returns an allocator that uses a shared arena.
     * Memory can be accessed from multiple threads.
     *
     * @return shared arena allocator
     */
    static MemoryAllocator shared() {
        Arena arena = Arena.ofShared();
        return arena::allocate;
    }

    /**
     * Returns an allocator that uses confined arenas.
     * Each allocation gets its own arena (careful: many small allocations).
     *
     * @return confined arena allocator
     */
    static MemoryAllocator confined() {
        return size -> Arena.ofConfined().allocate(size);
    }
}