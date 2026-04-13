/*
 * Apache License, Version 2.0
 * 
 * Copyright 2025 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.protocol.core.hash;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;

/**
 * Calculates hash values for packet distribution across channels.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface HashCalculator {

    /**
     * Calculate hash from a ByteBuffer. Uses buffer's position and limit
     * to determine packet boundaries.
     *
     * @param buffer the packet data
     * @return the calculated hash value
     */
    int calculate(ByteBuffer buffer);

    /**
     * Calculate hash from a native memory segment.
     *
     * @param segment the memory segment containing packet data
     * @param offset  byte offset to start of packet within segment
     * @return the calculated hash value
     */
    int calculate(MemorySegment segment, long offset);

    /**
     * The hash type this calculator implements.
     *
     * @return the hash type constant
     */
    int hashType();

    /**
     * Get a hash calculator for the specified hash type.
     *
     * @param hashType the hash type constant
     * @return the hash calculator
     * @throws IllegalArgumentException if hash type is unknown
     */
    static HashCalculator of(int hashType) {
        return HashCalculators.of(hashType);
    }
}