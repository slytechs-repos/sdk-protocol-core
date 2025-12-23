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
package com.slytechs.sdk.protocol.core.flag;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;

/**
 * Base interface for flag containers that manage collections of flags.
 * Provides operations for manipulating bitmasks using flag definitions.
 */
public interface FlagSet<F extends Flag> {
    
    /**
     * Returns the current bitmask value.
     */
    long value();
    
    /**
     * Returns all flag definitions for this flag set.
     */
    Collection<F> getAllFlags();
    
    /**
     * Returns the flag definition by name.
     */
    Optional<F> getFlag(String name);
    
    /**
     * Tests if the specified flag is set.
     */
    boolean isSet(F flag);
    
    /**
     * Tests if all specified flags are set.
     */
    boolean areAllSet(F... flags);
    
    /**
     * Tests if any of the specified flags are set.
     */
    boolean isAnySet(F... flags);
    
    /**
     * Returns the value of a flag (for bit fields, returns the field value).
     */
    long getValue(F flag);
    
    /**
     * Returns all currently set flags.
     */
    Set<F> getSetFlags();
    
    /**
     * Creates a new FlagSet with the specified flag set.
     */
    FlagSet<F> withFlag(F flag);
    
    /**
     * Creates a new FlagSet with the specified flag cleared.
     */
    FlagSet<F> withoutFlag(F flag);
    
    /**
     * Creates a new FlagSet with the specified flag set to the given value.
     */
    FlagSet<F> withValue(F flag, long value);
    
    /**
     * Creates a new FlagSet with multiple flags set.
     */
    FlagSet<F> withFlags(F... flags);
    
    /**
     * Creates a new FlagSet with multiple flags cleared.
     */
    FlagSet<F> withoutFlags(F... flags);
    
    /**
     * Creates a new FlagSet with the specified bitmask value.
     */
    FlagSet<F> withValue(long value);
    
    /**
     * Performs a bitwise AND operation with another flag set.
     */
    FlagSet<F> and(FlagSet<F> other);
    
    /**
     * Performs a bitwise OR operation with another flag set.
     */
    FlagSet<F> or(FlagSet<F> other);
    
    /**
     * Performs a bitwise XOR operation with another flag set.
     */
    FlagSet<F> xor(FlagSet<F> other);
    
    /**
     * Returns the bitwise NOT of this flag set.
     */
    FlagSet<F> not();
}