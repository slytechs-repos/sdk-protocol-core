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
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Abstract base implementation of FlagSet providing common functionality.
 */
public abstract class AbstractFlagSet<F extends Flag> implements FlagSet<F> {
    protected final long value;
    protected final Map<String, F> flagsByName;
    
    protected AbstractFlagSet(long value, Collection<F> flags) {
        this.value = value;
        this.flagsByName = flags.stream()
            .collect(Collectors.toMap(Flag::name, f -> f, (f1, f2) -> {
                throw new IllegalArgumentException("Duplicate flag name: " + f1.name());
            }));
    }
    
    @Override
    public long value() {
        return value;
    }
    
    @Override
    public Collection<F> getAllFlags() {
        return Collections.unmodifiableCollection(flagsByName.values());
    }
    
    @Override
    public Optional<F> getFlag(String name) {
        return Optional.ofNullable(flagsByName.get(name));
    }
    
    @Override
    public boolean isSet(F flag) {
        return (value & flag.mask()) == flag.mask();
    }
    
    @Override
    public boolean areAllSet(F... flags) {
        for (F flag : flags) {
            if (!isSet(flag)) return false;
        }
        return true;
    }
    
    @Override
    public boolean isAnySet(F... flags) {
        for (F flag : flags) {
            if (isSet(flag)) return true;
        }
        return false;
    }
    
    @Override
    public long getValue(F flag) {
        return (value & flag.mask()) >>> flag.position();
    }
    
    @Override
    public Set<F> getSetFlags() {
        return flagsByName.values().stream()
            .filter(this::isSet)
            .collect(Collectors.toSet());
    }
    
    @Override
    public FlagSet<F> withFlag(F flag) {
        return withValue(value | flag.mask());
    }
    
    @Override
    public FlagSet<F> withoutFlag(F flag) {
        return withValue(value & ~flag.mask());
    }
    
    @Override
    public FlagSet<F> withValue(F flag, long flagValue) {
        if (!flag.isValidValue(flagValue)) {
            throw new IllegalArgumentException("Invalid value " + flagValue + " for flag " + flag.name());
        }
        long newValue = (value & ~flag.mask()) | ((flagValue << flag.position()) & flag.mask());
        return withValue(newValue);
    }
    
    @Override
    public FlagSet<F> withFlags(F... flags) {
        long newValue = value;
        for (F flag : flags) {
            newValue |= flag.mask();
        }
        return withValue(newValue);
    }
    
    @Override
    public FlagSet<F> withoutFlags(F... flags) {
        long newValue = value;
        for (F flag : flags) {
            newValue &= ~flag.mask();
        }
        return withValue(newValue);
    }
    
    @Override
    public FlagSet<F> and(FlagSet<F> other) {
        return withValue(this.value & other.value());
    }
    
    @Override
    public FlagSet<F> or(FlagSet<F> other) {
        return withValue(this.value | other.value());
    }
    
    @Override
    public FlagSet<F> xor(FlagSet<F> other) {
        return withValue(this.value ^ other.value());
    }
    
    @Override
    public FlagSet<F> not() {
        return withValue(~value);
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof FlagSet)) return false;
        FlagSet<?> other = (FlagSet<?>) obj;
        return value == other.value();
    }
    
    @Override
    public int hashCode() {
        return Long.hashCode(value);
    }
    
    @Override
    public String toString() {
        if (value == 0) {
            return "[]";
        }
        
        Set<F> setFlags = getSetFlags();
        if (setFlags.isEmpty()) {
            return "[0x" + Long.toHexString(value) + "]";
        }
        
        return setFlags.stream()
            .map(flag -> {
                if (flag.isSingleBit()) {
                    return flag.name();
                } else {
                    return flag.name() + "=" + getValue(flag);
                }
            })
            .collect(Collectors.joining(", ", "[", "]"));
    }
}