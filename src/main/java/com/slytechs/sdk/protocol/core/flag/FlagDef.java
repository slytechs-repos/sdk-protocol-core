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

/**
 * Base implementation for flag enums. Enums should store this and delegate to it.
 */
public class FlagDef implements Flag {
    private final String name;
    private final long mask;
    private final int position;
    
    public FlagDef(String name, int position) {
        this(name, position, 1);
    }
    
    public FlagDef(String name, int position, int width) {
        this.name = name;
        this.position = position;
        this.mask = FlagUtils.bitMask(position, width);
    }
    
    public FlagDef(String name, long mask) {
        this.name = name;
        this.mask = mask;
        this.position = FlagUtils.validateMaskAndGetPosition(mask);
    }
    
    @Override
    public String name() {
        return name;
    }
    
    @Override
    public long mask() {
        return mask;
    }
    
    @Override
    public int position() {
        return position;
    }
    
    @Override
    public String toString() {
        return name;
    }
}