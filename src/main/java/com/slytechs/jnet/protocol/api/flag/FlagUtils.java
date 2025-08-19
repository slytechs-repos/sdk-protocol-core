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
package com.slytechs.jnet.protocol.api.flag;

/**
 * Utility class for creating flag implementations.
 * Since enums cannot extend classes in Java, this provides helper methods
 * for implementing the Flag interface in enum constants.
 */
public final class FlagUtils {
    
    private FlagUtils() {} // Utility class
    
    /**
     * Creates a single-bit flag mask at the specified position.
     */
    public static long singleBitMask(int position) {
        return bitMask(position, 1);
    }
    
    /**
     * Creates a multi-bit flag mask at the specified position with given width.
     */
    public static long bitMask(int position, int width) {
        if (position < 0 || position > 63) {
            throw new IllegalArgumentException("Position must be between 0 and 63");
        }
        if (width < 1 || width > 64 || position + width > 64) {
            throw new IllegalArgumentException("Invalid width or position+width exceeds 64 bits");
        }
        return ((1L << width) - 1) << position;
    }
    
    /**
     * Validates that a mask represents contiguous bits and returns the position.
     */
    public static int validateMaskAndGetPosition(long mask) {
        if (mask == 0) {
            throw new IllegalArgumentException("Mask cannot be zero");
        }
        
        int position = Long.numberOfTrailingZeros(mask);
        long shifted = mask >>> position;
        
        // Check if mask represents contiguous bits
        if ((shifted & (shifted + 1)) != 0) {
            throw new IllegalArgumentException("Mask must represent contiguous bits: " + Long.toHexString(mask));
        }
        
        return position;
    }
}