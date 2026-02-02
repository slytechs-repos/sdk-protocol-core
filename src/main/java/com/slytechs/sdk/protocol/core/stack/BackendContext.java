/*
 * Apache License, Version 2.0
 * 
 * Copyright 2025 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.sdk.protocol.core.stack;

import com.slytechs.sdk.protocol.core.descriptor.DescriptorType;

/**
 * Backend capabilities and constraints for Spec resolution.
 * 
 * <p>
 * BackendContext provides information about the capture backend (jnetpcap,
 * jnetworks, etc.) that is used during the resolve stage to validate and
 * adjust configurations. Backends may have different supported descriptor
 * types, hardware capabilities, and constraints.
 * </p>
 * 
 * <h2>Usage</h2>
 * 
 * <pre>{@code
 * // Backend provides its context
 * BackendContext context = new BackendContext()
 *     .nativeDescriptorType(DescriptorType.PCAP_PACKED)
 *     .supportsZeroCopy(true)
 *     .maxPacketSize(65535);
 * 
 * // Resolve policy against backend capabilities
 * ResolvedPacketPolicy resolved = PacketPolicyService.resolve(policy, context);
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see PacketPolicyService
 */
public class BackendContext {

    private DescriptorType nativeDescriptorType = DescriptorType.PCAP_PACKED;
    private boolean supportsZeroCopy = true;
    private boolean supportsMemoryCopy = true;
    private long maxPacketSize = 65535;
    private long maxPoolCapacity = Integer.MAX_VALUE;
    private String backendName = "default";

    public BackendContext() {
    }

    /**
     * Returns the native descriptor type used by this backend.
     *
     * @return native descriptor type
     */
    public DescriptorType nativeDescriptorType() {
        return nativeDescriptorType;
    }

    /**
     * Sets the native descriptor type.
     *
     * @param type the native descriptor type
     * @return this for chaining
     */
    public BackendContext nativeDescriptorType(DescriptorType type) {
        this.nativeDescriptorType = type;
        return this;
    }

    /**
     * Returns whether zero-copy is supported.
     *
     * @return true if zero-copy supported
     */
    public boolean supportsZeroCopy() {
        return supportsZeroCopy;
    }

    /**
     * Sets whether zero-copy is supported.
     *
     * @param supported true if supported
     * @return this for chaining
     */
    public BackendContext supportsZeroCopy(boolean supported) {
        this.supportsZeroCopy = supported;
        return this;
    }

    /**
     * Returns whether memory-copy is supported.
     *
     * @return true if memory-copy supported
     */
    public boolean supportsMemoryCopy() {
        return supportsMemoryCopy;
    }

    /**
     * Sets whether memory-copy is supported.
     *
     * @param supported true if supported
     * @return this for chaining
     */
    public BackendContext supportsMemoryCopy(boolean supported) {
        this.supportsMemoryCopy = supported;
        return this;
    }

    /**
     * Returns the maximum packet size supported.
     *
     * @return max packet size in bytes
     */
    public long maxPacketSize() {
        return maxPacketSize;
    }

    /**
     * Sets the maximum packet size.
     *
     * @param size max size in bytes
     * @return this for chaining
     */
    public BackendContext maxPacketSize(long size) {
        this.maxPacketSize = size;
        return this;
    }

    /**
     * Returns the maximum freeListPool capacity supported.
     *
     * @return max freeListPool capacity
     */
    public long maxPoolCapacity() {
        return maxPoolCapacity;
    }

    /**
     * Sets the maximum freeListPool capacity.
     *
     * @param capacity max capacity
     * @return this for chaining
     */
    public BackendContext maxPoolCapacity(long capacity) {
        this.maxPoolCapacity = capacity;
        return this;
    }

    /**
     * Returns the backend name.
     *
     * @return backend name
     */
    public String backendName() {
        return backendName;
    }

    /**
     * Sets the backend name.
     *
     * @param name backend name
     * @return this for chaining
     */
    public BackendContext backendName(String name) {
        this.backendName = name;
        return this;
    }

    @Override
    public String toString() {
        return String.format("BackendContext[%s, native=%s, zeroCopy=%s, maxPacket=%d]",
                backendName, nativeDescriptorType, supportsZeroCopy, maxPacketSize);
    }
}