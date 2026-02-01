/*
 * Copyright 2005-2026 Sly Technologies Inc.
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
package com.slytechs.sdk.protocol.core.filter;

/**
 * Base functional interface for protocol-specific header filter builders.
 * <p>
 * A {@code HeaderDsl} emits field-level filter conditions into a
 * {@link Emitter}. Each protocol-specific filter (e.g.
 * {@link VlanFilter.VlanDsl}, {@link TcpFilter.TcpDsl}) extends this
 * interface and adds typed methods for that protocol's header fields.
 * </p>
 * <p>
 * {@code HeaderDsl} instances are composable via functional chaining. Each
 * builder method returns a new {@code HeaderDsl} that first emits the
 * previous conditions, then appends its own. This enables fluent construction
 * without mutable state:
 *
 * {@snippet :
 * // Each call wraps the previous, building a chain of emit() calls
 * VlanDsl filter = VlanFilter.vid(100).pcp(5);
 * }
 * </p>
 * <p>
 * {@code HeaderDsl} is also the common type accepted by
 * {@link PacketDsl#anyOf(HeaderDsl...)} for OR grouping across
 * different header conditions of the same protocol layer.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see PacketDsl
 * @see Emitter
 */
@FunctionalInterface
public interface HeaderDsl extends FilterDsl {

    /**
     * Emits this filter's conditions into the given builder.
     * <p>
     * Implementations append protocol-specific field conditions (e.g. port
     * matches, address comparisons, flag checks) to the builder's internal
     * representation. The builder is returned to allow continued chaining.
     * </p>
     *
     * @param b the filter builder to emit conditions into
     * @return the same builder instance, for chaining
     */
    Emitter emit(Emitter b);
}