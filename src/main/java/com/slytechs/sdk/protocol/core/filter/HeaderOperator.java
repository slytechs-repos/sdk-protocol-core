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
 * A unary operator on a header filter builder that may throw
 * {@link FilterException}.
 * <p>
 * This is the checked-exception equivalent of
 * {@link java.util.function.UnaryOperator} used throughout the filter DSL to
 * allow header-specific field conditions to propagate validation errors at
 * filter construction time.
 * </p>
 * <p>
 * Typically used as a lambda parameter in protocol methods on
 * {@link PacketFilter} and {@link ProtocolFilter}:
 *
 * {@snippet :
 * // The lambda v -> v.vid(100) is a HeaderOperator<VlanBuilder>
 * ProtocolFilter dsl = PacketFilter.vlan(v -> v.vid(100));
 *
 * // Validation errors propagate as checked FilterException
 * ProtocolFilter dsl = PacketFilter.vlan(v -> v.vid(5000)); // throws FilterException
 * }
 *
 * @param <T> the type of header filter builder (e.g.
 *            {@link TcpFilter.TcpBuilder}, {@link VlanFilter.VlanBuilder})
 * @see PacketFilter
 * @see ProtocolFilter
 * @see FilterException
 */
@FunctionalInterface
public interface HeaderOperator<T> {

	/**
	 * Applies header-specific conditions to the given builder.
	 *
	 * @param header the header filter builder to configure
	 * @return the configured builder (typically the same instance for chaining)
	 * @throws FilterException if any field value is invalid
	 */
	T apply(T header) throws FilterException;
}