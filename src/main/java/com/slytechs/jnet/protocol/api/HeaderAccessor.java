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
package com.slytechs.jnet.protocol.api;

/**
 * Interface for accessing and binding higher-level protocol headers. If the header is present,
 * it binds a reusable Header object to the packet data.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface HeaderAccessor {
	HeaderAccessor EMPTY = new HeaderAccessor() {};

	default Header getHeader(int id) throws HeaderNotFoundException {
		return getHeader(id, 0);
	}

	default Header getHeader(int id, int depth) throws HeaderNotFoundException {
		throw new HeaderNotFoundException();
	}

	default <T extends Header> T getHeader(T header) throws HeaderNotFoundException {
		return getHeader(header, 0);
	}

	default <T extends Header> T getHeader(T header, int depth) throws HeaderNotFoundException {
		throw new HeaderNotFoundException();
	}

	default boolean hasHeader(Header header) {
		return hasHeader(header, 0);
	}

	default boolean hasHeader(Header header, int depth) {
		return false;
	}

	default boolean isPresent(int id) {
		return isPresent(id, 0);
	}

	default boolean isPresent(int id, int depth) {
		return false;
	}
}