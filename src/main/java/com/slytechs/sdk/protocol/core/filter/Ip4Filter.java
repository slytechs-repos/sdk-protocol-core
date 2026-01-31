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

import com.slytechs.sdk.protocol.core.filter.FilterBuilder.Op;

//Ip4Filter.java
public interface Ip4Filter {

	static Ip4Builder of() {
		return b -> b;
	}

	static Ip4Builder src(int addr) {
		return of().src(addr);
	}

	static Ip4Builder src(byte[] addr) {
		return of().src(addr);
	}

	static Ip4Builder dst(int addr) {
		return of().dst(addr);
	}

	static Ip4Builder dst(byte[] addr) {
		return of().dst(addr);
	}

	static Ip4Builder protocol(int proto) {
		return of().protocol(proto);
	}

	static Ip4Builder ttl(int ttl) {
		return of().ttl(ttl);
	}

	interface Ip4Builder extends HeaderFilter {

		default Ip4Builder src(int addr) {
			return b -> this.emit(b).and().field("ip4.src", 12, 32, Op.EQ, addr);
		}

		default Ip4Builder src(byte[] addr) {
			return b -> this.emit(b).and().field("ip4.src", 12, 32, Op.EQ, addr);
		}

		default Ip4Builder dst(int addr) {
			return b -> this.emit(b).and().field("ip4.dst", 16, 32, Op.EQ, addr);
		}

		default Ip4Builder dst(byte[] addr) {
			return b -> this.emit(b).and().field("ip4.dst", 16, 32, Op.EQ, addr);
		}

		default Ip4Builder protocol(int proto) {
			return b -> this.emit(b).and().field("ip4.proto", 9, 8, Op.EQ, proto);
		}

		default Ip4Builder ttl(int ttl) {
			return b -> this.emit(b).and().field("ip4.ttl", 8, 8, Op.EQ, ttl);
		}
	}
}