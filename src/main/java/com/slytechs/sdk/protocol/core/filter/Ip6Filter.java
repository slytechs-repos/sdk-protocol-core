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

/**
 * Filter for IPv6 header fields.
 * 
 * <p>
 * IPv6 Header (40 bytes fixed):
 * 
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version| Traffic Class |           Flow Label                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Payload Length        |  Next Header  |   Hop Limit   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                         Source Address                        +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                      Destination Address                      +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 */
//Ip6Filter.java
public interface Ip6Filter {

	static Ip6Builder of() {
		return b -> b;
	}

	static Ip6Builder src(byte[] addr) {
		return of().src(addr);
	}

	static Ip6Builder dst(byte[] addr) {
		return of().dst(addr);
	}

	static Ip6Builder nextHeader(int protocol) {
		return of().nextHeader(protocol);
	}

	static Ip6Builder hopLimit(int limit) {
		return of().hopLimit(limit);
	}

	static Ip6Builder flowLabel(int label) {
		return of().flowLabel(label);
	}

	interface Ip6Builder extends HeaderFilter {

		default Ip6Builder src(byte[] addr) {
			return b -> this.emit(b).and().field("ip6.src", 8, 128, Op.EQ, addr);
		}

		default Ip6Builder dst(byte[] addr) {
			return b -> this.emit(b).and().field("ip6.dst", 24, 128, Op.EQ, addr);
		}

		default Ip6Builder nextHeader(int protocol) {
			return b -> this.emit(b).and().field("ip6.nextHeader", 6, 8, Op.EQ, protocol);
		}

		default Ip6Builder hopLimit(int limit) {
			return b -> this.emit(b).and().field("ip6.hopLimit", 7, 8, Op.EQ, limit);
		}

		default Ip6Builder flowLabel(int label) {
			return b -> this.emit(b).and().field("ip6.flowLabel", 1, 20, Op.EQ, label);
		}
	}
}