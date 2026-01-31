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

//UdpFilter.java
public interface UdpFilter {

	static UdpBuilder of() {
		return b -> b;
	}

	static UdpBuilder srcPort(int port) {
		return of().srcPort(port);
	}

	static UdpBuilder dstPort(int port) {
		return of().dstPort(port);
	}

	static UdpBuilder port(int port) {
		return of().port(port);
	}

	interface UdpBuilder extends HeaderFilter {

		default UdpBuilder srcPort(int port) {
			return b -> this.emit(b).and().field("udp.srcPort", 0, 16, Op.EQ, port);
		}

		default UdpBuilder dstPort(int port) {
			return b -> this.emit(b).and().field("udp.dstPort", 2, 16, Op.EQ, port);
		}

		default UdpBuilder port(int port) {
			return b -> this.emit(b)
					.and()
					.group()
					.field("udp.srcPort", 0, 16, Op.EQ, port)
					.or()
					.field("udp.dstPort", 2, 16, Op.EQ, port)
					.endGroup();
		}
	}
}