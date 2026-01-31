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

//TcpFilter.java
public interface TcpFilter {

	static TcpBuilder of() {
		return b -> b;
	}

	static TcpBuilder srcPort(int port) {
		return of().srcPort(port);
	}

	static TcpBuilder dstPort(int port) {
		return of().dstPort(port);
	}

	static TcpBuilder port(int port) {
		return of().port(port);
	}

	static TcpBuilder flags(int flags) {
		return of().flags(flags);
	}

	static TcpBuilder flagSyn() {
		return of().flagSyn();
	}

	static TcpBuilder flagAck() {
		return of().flagAck();
	}

	static TcpBuilder flagFin() {
		return of().flagFin();
	}

	static TcpBuilder flagRst() {
		return of().flagRst();
	}

	interface TcpBuilder extends HeaderFilter {

		default TcpBuilder srcPort(int port) {
			return b -> this.emit(b).and().field("tcp.srcPort", 0, 16, Op.EQ, port);
		}

		default TcpBuilder dstPort(int port) {
			return b -> this.emit(b).and().field("tcp.dstPort", 2, 16, Op.EQ, port);
		}

		default TcpBuilder port(int port) {
			return b -> this.emit(b)
					.and()
					.group()
					.field("tcp.srcPort", 0, 16, Op.EQ, port)
					.or()
					.field("tcp.dstPort", 2, 16, Op.EQ, port)
					.endGroup();
		}

		default TcpBuilder flags(int flags) {
			return b -> this.emit(b).and().field("tcp.flags", 13, 8, Op.EQ, flags);
		}

		default TcpBuilder flagSyn() {
			return b -> this.emit(b).and().field("tcp.flags.syn", 13, 8, Op.MASK, 0x02);
		}

		default TcpBuilder flagAck() {
			return b -> this.emit(b).and().field("tcp.flags.ack", 13, 8, Op.MASK, 0x10);
		}

		default TcpBuilder flagFin() {
			return b -> this.emit(b).and().field("tcp.flags.fin", 13, 8, Op.MASK, 0x01);
		}

		default TcpBuilder flagRst() {
			return b -> this.emit(b).and().field("tcp.flags.rst", 13, 8, Op.MASK, 0x04);
		}
	}
}