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

public interface EthernetFilter {

	static EthernetBuilder of() {
		return b -> b;
	}

	static EthernetBuilder dst(byte[] mac) {
		return of().dst(mac);
	}

	static EthernetBuilder src(byte[] mac) {
		return of().src(mac);
	}

	static EthernetBuilder type(int etherType) {
		return of().type(etherType);
	}

	interface EthernetBuilder extends HeaderFilter {

		default EthernetBuilder dst(byte[] mac) {
			return b -> this.emit(b).and().field("eth.dst", 0, 48, Op.EQ, mac);
		}

		default EthernetBuilder src(byte[] mac) {
			return b -> this.emit(b).and().field("eth.src", 6, 48, Op.EQ, mac);
		}

		default EthernetBuilder type(int etherType) {
			return b -> this.emit(b).and().field("eth.type", 12, 16, Op.EQ, etherType);
		}
	}
}