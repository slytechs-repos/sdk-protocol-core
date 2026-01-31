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
 * Filter for MPLS (Multi-Protocol Label Switching) header fields.
 * 
 * <p>
 * MPLS Header (4 bytes):
 * 
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Label                  | TC  |S|       TTL     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * 
 * <ul>
 * <li><b>Label</b> (20 bits) - MPLS label value</li>
 * <li><b>TC</b> (3 bits) - Traffic Class (formerly EXP)</li>
 * <li><b>S</b> (1 bit) - Bottom of Stack flag</li>
 * <li><b>TTL</b> (8 bits) - Time to Live</li>
 * </ul>
 */
//MplsFilter.java
public interface MplsFilter {

	static MplsBuilder of() {
		return b -> b;
	}

	static MplsBuilder label(int label) {
		return of().label(label);
	}

	static MplsBuilder trafficClass(int tc) {
		return of().trafficClass(tc);
	}

	static MplsBuilder bottomOfStack() {
		return of().bottomOfStack();
	}

	interface MplsBuilder extends HeaderFilter {

		default MplsBuilder label(int label) {
			return b -> this.emit(b).and().field("mpls.label", 0, 20, Op.EQ, label);
		}

		default MplsBuilder trafficClass(int tc) {
			return b -> this.emit(b).and().field("mpls.tc", 2, 3, Op.EQ, tc);
		}

		default MplsBuilder bottomOfStack() {
			return b -> this.emit(b).and().field("mpls.bos", 2, 1, Op.EQ, 1);
		}

		default MplsBuilder ttl(int ttl) {
			return b -> this.emit(b).and().field("mpls.ttl", 3, 8, Op.EQ, ttl);
		}
	}
}