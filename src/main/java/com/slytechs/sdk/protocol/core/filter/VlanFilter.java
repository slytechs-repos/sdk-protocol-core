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

public interface VlanFilter {

	static VlanBuilder of() {
		return b -> b;
	}

	static VlanBuilder pcp(int priority) {
		return of().pcp(priority);
	}

	static VlanBuilder dei(int dropEligible) {
		return of().dei(dropEligible);
	}

	static VlanBuilder vid(int vid) {
		return of().vid(vid);
	}

	static VlanBuilder type(int etherType) {
		return of().type(etherType);
	}

	interface VlanBuilder extends HeaderFilter {

		default VlanBuilder pcp(int priority) {
			return b -> this.emit(b).and().field("vlan.pcp", 0, 3, Op.EQ, priority);
		}

		default VlanBuilder dei(int dropEligible) {
			return b -> this.emit(b).and().field("vlan.dei", 0, 1, Op.EQ, dropEligible);
		}

		default VlanBuilder vid(int vid) {
			return b -> this.emit(b).and().field("vlan.vid", 0, 12, Op.EQ, vid);
		}

		default VlanBuilder type(int etherType) {
			return b -> this.emit(b).and().field("vlan.type", 2, 16, Op.EQ, etherType);
		}
	}
}