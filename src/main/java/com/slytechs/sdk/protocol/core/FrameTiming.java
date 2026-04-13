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
package com.slytechs.sdk.protocol.core;

public interface FrameTiming {
	default String time(Packet pkt) {
		return pkt.timestampInfo().toString();
	}

	default String deltaTime(Packet pkt) {
		return "0.000000000 seconds";
	}

	default String arrivalTime(Packet pkt) {
		return time(pkt);
	}

	default String arrivalUtcTime(Packet pkt) {
		return time(pkt);
	}

	default String arrivalEpocTime(Packet pkt) {
		return time(pkt);
	}

	default String timeShift(Packet pkt) {
		return deltaTime(pkt);
	}

}