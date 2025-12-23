/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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
package com.slytechs.sdk.protocol.core.dissector;

import com.slytechs.sdk.common.memory.ByteBuf;
import com.slytechs.sdk.protocol.core.descriptor.L2FrameType;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface LazyDissector {

	/**
	 * Returns a bitmask of supported protocol's (their ordinals). Allows for a
	 * quick check if the dissector is usable for a particular protocol.
	 *
	 * @return the 64-bit bitmask
	 */
	long supportedBitmask();

	int dissect(long[] protocolArray, int arrayOffset, ByteBuf packet, L2FrameType l2Type);

	long lookupProtocolId(int protocolId, long[] protocolArray, int arrayLength);
}
