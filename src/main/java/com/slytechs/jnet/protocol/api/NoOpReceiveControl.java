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

import com.slytechs.jnet.protocol.api.builtin.L2FrameType;
import com.slytechs.jnet.protocol.api.descriptor.ReceiveControl;

/**
 * Empty/No-op implementation of ReceiveControl that silently consumes/ignores
 * all of the method calls.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
enum NoOpReceiveControl implements ReceiveControl {
	INSTANCE;

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.ReceiveControl#rxPort()
	 */
	@Override
	public int rxPort() {
		return 0;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.ReceiveControl#l2FrameType()
	 */
	@Override
	public L2FrameType l2FrameType() {
		return L2FrameType.L2_FRAME_TYPE_ETHER;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.ReceiveControl#hasL2Extensions()
	 */
	@Override
	public boolean hasL2Extensions() {
		return false;
	}

}
