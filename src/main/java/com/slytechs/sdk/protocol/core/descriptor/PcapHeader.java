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
package com.slytechs.sdk.protocol.core.descriptor;

import com.slytechs.sdk.common.time.TimestampUnit;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface PcapHeader extends PacketDescriptor {

	@Override
	int captureLength();

	@Override
	int wireLength();

	int tvUSec();

	int tvSec();

	void setTvSec(int epochSeconds);

	void setTvUSec(int useconds);

	@Override
	void setCaptureLength(int length);

	@Override
	void setWireLength(int length);

	@Override
	TimestampUnit timestampUnit();

	@Override
	default long timestamp() {
		long timestamp = timestampUnit().ofSecond(tvSec(), tvUSec());

		return timestamp;
	}
}
