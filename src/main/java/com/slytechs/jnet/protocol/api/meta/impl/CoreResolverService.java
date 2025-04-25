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
package com.slytechs.jnet.protocol.api.meta.impl;

import java.util.HashMap;
import java.util.Map;

import com.slytechs.jnet.platform.api.util.HexStrings;
import com.slytechs.jnet.platform.api.util.time.Timestamp;
import com.slytechs.jnet.protocol.api.meta.MetaValue.ValueResolver;
import com.slytechs.jnet.protocol.api.meta.spi.ValueResolverService;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class CoreResolverService implements ValueResolverService {

	/**
	 * 
	 */
	public CoreResolverService() {}

	/**
	 * @see com.slytechs.jnet.protocol.api.meta.spi.ValueResolverService#getResolvers()
	 */
	@Override
	public Map<String, ValueResolver> getResolvers() {
		var map = new HashMap<String, ValueResolver>();

		map.put("NONE", null);
		map.put("F", CoreResolverService::resolveAny);
		map.put("TIMESTAMP", Timestamp::formatTimestamp);
		map.put("TIMESTAMP_UNIT", Timestamp::formatTimestampUnit);
		map.put("TIMESTAMP_IN_PCAP_MICRO", Timestamp::formatTimestampPcapMicro);
		map.put("TIMESTAMP_IN_EPOCH_MILLI", Timestamp::formatTimestampInEpochMilli);
		map.put("BITSHIFT_1", v -> DisplayUtil.bitshiftIntLeft(v, 1));
		map.put("BITSHIFT_2", v -> DisplayUtil.bitshiftIntLeft(v, 2));
		map.put("BITSHIFT_3", v -> DisplayUtil.bitshiftIntLeft(v, 3));
		map.put("BITSHIFT_4", v -> DisplayUtil.bitshiftIntLeft(v, 4));
		map.put("BITSHIFT_5", v -> DisplayUtil.bitshiftIntLeft(v, 5));
		map.put("BITSHIFT_6", v -> DisplayUtil.bitshiftIntLeft(v, 6));
		map.put("BITSHIFT_7", v -> DisplayUtil.bitshiftIntLeft(v, 7));
		map.put("BITSHIFT_8", v -> DisplayUtil.bitshiftIntLeft(v, 8));

		return map;
//		return new HashMap<>();
	}

	private static String resolveAny(Object target) {
		return switch (target) {

		case byte[] arr -> resolveArrayValue(arr);

		default -> String.valueOf(target);
		};
	}

	private static String resolveArrayValue(byte[] arr) {
		return switch (arr.length) {

		default -> HexStrings.toHexString(arr);
		};
	}
}
