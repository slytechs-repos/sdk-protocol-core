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
package com.slytechs.jnet.protocol.api.address;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
class Addresses {

	public static String unsupportedMessage(String name) {
		return "not implemented by " + name;
	}

	public static byte[] validateLength(byte[] bytes, int expectedLength) {
		if (bytes.length != expectedLength) {
			throw new IllegalArgumentException(
					"Expected " + expectedLength + " bytes, got " + bytes.length);
		}
		return bytes;
	}

	public static long toLongFromBytes(byte[] bytes) {
		long result = 0;
		for (int i = 0; i < 6; i++) {
			result = (result << 8) | (bytes[i] & 0xFF);
		}
		return result;
	}

	private Addresses() {}

}
