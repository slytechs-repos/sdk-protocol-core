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
package com.slytechs.jnet.protocol.api.descriptor;

import java.util.List;

/**
 * Chainable network tag for protocol-specific metadata (e.g., DPDK tags, IPF
 * fragment links).
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface NetTag {

	int RESOURCE_ID_TYPE = 1;

	/**
	 * Gets the next tag in the chain.
	 *
	 * @return the next NetTag, or null if none
	 */
	NetTag next();

	NetTag setNext(NetTag next);

	int type();

	static <T extends NetTag> T getTag(NetTag head, int type) {
		throw new UnsupportedOperationException();
	}

	static <T extends NetTag> boolean compareTag(NetTag head, T tag) {
		return head == tag;
	}

	static <T extends NetTag> T removeTag(NetTag head, int type) {
		throw new UnsupportedOperationException();
	}

	static <T extends NetTag> List<T> getAllTags(NetTag head, int type) {
		throw new UnsupportedOperationException();
	}

	static <T extends NetTag> List<T> removeAllTags(NetTag head, int type) {
		throw new UnsupportedOperationException();
	}
}