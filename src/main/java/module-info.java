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
/**
 * 
 */

module com.slytechs.sdk.protocol.core {
	exports com.slytechs.sdk.protocol.core;
	exports com.slytechs.sdk.protocol.core.address;
	exports com.slytechs.sdk.protocol.core.flag;
	exports com.slytechs.sdk.protocol.core.checksum;
	exports com.slytechs.sdk.protocol.core.pack;
	exports com.slytechs.sdk.protocol.core.builtin;
	exports com.slytechs.sdk.protocol.core.descriptor;
	exports com.slytechs.sdk.protocol.core.dissector;
	exports com.slytechs.sdk.protocol.core.format;
	exports com.slytechs.sdk.protocol.core.table;
	exports com.slytechs.sdk.protocol.core.stack;
	exports com.slytechs.sdk.protocol.core.stack.processor;
	exports com.slytechs.sdk.protocol.core.spi;
 
	requires java.logging;
	requires transitive com.slytechs.sdk.common;

	uses com.slytechs.sdk.protocol.core.pack.ProtocolPackPlugin;
    uses com.slytechs.sdk.protocol.core.table.TableProvider;
    uses com.slytechs.sdk.protocol.core.spi.ProtocolProvider;
}