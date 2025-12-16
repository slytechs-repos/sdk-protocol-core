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

module com.slytechs.jnet.protocol.api {
	exports com.slytechs.jnet.protocol.api;
	exports com.slytechs.jnet.protocol.api.address;
	exports com.slytechs.jnet.protocol.api.flag;
	exports com.slytechs.jnet.protocol.api.checksum;
	exports com.slytechs.jnet.protocol.api.pack;
	exports com.slytechs.jnet.protocol.api.builtin;
	exports com.slytechs.jnet.protocol.api.descriptor;
	exports com.slytechs.jnet.protocol.api.dissector;
	exports com.slytechs.jnet.protocol.api.format;
	exports com.slytechs.jnet.protocol.api.table;

	requires transitive com.slytechs.jnet.core.api;
	requires java.logging;

	uses com.slytechs.jnet.protocol.api.pack.ProtocolPackPlugin;
    uses com.slytechs.jnet.protocol.api.table.TableProvider;
}