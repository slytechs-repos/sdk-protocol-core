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
package com.slytechs.sdk.protocol.core.descriptor;

/**
 * Descriptor type constants.
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public sealed interface DescriptorTypes permits DescriptorType {

	int UNKNOWN = 0;

	/** SDK packet descriptor - on demand protocol dissection (16 bytes) */
	int TYPE1 = 1;

	/** SDK packet descriptor - full protocol table (~96 bytes) */
	int TYPE2 = 2;

	/** Pcap file header - kernel format (24-byte on x64 padded) */
	int PCAP_PADDED = 12;

	/** Pcap packet - file format (16-byte c-struct packed) */
	int PCAP_PACKED = 13;

	/** Napatech native */
	int NTAPI = 14;

	/** DPDK native */
	int DPDK = 15;

}