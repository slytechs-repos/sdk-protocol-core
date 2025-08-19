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

import com.slytechs.jnet.core.api.format.StructFormat;
import com.slytechs.jnet.core.api.format.StructFormattable;

/**
 * {@snippet lang = c:
 * struct pack_record_s {
 * 	uint64_t
 * 		ordinal:8,    // Index within the protocol pack
 * 		pack:8,       // Protocol pack unique number
 *      class_mask:16;// Classification mask
 * 
 * 		size:16,     // (Optional) Size of the protocol header (in units of 8-bits)
 * 		offset:16;   // (Optional) Offset into the packet (in units of 8-bit bytes)
 * }
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public final class RecordCodec implements StructFormattable {

	public int id;
	public int ordinal;
	public int pack;
	public int classMask;
	public int size;
	public int offset;

	public RecordCodec() {}

	public void decode(long rec) {
		id = (int) ((rec >>> 0) & 0xFFFF);
		ordinal = (int) ((rec >>> 0) & 0xFF);
		pack = (int) ((rec >>> 8) & 0xFF);
		classMask = (int) ((rec >>> 16) & 0xFFFF);
		size = (int) ((rec >>> 32) & 0xFFFF);
		offset = (int) ((rec >>> 48) & 0xFFFF);
	}

	public long encode() {
		long rec = ((id & 0xFFFF) << 0);

		rec |= ((classMask & 0xFFFFL) << 16);
		rec |= ((size & 0xFFFFL) << 32);
		rec |= ((offset & 0xFFFFL) << 48);

		return rec;
	}

	public void clear() {
		id = ordinal = pack = classMask = size = offset = 0;
	}
	
	private String mapTcpip(int id) {
		return switch(id) {
		case 0x201 -> "ETHERNET";
		case 0x202 -> "VLAN";
		case 0x20b -> "IPv4";
		default -> "?";
		};
	}
	
	@Override
	public StructFormat format(StructFormat p) {
		return p.openln("RecordCodec")
				.println("id",  "0x" + Integer.toHexString(id), mapTcpip(id))
				.println("offset", offset)
				.println("size", size)
				.close();
	}
	
	@Override
	public String toString() {
		return format(new StructFormat()).toString();
	}
}
