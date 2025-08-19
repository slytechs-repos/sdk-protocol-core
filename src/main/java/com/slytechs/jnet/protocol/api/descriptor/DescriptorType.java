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

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public enum DescriptorType {
	DESCRIPTOR_TYPE_PCAP(Constants.DESCRIPTOR_TYPE_PCAP),
	DESCRIPTOR_TYPE_NET1(Constants.DESCRIPTOR_TYPE_NET1),
	DESCRIPTOR_TYPE_NET2(Constants.DESCRIPTOR_TYPE_NET2),
	DESCRIPTOR_TYPE_NTAPI(Constants.DESCRIPTOR_TYPE_NTAPI),
	DESCRIPTOR_TYPE_DPDK(Constants.DESCRIPTOR_TYPE_DPDK),

	;

	private final int id;

	DescriptorType(int id) {
		this.id = id;
	}

	interface Constants {
		public static final int DESCRIPTOR_TYPE_PCAP = 0;
		public static final int DESCRIPTOR_TYPE_NET1 = 1;
		public static final int DESCRIPTOR_TYPE_NET2 = 2;

		public static final int DESCRIPTOR_TYPE_NTAPI = 14;
		public static final int DESCRIPTOR_TYPE_DPDK = 15;
	}

	public int getValue() {
		return id;
	}

}
