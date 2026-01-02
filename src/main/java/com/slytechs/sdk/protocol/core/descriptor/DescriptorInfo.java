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
 * Descriptor type metadata.
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public enum DescriptorInfo implements DescriptorType {

	/** The pcap padded (24-bytes on x64 c-struct padded.) */
	PCAP_PADDED(DescriptorType.PCAP_PADDED, "PCAP_PADDED"),

	/**
	 * The pcap packed (16-bytes c-struct packed.) Typically used when reading from
	 * pcap capture files.
	 */
	PCAP_PACKED(DescriptorType.PCAP_PACKED, "PCAP_PACKED"),

	/** The net. */
	NET(DescriptorType.NET, "NET"),

	/** The ntapi. */
	NTAPI(DescriptorType.NTAPI, "NTAPI"),

	/** The dpdk. */
	DPDK(DescriptorType.DPDK, "DPDK"),

	;

	/** The id. */
	private final int id;

	/** The label. */
	private final String label;

	/**
	 * Instantiates a new descriptor type info.
	 *
	 * @param id    the id
	 * @param label the label
	 */
	DescriptorInfo(int id, String label) {
		this.id = id;
		this.label = label;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.DescriptorType#descriptorId()
	 */
	@Override
	public int descriptorId() {
		return id;
	}

	/**
	 * Gets the label.
	 *
	 * @return the label
	 */
	public String getLabel() {
		return label;
	}

	/**
	 * Value of.
	 *
	 * @param type the type
	 * @return the descriptor type info
	 */
	public static DescriptorInfo valueOf(int type) {
		for (DescriptorInfo info : values()) {
			if (info.id == type)
				return info;
		}
		throw new IllegalArgumentException("Unknown descriptor type: " + type);
	}
}