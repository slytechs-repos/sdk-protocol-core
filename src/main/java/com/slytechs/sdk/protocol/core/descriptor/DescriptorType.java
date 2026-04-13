/*
 * Copyright 2005-2026 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.protocol.core.descriptor;

import java.nio.ByteOrder;
import java.util.function.Supplier;

import com.slytechs.sdk.common.util.IntId;

/**
 * Descriptor type metadata.
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public enum DescriptorType implements DescriptorTypes, IntId {

	/** Unknown type */
	UNKNOWN(DescriptorTypes.UNKNOWN, "UNKNOWN"),

	/** The net. */
	TYPE1(DescriptorTypes.TYPE1, "TYPE1", Type1PacketDescriptor::new),

	/** The type2. */
	TYPE2(DescriptorTypes.TYPE2, "TYPE2", Type2PacketDescriptor::new),

	/** The pcap padded (24-bytes on x64 c-struct padded.) */
	PCAP_PADDED(DescriptorTypes.PCAP_PADDED, "PCAP_PADDED", PcapDescriptorPadded::new),

	/**
	 * The pcap packed (16-bytes c-struct packed.) Typically used when reading from
	 * pcap capture files.
	 */
	PCAP_PACKED(DescriptorTypes.PCAP_PACKED, "PCAP_PACKED", () -> PcapDescriptorPacked.of(ByteOrder.nativeOrder())),

	/** The ntapi. */
	NTAPI(DescriptorTypes.NTAPI, "NTAPI"),

	/** The dpdk. */
	DPDK(DescriptorTypes.DPDK, "DPDK"),

	;

	/**
	 * The default descriptor type (TYPE2) with full dissected packet protocol table
	 * support and TX/RX capabilities.
	 */
	public static final DescriptorType DEFAULT_TYPE = TYPE2;

	/** The id. */
	private final int descriptorType;

	/** The label. */
	private final String label;

	private final Supplier<PacketDescriptor> factory;

	/**
	 * Instantiates a new descriptor type info.
	 *
	 * @param descriptorType the id
	 * @param label          the label
	 */
	DescriptorType(int descriptorType, String label) {
		this.descriptorType = descriptorType;
		this.label = label;

		this.factory = () -> {
			throw new IllegalArgumentException("Unsupported descriptor type: " + label);
		};
	}

	/**
	 * Instantiates a new descriptor type info.
	 *
	 * @param descriptorType the id
	 * @param label          the label
	 */
	DescriptorType(int descriptorType, String label, Supplier<PacketDescriptor> factory) {
		this.descriptorType = descriptorType;
		this.label = label;
		this.factory = factory;
	}

	/**
	 * @see com.slytechs.sdk.protocol.core.descriptor.DescriptorTypes#id()
	 */
	@Override
	public int id() {
		return descriptorType;
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
	public static DescriptorType valueOf(int type) {
		for (DescriptorType info : values()) {
			if (info.descriptorType == type)
				return info;
		}

		return UNKNOWN;
	}

	public PacketDescriptor newPacketDescriptor() {
		return factory.get();
	}

}