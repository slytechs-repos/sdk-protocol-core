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
package com.slytechs.jnet.protocol.api.descriptor;

import java.nio.ByteOrder;

import com.slytechs.jnet.core.api.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.builtin.L2FrameType;
import com.slytechs.jnet.protocol.api.dissector.PacketDissector;

/**
 * The Enum DescriptorType.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public enum DescriptorType {

	/** The descriptor type pcap hdr. */
	DESCRIPTOR_TYPE_PCAP_HDR(Constants.DESCRIPTOR_TYPE_PCAP_HDR, "PCAP_HDR", PcapHdrDescriptor::new),

	/** The descriptor type pcap. */
	DESCRIPTOR_TYPE_PCAP(Constants.DESCRIPTOR_TYPE_PCAP, "PCAP", PcapDescriptor::of),

	/** The descriptor type net. */
	DESCRIPTOR_TYPE_NET(Constants.DESCRIPTOR_TYPE_NET, "NET", NetPacketDescriptor::new),

	/** The descriptor type net1. */
	DESCRIPTOR_TYPE_NET1(Constants.DESCRIPTOR_TYPE_NET1, "NET1", Net1PacketDescriptor::new),

	/** The descriptor type net2. */
	DESCRIPTOR_TYPE_NET2(Constants.DESCRIPTOR_TYPE_NET2, "Net2", Net2PacketDescriptor::new),

	/** The descriptor type net3. */
	DESCRIPTOR_TYPE_NET3(Constants.DESCRIPTOR_TYPE_NET3, "Net3", Net3PacketDescriptor::new),

	/** The descriptor type ntapi. */
	DESCRIPTOR_TYPE_NTAPI(Constants.DESCRIPTOR_TYPE_NTAPI, "NTAPI"),

	/** The descriptor type dpdk. */
	DESCRIPTOR_TYPE_DPDK(Constants.DESCRIPTOR_TYPE_DPDK, "DPDK"),

	;

	/**
	 * The Interface Factory.
	 *
	 * @param <T> the generic type
	 */
	interface Factory<T extends PacketDescriptor> {

		/**
		 * New instance.
		 *
		 * @param l2Type        the l 2 type
		 * @param timestampUnit the timestamp unit
		 * @return the t
		 */
		T newInstance(L2FrameType l2Type, TimestampUnit timestampUnit);
	}

	/**
	 * The Interface Factory2.
	 *
	 * @param <T> the generic type
	 */
	interface Factory2<T extends PacketDescriptor> {

		/**
		 * New instance.
		 *
		 * @param order         the order
		 * @param l2Type        the l 2 type
		 * @param timestampUnit the timestamp unit
		 * @return the t
		 */
		T newInstance(ByteOrder order, L2FrameType l2Type, TimestampUnit timestampUnit);
	}

	/** The id. */
	private final int id;

	/** The label. */
	private final String label;

	/** The descriptor factory. */
	private final Factory2<? extends PacketDescriptor> descriptorFactory;

	/**
	 * Instantiates a new descriptor type.
	 *
	 * @param id    the id
	 * @param label the label
	 */
	DescriptorType(int id, String label) {
		this.id = id;
		this.label = label;
		this.descriptorFactory = (_, _, _) -> null;
	}

	/**
	 * Instantiates a new descriptor type.
	 *
	 * @param <T>               the generic type
	 * @param id                the id
	 * @param label             the label
	 * @param descriptorFactory the descriptor factory
	 */
	<T extends PacketDescriptor> DescriptorType(int id, String label, Factory<T> descriptorFactory) {
		this.id = id;
		this.label = label;
		this.descriptorFactory = (o, l2, u) -> descriptorFactory.newInstance(l2, u);
	}

	/**
	 * Instantiates a new descriptor type.
	 *
	 * @param <T>               the generic type
	 * @param id                the id
	 * @param label             the label
	 * @param descriptorFactory the descriptor factory
	 */
	<T extends PacketDescriptor> DescriptorType(int id, String label, Factory2<T> descriptorFactory) {
		this.id = id;
		this.label = label;
		this.descriptorFactory = descriptorFactory;
	}

	/**
	 * The Interface Constants.
	 */
	public interface Constants {

		/** The Constant DESCRIPTOR_TYPE_PCAP_HDR. */
		public static final int DESCRIPTOR_TYPE_PCAP_HDR = 0;

		/** The Constant DESCRIPTOR_TYPE_PCAP. */
		public static final int DESCRIPTOR_TYPE_PCAP = 1;

		/** The Constant DESCRIPTOR_TYPE_NET. */
		public static final int DESCRIPTOR_TYPE_NET = 2;

		/** The Constant DESCRIPTOR_TYPE_NET1. */
		public static final int DESCRIPTOR_TYPE_NET1 = 3;

		/** The Constant DESCRIPTOR_TYPE_NET2. */
		public static final int DESCRIPTOR_TYPE_NET2 = 4;

		/** The Constant DESCRIPTOR_TYPE_NET3. */
		public static final int DESCRIPTOR_TYPE_NET3 = 5;

		/** The Constant DESCRIPTOR_TYPE_NTAPI. */
		public static final int DESCRIPTOR_TYPE_NTAPI = 14;

		/** The Constant DESCRIPTOR_TYPE_DPDK. */
		public static final int DESCRIPTOR_TYPE_DPDK = 15;
	}

	/**
	 * Gets the value.
	 *
	 * @return the value
	 */
	public int getValue() {
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
	 * Gets the dissector.
	 *
	 * @return the dissector
	 */
	public PacketDissector getDissector() {
		return PacketDissector.dissector(this);
	}

	/**
	 * New descriptor.
	 *
	 * @param <T>           the generic type
	 * @param l2Type        the l 2 type
	 * @param timestampUnit the timestamp unit
	 * @return the t
	 */
	@SuppressWarnings("unchecked")
	public <T extends PacketDescriptor> T newDescriptor(L2FrameType l2Type, TimestampUnit timestampUnit) {
		return (T) descriptorFactory.newInstance(ByteOrder.nativeOrder(), l2Type, timestampUnit);
	}

	/**
	 * New descriptor.
	 *
	 * @param <T>           the generic type
	 * @param order         the order
	 * @param l2Type        the l 2 type
	 * @param timestampUnit the timestamp unit
	 * @return the t
	 */
	@SuppressWarnings("unchecked")
	public <T extends PacketDescriptor> T newDescriptor(ByteOrder order, L2FrameType l2Type,
			TimestampUnit timestampUnit) {
		return (T) descriptorFactory.newInstance(order, l2Type, timestampUnit);
	}

}
