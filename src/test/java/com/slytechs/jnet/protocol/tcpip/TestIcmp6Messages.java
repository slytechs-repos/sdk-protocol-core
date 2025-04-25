/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
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
package com.slytechs.jnet.protocol.tcpip;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.protocol.api.common.HeaderNotFound;
import com.slytechs.jnet.protocol.api.core.CoreId;
import com.slytechs.jnet.protocol.api.core.PacketDescriptorType;
import com.slytechs.jnet.protocol.api.descriptor.DescriptorConstants;
import com.slytechs.jnet.protocol.api.descriptor.impl.PacketDissector;
import com.slytechs.jnet.protocol.api.meta.PacketFormat;
import com.slytechs.jnet.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.test.Tests;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
class TestIcmp6Messages {

	static final PacketDissector DISSECTOR = PacketDissector
			.dissector(PacketDescriptorType.TYPE2);

	static final ByteBuffer DESC_BUFFER = ByteBuffer
			.allocateDirect(DescriptorConstants.DESC_TYPE2_BYTE_SIZE_MAX)
			.order(ByteOrder.nativeOrder());

	/**
	 * @throws java.lang.Exception
	 */
	@BeforeEach
	void setUp(TestInfo info) throws Exception {
		DISSECTOR.reset();

		DESC_BUFFER.clear();
		while (DESC_BUFFER.remaining() > 0)
			DESC_BUFFER.put((byte) 0);

		DESC_BUFFER.clear();

		Tests.displayTestName(info);
	}

	/**
	 * @throws java.lang.Exception
	 */
	@AfterEach
	void tearDown() throws Exception {
	}

	@Test
	void ICMPv6_NEIGHBOR_SOLICITATION() {

		var packet = TestPackets.ETH_IPv6_ICMPv6_NEIGHBOR_SOLICITATION.toPacket();
		packet.descriptor().bind(DESC_BUFFER);
		packet.setFormatter(new PacketFormat());

		DISSECTOR.dissectPacket(packet);
		DISSECTOR.writeDescriptor(packet.descriptor());

		packet.descriptor().buffer().flip();

		Tests.out.println(packet.descriptor().toString(Detail.HIGH));
		Tests.out.println(packet.toString(Detail.HIGH));

		assertTrue(packet.hasHeader(CoreId.CORE_ID_ICMPv6_NEIGHBOR_SOLICITATION));
	}

	@Test
	void ICMPv6_NEIGHBOR_ADVERTISEMENT() throws HeaderNotFound {
		var packet = TestPackets.ETH_IPv6_ICMPv6_NEIGHBOR_ADVERTISEMENT.toPacket();
		packet.descriptor().bind(DESC_BUFFER);
		packet.setFormatter(new PacketFormat());

		DISSECTOR.dissectPacket(packet);
		DISSECTOR.writeDescriptor(packet.descriptor());

		packet.descriptor().buffer().flip();

//		Tests.out.println(packet.descriptor().toString(Detail.HIGH));
//		Tests.out.println(packet.toString(Detail.HEXDUMP));
		Tests.out.println(packet.getHeader(new Ethernet()).toString(Detail.HEXDUMP));
//		Tests.out.println(packet.getHeader(new Icmp6NeighborAdvertisement()).toString(Detail.HEXDUMP));
		
		

		assertTrue(packet.hasHeader(CoreId.CORE_ID_ICMPv6_NEIGHBOR_ADVERTISEMENT));
	}

}
