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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.protocol.api.common.HeaderNotFound;
import com.slytechs.jnet.protocol.api.core.PacketDescriptorType;
import com.slytechs.jnet.protocol.api.descriptor.DescriptorConstants;
import com.slytechs.jnet.protocol.api.descriptor.impl.PacketDissector;
import com.slytechs.jnet.protocol.api.meta.PacketFormat;
import com.slytechs.jnet.protocol.tcpip.tcp.Tcp;
import com.slytechs.jnet.protocol.tcpip.tcp.TcpWindowScaleOption;
import com.slytechs.test.Tests;

/**
 * VLAN header tests
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
@Tag("osi-layer4")
@Tag("tcp")
class TestTcpHeader {

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

		Tests.out.println("---- " + info.getDisplayName() + " ----");
	}

	@Test
	void test_Tcp_dstPort() throws HeaderNotFound {
		var packet = TestPackets.ETH_IPv4_TCP_WCALEOPT.toPacket();
		packet.descriptor().bind(DESC_BUFFER);

		DISSECTOR.dissectPacket(packet);
		DISSECTOR.writeDescriptor(packet.descriptor());

		var tcp = packet.getHeader(new Tcp());

		assertEquals(80, tcp.destination());
	}

	@Test
	void test_Tcp_windowSizeScaledShiftCount7() throws HeaderNotFound {
		var packet = TestPackets.ETH_IPv4_TCP_WCALEOPT.toPacket();
		packet.descriptor().bind(DESC_BUFFER);

		DISSECTOR.dissectPacket(packet);
		DISSECTOR.writeDescriptor(packet.descriptor());

		var tcp = packet.getHeader(new Tcp());
		Tests.out.println(tcp.toString(Detail.HIGH, new PacketFormat()));

		assertEquals(5840 << 7, tcp.windowScaled(7));
	}

	@Test
	void test_Tcp_windowSizeScaledWithWScaleOptionManual() throws HeaderNotFound {
		var packet = TestPackets.ETH_IPv4_TCP_WCALEOPT.toPacket();
		packet.descriptor().bind(DESC_BUFFER);

		DISSECTOR.dissectPacket(packet);
		DISSECTOR.writeDescriptor(packet.descriptor());

		var tcp = packet.getHeader(new Tcp());
		var wscale = tcp.getOption(new TcpWindowScaleOption());

		assertEquals(5840 << 7, tcp.windowScaled(wscale.shiftCount()));
	}

	@Test
	void test_Tcp_windowSizeScaledWithWScaleOptionAuto() throws HeaderNotFound {
		var packet = TestPackets.ETH_IPv4_TCP_WCALEOPT.toPacket();
		packet.descriptor().bind(DESC_BUFFER);

		DISSECTOR.dissectPacket(packet);
		DISSECTOR.writeDescriptor(packet.descriptor());

		var tcp = packet.getHeader(new Tcp());

		assertEquals(5840 << 7, tcp.windowScaled());
	}

}
