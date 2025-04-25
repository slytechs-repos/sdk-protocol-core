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
package com.slytechs.jnet.protocol.api.meta;

import static java.nio.charset.StandardCharsets.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.stream.IntStream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.slytechs.jnet.platform.api.common.NotFound;
import com.slytechs.jnet.platform.api.util.HexStrings;
import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.platform.api.util.json.JsonException;
import com.slytechs.jnet.protocol.api.common.Packet;
import com.slytechs.jnet.protocol.api.common.Payload;
import com.slytechs.jnet.protocol.api.core.HashType;
import com.slytechs.jnet.protocol.api.core.PacketDescriptorType;
import com.slytechs.jnet.protocol.api.descriptor.DescriptorConstants;
import com.slytechs.jnet.protocol.api.descriptor.Type2Descriptor;
import com.slytechs.jnet.protocol.api.descriptor.impl.PacketDissector;
import com.slytechs.jnet.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.jnet.protocol.tcpip.ip.Ip4;
import com.slytechs.test.Tests;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
class TestMetaHeader {

	private static byte[] byteArrayInitialized(int len) {
		byte[] array = new byte[len];
		IntStream.range(0, len)
				.forEach(i -> array[i] = (byte) i);;
		return array;
	}

	/**
	 * (Source wireshark capture and copy/paste)
	 * 
	 * <pre>
	Frame 1: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
	Encapsulation type: Ethernet (1)
	Arrival Time: Mar  1, 2011 15:45:13.266821000 EST
	[Time shift for this packet: 0.000000000 seconds]
	Epoch Time: 1299012313.266821000 seconds
	[Time delta from previous captured frame: 0.000000000 seconds]
	[Time delta from previous displayed frame: 0.000000000 seconds]
	[Time since reference or first frame: 0.000000000 seconds]
	Frame Number: 1
	Frame Length: 74 bytes (592 bits)
	Capture Length: 74 bytes (592 bits)
	[Frame is marked: False]
	[Frame is ignored: False]
	[Protocols in frame: eth:ethertype:ip:tcp]
	[Coloring Rule Name: HTTP]
	[Coloring Rule String: http || tcp.port == 80 || http2]
	Ethernet II, Src: ASUSTekC_b3:01:84 (00:1d:60:b3:01:84), Dst: Actionte_2f:47:87 (00:26:62:2f:47:87)
	Destination: Actionte_2f:47:87 (00:26:62:2f:47:87)
	    Address: Actionte_2f:47:87 (00:26:62:2f:47:87)
	    .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
	    .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
	Source: ASUSTekC_b3:01:84 (00:1d:60:b3:01:84)
	    Address: ASUSTekC_b3:01:84 (00:1d:60:b3:01:84)
	    .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
	    .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
	Type: IPv4 (0x0800)
	Internet Protocol Version 4, Src: 192.168.1.140, Dst: 174.143.213.184
	0100 .... = Version: 4
	.... 0101 = Header Length: 20 bytes (5)
	Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
	    0000 00.. = Differentiated Services Codepoint: Default (0)
	    .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
	Total Length: 60
	Identification: 0xcb5b (52059)
	Flags: 0x40, Don't fragment
	    0... .... = Reserved bit: Not set
	    .1.. .... = Don't fragment: Set
	    ..0. .... = More fragments: Not set
	...0 0000 0000 0000 = Fragment Offset: 0
	Time to Live: 64
	Protocol: TCP (6)
	Header Checksum: 0x28e4 [validation disabled]
	[Header checksum status: Unverified]
	Source Address: 192.168.1.140
	Destination Address: 174.143.213.184
	 * 
	 * </pre>
	 * 
	 * Binary representation of the above header.
	 */
	private static final String ETH_HEX_STRING = "0026622f4787 001d60b30184 0800";
	private static final String IP4_HEX_STRING = "4500003c cb5b4000 400628e4 c0a8018c ae8fd5b8";
	private static final String TCP_HEX_STRING = "e14e00508e50190100000000a00216d08f470000020405b40402080a0021d25a0000000001030307";
	private static final String DATA_STRING = "Just some data.";
	private static final byte[] PACKET_ETH = HexStrings.parseHexString(""
			+ ETH_HEX_STRING
			+ IP4_HEX_STRING
			+ TCP_HEX_STRING
			+ HexStrings.toHexString(DATA_STRING.getBytes(UTF_8))
			+ HexStrings.toHexString(byteArrayInitialized(255))
			+ "");
	private Packet packet;

	/**
	 * @throws java.lang.Exception
	 */
	@BeforeEach
	void setUp() throws Exception {
		byte[] PACKET = PACKET_ETH;
		ByteBuffer descriptorData = ByteBuffer.allocate(
				DescriptorConstants.DESC_TYPE2_BYTE_SIZE_MAX)
				.order(ByteOrder.nativeOrder());
		ByteBuffer packetData = ByteBuffer.wrap(PACKET);

		final long TIMESTAMP = System.currentTimeMillis();

		PacketDissector dissector;
		dissector = PacketDissector.javaDissector(PacketDescriptorType.TYPE2);
		dissector.dissectPacket(packetData, TIMESTAMP, PACKET.length, PACKET.length);
		dissector.writeDescriptor(descriptorData);
		descriptorData.clear();

		Type2Descriptor descriptorType2 = new Type2Descriptor()
				.withBinding(descriptorData)
				.hash(0x12345, HashType.ROUND_ROBIN)
				.rxPort(10)
				.txPort(15)
				.txIgnore(1);

		descriptorType2.frameNo(7);

		packet = new Packet(descriptorType2);
		packet.bind(PACKET);
	}

	/**
	 * @throws java.lang.Exception
	 */
	@AfterEach
	void tearDown() throws Exception {
		packet = null;
	}

	@Test
	void testPerHeaderFormatter() throws NotFound, JsonException {
		PacketFormat pf = new PacketFormat(Detail.SUMMARY);

		Ethernet eth = new Ethernet();
		Ip4 ip4 = new Ip4();
		Payload payload = new Payload();

//		if (packet.hasHeader(eth))
//			Tests.out.println(pf.format(eth));

		if (packet.hasHeader(ip4))
			Tests.out.println(pf.format(ip4, Detail.HEXDUMP));

//		if (packet.hasHeader(payload))
//			Tests.out.println(pf.format(payload));
	}

	@Test
	void testPacketFormatter() throws NotFound, JsonException {
		PacketFormat format = new PacketFormat(Detail.SUMMARY);

		Tests.out.println(format.format(packet));
	}

	@Test
	void testPacketHexdumps() throws NotFound, JsonException {
		PacketFormat format = new PacketFormat(Detail.SUMMARY);

//		Ethernet eth = packet.getHeader(new Ethernet());
//		Payload payload = packet.getHeader(new Payload());

		Tests.out.println("Dump entire packet:");
		Tests.out.println(format.formatHexdump(packet));
//
//		Tests.out.println("Dump Ethernet header only:");
//		Tests.out.println(format.formatHexdump(eth));
//
//		Tests.out.println("Dump Payload.data field:");
//		Tests.out.println(format.formatHexdump(new MetaHeader(format, payload).getField("data")));

	}
}
