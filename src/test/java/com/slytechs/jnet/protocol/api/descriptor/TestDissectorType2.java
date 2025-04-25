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
package com.slytechs.jnet.protocol.api.descriptor;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.logging.Level;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import com.slytechs.jnet.platform.api.common.impl.Benchmark;
import com.slytechs.jnet.platform.api.util.HexStrings;
import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.protocol.api.common.Packet;
import com.slytechs.jnet.protocol.api.core.CoreId;
import com.slytechs.jnet.protocol.api.core.HashType;
import com.slytechs.jnet.protocol.api.core.L2FrameType;
import com.slytechs.jnet.protocol.api.core.PacketDescriptorType;
import com.slytechs.jnet.protocol.api.descriptor.impl.PacketDissector;
import com.slytechs.jnet.protocol.tcpip.dissector.Type2DissectorJavaImpl;
import com.slytechs.jnet.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.jnet.protocol.tcpip.ip.DiffServ;
import com.slytechs.jnet.protocol.tcpip.ip.Ip4;
import com.slytechs.jnet.protocol.tcpip.ip.Ip4IdOptions;
import com.slytechs.jnet.protocol.tcpip.ip.Ip4RouterAlertOption;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6;
import com.slytechs.jnet.protocol.tcpip.ip.Ip6FragmentExtension;
import com.slytechs.test.Tests;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
class TestDissectorType2 {
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
	private static final String IP4_RSVP_W_OPTS_HEX_STRING = "4600012000000000fe2e00a2110303031002020294040000";
	private static final String IP4_TCP_W_OPTS_HEX_STRING = "4600012000000000fe0600a2110303031002020294040000";
	private static final String TCP_HEX_STRING = "e14e00508e50190100000000a00216d08f470000020405b40402080a0021d25a0000000001030307";
	private static final byte[] PACKET_IP4 = HexStrings.parseHexString(ETH_HEX_STRING + IP4_HEX_STRING);
	private static final byte[] PACKET_IP4_TCP = HexStrings.parseHexString(ETH_HEX_STRING + IP4_HEX_STRING
			+ TCP_HEX_STRING);
	private static final byte[] PACKET_IP4_TCP_W_IP_OPTS = HexStrings.parseHexString(ETH_HEX_STRING
			+ IP4_TCP_W_OPTS_HEX_STRING
			+ TCP_HEX_STRING);
	PacketDissector dissector;

	private String testName;
	private Level displayLevel = Level.ALL;
	private Level defaultLevel = Level.INFO;

//	private static final byte[] SRC_ADDRESS = ArrayUtils.parseHexString("192.168.1.140");
//	private static final byte[] DST_ADDRESS = ArrayUtils.parseHexString("174.143.213.184");

	private void log(Level level, String fmt, Object... args) {
		if (level.intValue() >= displayLevel.intValue())
			Tests.out.printf("> %s", fmt.formatted(args));
	}

	private void log(Object obj) {
		log(defaultLevel, String.valueOf(obj));
	}

	private void log(String fmt, Object... args) {
		log(defaultLevel, fmt, args);
	}

	private void logPacketsPerSecond(double tsecs, double pps, long total) {
		log("duration=%,.1fsec rate=%,.0fpps total=%,d%n",
				tsecs,
				pps,
				total);
	}

	private void logDescriptorsPerSecond(double tsecs, double pps, long total) {
		log("duration=%,.1fsec rate=%,.0fdps total=%,d%n",
				tsecs,
				pps,
				total);
	}

	@BeforeEach
	void setUp(TestInfo info) throws Exception {
		testName = info.getTestMethod().get().getName();
		dissector = PacketDissector.javaDissector(PacketDescriptorType.TYPE2);

		if (defaultLevel.intValue() >= displayLevel.intValue())
			Tests.out.printf("> --- %s() ---%n", testName);
	}

	/**
	 * @throws java.lang.Exception
	 */
	@AfterEach
	void tearDown() throws Exception {
		dissector = null;

		if (defaultLevel.intValue() >= displayLevel.intValue())
			Tests.out.println();
	}

	@Test
	void type2DissectionToJavaDescriptor() {
		byte[] PACKET = PACKET_IP4_TCP_W_IP_OPTS;
		ByteBuffer dsc = ByteBuffer.allocate(
				DescriptorConstants.DESC_TYPE2_BYTE_SIZE_MAX)
				.order(ByteOrder.nativeOrder());
		ByteBuffer pkt = ByteBuffer.wrap(PACKET);

		final long TIMESTAMP = System.currentTimeMillis();

		dissector.dissectPacket(pkt, TIMESTAMP, PACKET.length, PACKET.length);
		dissector.writeDescriptor(dsc);
		dsc.clear();

		Type2Descriptor type2 = new Type2Descriptor()
				.withBinding(dsc)
				.hash(0x12345, HashType.ROUND_ROBIN)
				.rxPort(10)
				.txPort(15)
				.txIgnore(1)

		;

		log("%s%n", type2);

		Tests.out.println(type2.toString(Detail.HIGH));

		assertEquals(TIMESTAMP, type2.timestamp(), "timestamp");
		assertEquals(PACKET.length, type2.captureLength(), "captureLength");

		assertEquals(L2FrameType.L2_FRAME_TYPE_ETHER, type2.l2FrameType(), "l2FrameType");

		assertEquals(PACKET.length, type2.wireLength(), "wireLength");

		Packet packet = new Packet(type2);
		packet.bind(PACKET);

		Ethernet eth = new Ethernet();
		Ip4 ip4 = new Ip4();
		Ip6 ip6 = new Ip6();
		Ip4RouterAlertOption router4 = new Ip4RouterAlertOption();
		Ip6FragmentExtension frag6 = new Ip6FragmentExtension();

		if (packet.hasHeader(eth)) {
			log("ETH.type=0x%04X%n", eth.type());
		}

		if (packet.hasHeader(ip4) && ip4.hasOption(router4)) {
			log("IPv4.protocol=%d examinePacket=%s%n", ip4.protocol(), router4.examinePacket());
		}

		if (packet.hasHeader(frag6)) {
			log("IPv6.next=%d%n", ip6.nextHeader());
		}
	}

	@Test
//	@Disabled
	void speedTestJava() {
		byte[] PACKET = PACKET_IP4_TCP_W_IP_OPTS;
		ByteBuffer desc1 = ByteBuffer.allocate(DescriptorConstants.DESC_TYPE2_BYTE_SIZE_MAX)
				.order(ByteOrder.nativeOrder());
		ByteBuffer desc2 = ByteBuffer.allocate(DescriptorConstants.DESC_TYPE2_BYTE_SIZE_MAX)
				.order(ByteOrder.nativeOrder());
		ByteBuffer pkt = MemorySegment.ofArray(PACKET)
				.asByteBuffer();

		final long TIMESTAMP = System.currentTimeMillis();

		Type2DissectorJavaImpl diss2 = ((Type2DissectorJavaImpl) dissector)
//				.disableBitmaskRecording()
//				.disableExtensionRecordingForAll()
				.disableExtensionRecordingFor(CoreId.IPv4,
//						Ip4OptionId.ROUTER_ALERT,
						Ip4IdOptions.NO_OPERATION,
						Ip4IdOptions.END_OF_OPTIONS)

		;

		dissector.dissectPacket(pkt, TIMESTAMP, PACKET.length, PACKET.length);
		dissector.writeDescriptor(desc1);

		diss2.writeDescriptorUsingLayout(desc2);

//		Tests.out.printf("desc1=%s%n", HexStrings.toHexString(desc1.array(), 0, 24));
//		Tests.out.printf("desc2=%s%n", HexStrings.toHexString(desc2.array(), 0, 24));

		Type2Descriptor type2 = new Type2Descriptor()
				.withBinding(desc2)
				.hash(0x12345, HashType.ROUND_ROBIN)
				.rxPort(10)
				.txPort(15)
				.txIgnore(1);
		Tests.out.printf("type2=%s%n", type2.buildString(Detail.HIGH));

		Packet packet = new Packet(type2);
		packet.bind(PACKET);

		Ethernet eth = new Ethernet();
		Ip4 ip4 = new Ip4();
		DiffServ ip6 = new Ip6();
		Ip4RouterAlertOption ra4 = new Ip4RouterAlertOption();
		Ip6FragmentExtension frag6 = new Ip6FragmentExtension();

//		final long COUNT = 3_000_000_000l;
//		final long COUNT = 300_000_000;
//		final long COUNT = 30_000_000;
//		final long COUNT = 3_000_000;
		final long COUNT = 1;
		long count = COUNT;

		Benchmark benchmark = Benchmark.setup()
				.reportRate(COUNT, this::logPacketsPerSecond);

		while (count-- > 0) {
			dissector.dissectPacket(pkt.clear(), TIMESTAMP, PACKET.length, PACKET.length);
			dissector.writeDescriptor(desc1.clear());

			if (packet.hasHeader(eth)) {
				Tests.out.println(eth);
			}

			if (packet.hasHeader(ip4)) {
				Tests.out.println(ip4);
			}

			if (packet.hasHeader(ip4) && ip4.hasOption(ra4)) {
				Tests.out.println(ra4);
			}

			if (packet.hasHeader(frag6)) {
			}
		}

		benchmark.complete();
	}
}
