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
package com.slytechs.jnet.protocol.tcpip;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.protocol.api.common.HeaderNotFound;
import com.slytechs.jnet.protocol.api.core.PacketDescriptorType;
import com.slytechs.jnet.protocol.api.descriptor.DescriptorConstants;
import com.slytechs.jnet.protocol.api.descriptor.impl.PacketDissector;
import com.slytechs.jnet.protocol.tcpip.ipx.Ipx;

@Tag("osi-layer3")
@Tag("ipx")
class TestIpxHeader {

    static final PacketDissector DISSECTOR = PacketDissector
            .dissector(PacketDescriptorType.TYPE2);

    static final ByteBuffer DESC_BUFFER = ByteBuffer
            .allocateDirect(DescriptorConstants.DESC_TYPE2_BYTE_SIZE_MAX)
            .order(ByteOrder.nativeOrder());

    @BeforeEach
    void setUp() throws Exception {
        DISSECTOR.reset();

        DESC_BUFFER.clear();
        while (DESC_BUFFER.remaining() > 0)
            DESC_BUFFER.put((byte) 0);

        DESC_BUFFER.clear();
    }

    @Test
    void test_Ipx_checksum() throws HeaderNotFound {
        var packet = TestPackets.ETH_IPX_SPX.toPacket();
        packet.descriptor().bind(DESC_BUFFER);

        DISSECTOR.dissectPacket(packet);
        DISSECTOR.writeDescriptor(packet.descriptor());

        var ipx = packet.getHeader(new Ipx());
        assertEquals(0xFFFF, ipx.checksum());
        
        System.out.println(packet.descriptor().toString(Detail.HIGH));
        System.out.println(packet);
    }

    @Test
    void test_Ipx_type() throws HeaderNotFound {
        var packet = TestPackets.ETH_IPX_SPX.toPacket();
        packet.descriptor().bind(DESC_BUFFER);

        DISSECTOR.dissectPacket(packet);
        DISSECTOR.writeDescriptor(packet.descriptor());

        var ipx = packet.getHeader(new Ipx());
        assertEquals(5, ipx.type()); // SPX type
        
        System.out.println(packet);
   }

    @Test
    void test_Ipx_destination() throws HeaderNotFound {
        var packet = TestPackets.ETH_IPX_SPX.toPacket();
        packet.descriptor().bind(DESC_BUFFER);

        DISSECTOR.dissectPacket(packet);
        DISSECTOR.writeDescriptor(packet.descriptor());

        var ipx = packet.getHeader(new Ipx());

        assertEquals(0x00000001, ipx.destinationNetwork());
        assertEquals(0x1234, ipx.destinationSocket());

        var expectedNode = new byte[] {
                (byte) 0x00, (byte) 0x60, (byte) 0x08,
                (byte) 0x9f, (byte) 0xb1, (byte) 0xf3
        };
        assertArrayEquals(expectedNode, ipx.destinationNode());
        
        System.out.println(packet);
    }
}