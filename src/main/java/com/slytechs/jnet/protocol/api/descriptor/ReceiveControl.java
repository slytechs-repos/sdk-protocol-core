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

import com.slytechs.jnet.protocol.api.builtin.L2FrameType;

/**
 * Provides read-only access to packet reception metadata and Layer 2 frame
 * information.
 * 
 * <p>
 * The {@code ReceiveControl} interface exposes metadata about how a packet was
 * received by the network interface, including the ingress port and Layer 2
 * frame characteristics. This information is typically populated by the capture
 * backend (DPDK, Napatech, pcap, etc.) and is read-only from the application
 * perspective.
 * 
 * <h2>Reception Metadata</h2>
 * 
 * <p>
 * Reception metadata includes:
 * <ul>
 * <li><strong>RX Port:</strong> The physical or logical port where the packet
 * arrived</li>
 * <li><strong>L2 Frame Type:</strong> The Layer 2 encapsulation format
 * (Ethernet, 802.11, etc.)</li>
 * <li><strong>L2 Extensions:</strong> Presence of VLAN tags, MPLS labels, or
 * other L2 extensions</li>
 * </ul>
 * 
 * <h2>Usage Examples</h2>
 * 
 * <h3>Port-Based Packet Classification</h3>
 * 
 * <pre>{@code
 * public void classifyByPort(Packet packet) {
 * 	if (packet.hasReceiveInfo()) {
 * 		ReceiveControl rx = packet.receiveControl();
 * 		int port = rx.rxPort();
 * 
 * 		switch (port) {
 * 		case 0 -> processWanTraffic(packet);
 * 		case 1 -> processLanTraffic(packet);
 * 		case 2 -> processDmzTraffic(packet);
 * 		default -> processUnknownPort(packet, port);
 * 		}
 * 	}
 * }
 * }</pre>
 * 
 * <h3>Frame Type Detection</h3>
 * 
 * <pre>{@code
 * public void analyzeFrameType(Packet packet) {
 * 	if (packet.hasReceiveInfo()) {
 * 		ReceiveControl rx = packet.receiveControl();
 * 		L2FrameType frameType = rx.l2FrameType();
 * 
 * 		switch (frameType) {
 * 		case L2_FRAME_TYPE_ETHER:
 * 			if (rx.hasL2Extensions()) {
 * 				// Process VLAN tags or other extensions
 * 				processEthernetWithExtensions(packet);
 * 			} else {
 * 				processStandardEthernet(packet);
 * 			}
 * 			break;
 * 
 * 		case L2_FRAME_TYPE_IEEE80211:
 * 			processWifiFrame(packet);
 * 			break;
 * 
 * 		case L2_FRAME_TYPE_PPP:
 * 			processPppFrame(packet);
 * 			break;
 * 		}
 * 	}
 * }
 * }</pre>
 * 
 * <h3>Traffic Statistics by Port</h3>
 * 
 * <pre>{@code
 * public class PortStatistics {
 * 	private final long[] rxBytes = new long[64];
 * 	private final long[] rxPackets = new long[64];
 * 
 * 	public void updateStatistics(Packet packet) {
 * 		if (packet.hasReceiveInfo()) {
 * 			int port = packet.receiveControl().rxPort();
 * 			if (port < rxBytes.length) {
 * 				rxBytes[port] += packet.captureLength();
 * 				rxPackets[port]++;
 * 			}
 * 		}
 * 	}
 * 
 * 	public void printStatistics() {
 * 		for (int port = 0; port < rxBytes.length; port++) {
 * 			if (rxPackets[port] > 0) {
 * 				System.out.printf("Port %d: %d packets, %d bytes%n",
 * 						port, rxPackets[port], rxBytes[port]);
 * 			}
 * 		}
 * 	}
 * }
 * }</pre>
 * 
 * <h2>Implementation Notes</h2>
 * 
 * <p>
 * This interface is typically implemented by packet descriptors that contain
 * reception metadata, such as:
 * <ul>
 * <li>{@code NetPacketDescriptor} - Standard jnetworks-sdk descriptor</li>
 * <li>{@code DpdkDescriptor} - DPDK mbuf-based descriptor</li>
 * <li>{@code NapatechDescriptor} - Napatech capture card descriptor</li>
 * </ul>
 * 
 * <p>
 * The metadata is populated during packet capture and remains immutable during
 * the packet's lifetime. This read-only design ensures thread-safety when
 * multiple threads analyze the same packet.
 * 
 * <h2>Performance Considerations</h2>
 * 
 * <p>
 * All methods in this interface are designed for zero-allocation access:
 * <ul>
 * <li>Direct bit extraction from descriptor fields</li>
 * <li>No object allocation or copying</li>
 * <li>Constant-time O(1) access</li>
 * <li>Cache-friendly sequential memory access</li>
 * </ul>
 * 
 * @see Packet#receiveControl()
 * @see Packet#hasReceiveInfo()
 * @see TransmitControl
 * @see L2FrameType
 * @see PacketDescriptor
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public interface ReceiveControl {

	/**
	 * Returns the port number where this packet was received.
	 * 
	 * <p>
	 * The receive port identifies which network interface or queue received this
	 * packet. Port numbering is implementation-specific and typically starts at 0.
	 * The maximum port number depends on the capture backend and hardware
	 * configuration.
	 * 
	 * <p>
	 * Common port numbering schemes:
	 * <ul>
	 * <li><strong>Physical ports:</strong> Direct mapping to network interfaces
	 * (eth0=0, eth1=1, etc.)</li>
	 * <li><strong>Logical ports:</strong> May include virtual interfaces, VLANs, or
	 * sub-interfaces</li>
	 * <li><strong>Queue indices:</strong> For multi-queue NICs, may represent RSS
	 * queue number</li>
	 * </ul>
	 * 
	 * <h3>Port Number Ranges</h3>
	 * <ul>
	 * <li><strong>NetPacketDescriptor:</strong> 0-63 (6 bits)</li>
	 * <li><strong>DpdkDescriptor:</strong> 0-255 (8 bits)</li>
	 * <li><strong>NapatechDescriptor:</strong> 0-255 (8 bits)</li>
	 * </ul>
	 * 
	 * @return the receive port number, typically 0-63 or 0-255 depending on
	 *         implementation
	 */
	int rxPort();

	/**
	 * Returns the Layer 2 frame type of the received packet.
	 * 
	 * <p>
	 * The frame type identifies the data link layer protocol used to encapsulate
	 * this packet. This information is essential for correct protocol dissection as
	 * different frame types have different header structures and lengths.
	 * 
	 * <p>
	 * Common frame types include:
	 * <ul>
	 * <li>{@link L2FrameType#L2_FRAME_TYPE_ETHER} - Ethernet II (DIX)</li>
	 * <li>{@link L2FrameType#L2_FRAME_TYPE_IEEE80211} - WiFi 802.11</li>
	 * <li>{@link L2FrameType#L2_FRAME_TYPE_PPP} - Point-to-Point Protocol</li>
	 * <li>{@link L2FrameType#L2_FRAME_TYPE_LINUX_SLL} - Linux cooked capture</li>
	 * </ul>
	 * 
	 * <h3>Frame Type Detection</h3>
	 * <p>
	 * The frame type is typically determined by:
	 * <ul>
	 * <li>The capture interface type (Ethernet, WiFi, etc.)</li>
	 * <li>Pcap file linktype when reading from files</li>
	 * <li>Hardware configuration for specialized capture cards</li>
	 * </ul>
	 * 
	 * @return the L2 frame type enumeration constant
	 * @see L2FrameType
	 */
	L2FrameType l2FrameType();

	/**
	 * Returns whether the Layer 2 frame contains extensions that affect header
	 * length.
	 * 
	 * <p>
	 * Layer 2 extensions modify the standard frame structure and must be accounted
	 * for when calculating header lengths and offsets. When this method returns
	 * {@code true}, the L2 header parser should check for and process extensions.
	 * 
	 * <h3>Header Length Concepts</h3>
	 * <p>
	 * Headers in this framework have three distinct length measurements:
	 * <ul>
	 * <li><strong>Base Length:</strong> The static size of the core protocol
	 * structure (e.g., 14 bytes for basic Ethernet, 24 bytes for 802.11 MAC
	 * header)</li>
	 * <li><strong>Total Length:</strong> Base length plus any protocol-defined
	 * options (e.g., IP options, TCP options)</li>
	 * <li><strong>Extended Length:</strong> Base length plus protocol extensions
	 * that are technically separate protocols but modify the L2 frame structure
	 * (e.g., VLAN tags, MPLS labels)</li>
	 * </ul>
	 * 
	 * <p>
	 * This method specifically indicates the presence of <em>protocol
	 * extensions</em> that affect the extended length, not protocol options that
	 * affect total length.
	 * 
	 * <h3>Common L2 Extensions</h3>
	 * 
	 * <h4>Ethernet Extensions (affect extended length):</h4>
	 * <ul>
	 * <li><strong>VLAN tags (802.1Q):</strong> Adds 4 bytes per tag</li>
	 * <li><strong>Q-in-Q (802.1ad):</strong> Multiple stacked VLAN tags</li>
	 * <li><strong>MPLS labels:</strong> 4 bytes per label, can be stacked</li>
	 * </ul>
	 * 
	 * <h4>WiFi Extensions (affect extended length):</h4>
	 * <ul>
	 * <li><strong>QoS Control:</strong> 2 bytes for WMM/802.11e</li>
	 * <li><strong>HT Control:</strong> 4 bytes for 802.11n high throughput</li>
	 * </ul>
	 * 
	 * <h3>Length Calculation Example</h3>
	 * 
	 * <pre>{@code
	 * // Ethernet frame with VLAN tag
	 * // Base length: 14 bytes (dst MAC + src MAC + EtherType)
	 * // Extended length: 18 bytes (base + 4-byte VLAN tag)
	 * // Total length: 18 bytes (no options in Ethernet)
	 * 
	 * if (rx.hasL2Extensions()) {
	 * 	// Must scan for extensions to determine extended length
	 * 	int length = 14; // Base Ethernet length
	 * 	int etherType = packet.getShort(12) & 0xFFFF;
	 * 
	 * 	while (etherType == 0x8100 || etherType == 0x88A8) {
	 * 		length += 4; // Add VLAN tag length
	 * 		etherType = packet.getShort(length - 2) & 0xFFFF;
	 * 	}
	 * 	// length now contains the extended length
	 * }
	 * }</pre>
	 * 
	 * @return {@code true} if L2 protocol extensions are present, {@code false} for
	 *         standard frame
	 */
	boolean hasL2Extensions();
}