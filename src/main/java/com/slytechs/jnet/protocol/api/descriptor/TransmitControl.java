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
 * Provides control over packet transmission parameters and hardware offload
 * features.
 * 
 * <p>
 * The {@code TransmitControl} interface defines methods for configuring how
 * packets are transmitted by network interfaces, including port selection,
 * timing control, and hardware offload features. This interface is implemented
 * by packet descriptors that support transmission capabilities, such as
 * {@code NetPacketDescriptorDeprecated}, {@code DpdkDescriptor}, and
 * {@code NapatechDescriptor}.
 * 
 * <h2>Design Philosophy</h2>
 * 
 * <p>
 * This interface follows a fluent API pattern where all setter methods return
 * {@code this}, enabling method chaining for efficient configuration without
 * allocating temporary objects. This design is critical for high-performance
 * packet processing at rates exceeding 100 million packets per second.
 * 
 * <h2>Transmission Parameters</h2>
 * 
 * <p>
 * The interface provides control over several aspects of packet transmission:
 * 
 * <ul>
 * <li><strong>Port Selection:</strong> Directs packets to specific output
 * ports</li>
 * <li><strong>Transmission Control:</strong> Enables/disables packet
 * transmission</li>
 * <li><strong>Timing Control:</strong> Manages when packets are
 * transmitted</li>
 * <li><strong>Hardware Offloads:</strong> Controls CRC calculation and other
 * features</li>
 * </ul>
 * 
 * <h2>Usage Examples</h2>
 * 
 * <h3>Basic Transmission Configuration</h3>
 * 
 * <pre>{@code
 * Packet packet = txBuffer.getPacket(0);
 * 
 * // Configure transmission using fluent API
 * packet.transmitControl()
 * 		.setTxPort(2) // Send to port 2
 * 		.setTxEnabled(true) // Enable transmission
 * 		.setTxImmediate(false) // Respect packet timing
 * 		.setTxCrcRecalc(true); // Recalculate CRC
 * }</pre>
 * 
 * <h3>Replay with Original Timing</h3>
 * 
 * <pre>{@code
 * // Replay captured packets maintaining original timing
 * public void replayWithTiming(List<Packet> packets) {
 * 	boolean firstPacket = true;
 * 
 * 	for (Packet packet : packets) {
 * 		if (packet.canTransmit()) {
 * 			TransmitControl tx = packet.transmitControl();
 * 
 * 			if (firstPacket) {
 * 				// Sync clock with first packet's timestamp
 * 				tx.setTxTimestampSync(true)
 * 						.setTxImmediate(false); // Preserve inter-frame gaps
 * 				firstPacket = false;
 * 			} else {
 * 				// Subsequent packets maintain timing relationships
 * 				tx.setTxTimestampSync(false)
 * 						.setTxImmediate(false);
 * 			}
 * 
 * 			tx.setTxEnabled(true);
 * 		}
 * 	}
 * }
 * }</pre>
 * 
 * <h3>High-Speed Forwarding</h3>
 * 
 * <pre>{@code
 * // Fast packet forwarding without timing preservation
 * public void fastForward(Packet packet, int outPort) {
 * 	packet.transmitControl()
 * 			.setTxPort(outPort)
 * 			.setTxEnabled(true)
 * 			.setTxImmediate(true) // Send immediately
 * 			.setTxCrcRecalc(false); // Use existing CRC for speed
 * }
 * }</pre>
 * 
 * <h2>Hardware Support</h2>
 * 
 * <p>
 * Not all network interfaces support all transmission features. Applications
 * should use {@link Packet#canTransmit()} to verify that transmission control
 * is available before attempting to configure transmission parameters.
 * 
 * <p>
 * When transmission control is not supported, implementations may either:
 * <ul>
 * <li>Silently ignore the settings (NoOp implementation)</li>
 * <li>Throw {@code UnsupportedOperationException}</li>
 * <li>Return {@code false} from {@link Packet#canTransmit()}</li>
 * </ul>
 * 
 * <h2>Thread Safety</h2>
 * 
 * <p>
 * Implementations of this interface are typically not thread-safe. Each thread
 * should work with its own packet instances to avoid synchronization overhead
 * in high-performance scenarios.
 * 
 * <h2>Performance Considerations</h2>
 * 
 * <p>
 * The fluent API design enables efficient packet configuration without object
 * allocation:
 * <ul>
 * <li>All setters return {@code this} for method chaining</li>
 * <li>No temporary objects are created during configuration</li>
 * <li>Bit manipulation is used internally for compact storage</li>
 * <li>Methods can be inlined by the JIT compiler</li>
 * </ul>
 * 
 * @see Packet#transmitControl()
 * @see Packet#canTransmit()
 * @see ReceiveControl
 * @see PacketDescriptor
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public interface TransmitControl {

	/**
	 * Sets the transmission port number for this packet.
	 * 
	 * <p>
	 * The port number identifies which network interface or queue should be used to
	 * transmit this packet. Valid port numbers are implementation-specific and
	 * typically range from 0 to the number of available ports minus one.
	 * 
	 * <p>
	 * Port numbering schemes vary by implementation:
	 * <ul>
	 * <li><strong>Physical ports:</strong> Maps directly to network interfaces</li>
	 * <li><strong>Virtual ports:</strong> May map to VLANs or virtual
	 * interfaces</li>
	 * <li><strong>Queue indices:</strong> For multi-queue NICs with RSS/RFS</li>
	 * </ul>
	 * 
	 * @param port the transmission port number (typically 0-255 or 0-63 depending
	 *             on the implementation)
	 * @return this instance for method chaining
	 * @throws IllegalArgumentException if the port number exceeds the supported
	 *                                  range
	 * 
	 * @see #txPort()
	 */
	TransmitControl setTxPort(int port);

	/**
	 * Enables or disables packet transmission.
	 * 
	 * <p>
	 * When enabled, the packet will be transmitted when the containing buffer is
	 * released or flushed. When disabled, the packet is skipped during transmission
	 * even if present in a transmit buffer.
	 * 
	 * <p>
	 * This flag is useful for:
	 * <ul>
	 * <li>Selective packet filtering during replay</li>
	 * <li>Conditional transmission based on runtime criteria</li>
	 * <li>Debugging and testing scenarios</li>
	 * </ul>
	 * 
	 * @param enabled {@code true} to enable transmission, {@code false} to disable
	 * @return this instance for method chaining
	 * 
	 * @see #isTxEnabled()
	 */
	TransmitControl setTxEnabled(boolean enabled);

	/**
	 * Sets whether the packet should be transmitted immediately.
	 * 
	 * <p>
	 * When set to {@code true}, the packet is transmitted as soon as possible
	 * without regard to timing constraints or inter-frame gaps. When set to
	 * {@code false}, the packet transmission respects timing relationships with
	 * other packets, maintaining inter-frame gaps and rate limits.
	 * 
	 * <h3>Timing Modes</h3>
	 * <ul>
	 * <li><strong>Immediate ({@code true}):</strong> Maximum throughput mode,
	 * packets are sent back-to-back at line rate</li>
	 * <li><strong>Timed ({@code false}):</strong> Preserves original packet timing,
	 * useful for accurate replay scenarios</li>
	 * </ul>
	 * 
	 * <h3>Use Cases</h3>
	 * 
	 * <pre>{@code
	 * // High-speed forwarding
	 * packet.transmitControl().setTxImmediate(true);
	 * 
	 * // Accurate replay with timing preservation
	 * packet.transmitControl().setTxImmediate(false);
	 * }</pre>
	 * 
	 * @param immediate {@code true} for immediate transmission, {@code false} to
	 *                  respect timing constraints
	 * @return this instance for method chaining
	 * 
	 * @see #isTxImmediate()
	 * @see #setTxTimestampSync(boolean)
	 */
	TransmitControl setTxImmediate(boolean immediate);

	/**
	 * Sets whether to recalculate the CRC (Cyclic Redundancy Check) on
	 * transmission.
	 * 
	 * <p>
	 * When enabled, the network interface recalculates the Ethernet FCS (Frame
	 * Check Sequence) before transmission. This is necessary when:
	 * <ul>
	 * <li>Packet contents have been modified</li>
	 * <li>The original CRC is invalid or missing</li>
	 * <li>Testing CRC calculation functionality</li>
	 * </ul>
	 * 
	 * <p>
	 * When disabled, the existing CRC is transmitted unchanged, which is faster but
	 * requires the CRC to be valid.
	 * 
	 * <h3>Hardware Support</h3>
	 * <p>
	 * CRC offload capability varies by network interface. Some NICs always
	 * recalculate CRC regardless of this setting, while others require explicit
	 * configuration.
	 * 
	 * @param recalc {@code true} to recalculate CRC, {@code false} to use existing
	 * @return this instance for method chaining
	 * 
	 * @see #isTxCrcRecalc()
	 */
	TransmitControl setTxCrcRecalc(boolean recalc);

	/**
	 * Sets whether to synchronize transmission with the packet's timestamp.
	 * 
	 * <p>
	 * When enabled, the transmission hardware uses the packet's timestamp to
	 * determine when to transmit. This is typically used for the first packet in a
	 * replay sequence to establish the timing reference.
	 * 
	 * <h3>Timestamp Synchronization</h3>
	 * <p>
	 * The synchronization behavior depends on the hardware capabilities:
	 * <ul>
	 * <li><strong>Hardware timing:</strong> Packet is held until its timestamp
	 * matches the hardware clock</li>
	 * <li><strong>Software timing:</strong> Driver delays transmission based on
	 * timestamp comparison</li>
	 * <li><strong>Relative timing:</strong> Maintains time deltas between
	 * packets</li>
	 * </ul>
	 * 
	 * <h3>Typical Usage Pattern</h3>
	 * 
	 * <pre>{@code
	 * boolean firstPacket = true;
	 * for (Packet packet : packets) {
	 * 	if (firstPacket) {
	 * 		// Sync clock with first packet
	 * 		packet.transmitControl()
	 * 				.setTxTimestampSync(true)
	 * 				.setTxImmediate(false);
	 * 		firstPacket = false;
	 * 	} else {
	 * 		// Subsequent packets use relative timing
	 * 		packet.transmitControl()
	 * 				.setTxTimestampSync(false)
	 * 				.setTxImmediate(false);
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * @param sync {@code true} to sync with timestamp, {@code false} for normal
	 *             timing
	 * @return this instance for method chaining
	 * 
	 * @see #isTxTimestampSync()
	 * @see #setTxImmediate(boolean)
	 */
	TransmitControl setTxTimestampSync(boolean sync);

	/**
	 * Returns the configured transmission port number.
	 * 
	 * <p>
	 * The port number indicates which network interface or queue will be used for
	 * transmission. A value of 0 typically indicates the default port.
	 * 
	 * @return the transmission port number
	 * @see #setTxPort(int)
	 */
	int txPort();

	/**
	 * Returns whether packet transmission is enabled.
	 * 
	 * <p>
	 * When {@code true}, the packet will be transmitted when the buffer is
	 * released. When {@code false}, the packet will be skipped.
	 * 
	 * @return {@code true} if transmission is enabled, {@code false} otherwise
	 * @see #setTxEnabled(boolean)
	 */
	boolean isTxEnabled();

	/**
	 * Returns whether immediate transmission is configured.
	 * 
	 * <p>
	 * When {@code true}, the packet will be transmitted immediately without timing
	 * constraints. When {@code false}, timing relationships are preserved.
	 * 
	 * @return {@code true} if immediate transmission is set, {@code false}
	 *         otherwise
	 * @see #setTxImmediate(boolean)
	 */
	boolean isTxImmediate();

	/**
	 * Returns whether CRC recalculation is enabled.
	 * 
	 * <p>
	 * When {@code true}, the network interface will recalculate the FCS before
	 * transmission. When {@code false}, the existing CRC is used.
	 * 
	 * @return {@code true} if CRC recalculation is enabled, {@code false} otherwise
	 * @see #setTxCrcRecalc(boolean)
	 */
	boolean isTxCrcRecalc();

	/**
	 * Returns whether timestamp synchronization is enabled.
	 * 
	 * <p>
	 * When {@code true}, transmission timing is synchronized with the packet's
	 * timestamp. This is typically used for the first packet in a replay sequence.
	 * 
	 * @return {@code true} if timestamp sync is enabled, {@code false} otherwise
	 * @see #setTxTimestampSync(boolean)
	 */
	boolean isTxTimestampSync();
}