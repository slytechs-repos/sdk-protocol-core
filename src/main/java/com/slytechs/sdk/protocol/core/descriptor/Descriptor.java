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
package com.slytechs.sdk.protocol.core.descriptor;

/**
 * Base interface for all descriptor types in the packet processing framework.
 * 
 * <p>
 * Descriptors are compact, memory-efficient data structures that store metadata
 * about packets, headers, and protocol-specific information. They serve as the
 * foundation for the framework's high-performance packet dissection and
 * analysis capabilities.
 * 
 * <h2>Descriptor Hierarchy</h2>
 * 
 * <p>
 * The descriptor system follows a hierarchical structure:
 * 
 * <pre>
 *                    Descriptor
 *                        │
 *         ┌──────────────┼──────────────┐
 *         │              │              │
 *   PacketDescriptor  HeaderDescriptor  PacketTag
 *         │              │              │
 *    ┌────┴────┐    ┌────┴────┐    ┌───┴───┐
 *   Type1  Type2   Type1  Type2   IpfTag  TcpTag
 * </pre>
 * 
 * <h2>Descriptor Types</h2>
 * 
 * <p>
 * Different descriptor types provide varying levels of detail and
 * functionality:
 * <ul>
 * <li><strong>TYPE1:</strong> Basic descriptors with minimal metadata
 * (fastest)</li>
 * <li><strong>TYPE2:</strong> Extended descriptors with detailed protocol
 * information</li>
 * <li><strong>TYPE3:</strong> Full descriptors with complete metadata and
 * annotations</li>
 * </ul>
 * 
 * <h2>Memory Layout</h2>
 * 
 * <p>
 * Descriptors are designed for cache-efficiency and minimal memory footprint:
 * 
 * <pre>{@code
 * // Typical descriptor memory layout (Type2 example)
 * +--------+--------+--------+--------+
 * | Type   | ID     | Length | Flags  |  // 16 bytes header
 * +--------+--------+--------+--------+
 * | Protocol-specific data...         |  // Variable length
 * +------------------------------------+
 * }</pre>
 * 
 * <h2>Usage Patterns</h2>
 * 
 * <h3>Type Checking</h3>
 * 
 * <pre>{@code
 * Descriptor desc = packet.getDescriptor();
 * 
 * // Check descriptor type for capabilities
 * switch (desc.type()) {
 * case TYPE1:
 * 	// Basic processing only
 * 	processBasic(desc);
 * 	break;
 * case TYPE2:
 * 	// Extended processing available
 * 	Type2Descriptor type2 = (Type2Descriptor) desc;
 * 	processExtended(type2);
 * 	break;
 * case TYPE3:
 * 	// Full processing with annotations
 * 	Type3Descriptor type3 = (Type3Descriptor) desc;
 * 	processComplete(type3);
 * 	break;
 * }
 * }</pre>
 * 
 * <h3>Descriptor Validation</h3>
 * 
 * <pre>{@code
 * public boolean isValidDescriptor(Descriptor desc) {
 * 	// Validate descriptor integrity
 * 	if (desc.type() == null) {
 * 		return false;
 * 	}
 * 
 * 	// Check length constraints
 * 	int length = desc.length();
 * 	if (length < MIN_DESCRIPTOR_SIZE || length > MAX_DESCRIPTOR_SIZE) {
 * 		return false;
 * 	}
 * 
 * 	// Verify ID is within valid range
 * 	int id = desc.id();
 * 	return id >= 0 && id < MAX_DESCRIPTOR_ID;
 * }
 * }</pre>
 * 
 * <h2>Performance Considerations</h2>
 * 
 * <p>
 * Descriptors are optimized for high-performance packet processing:
 * <ul>
 * <li>Compact memory layout minimizes cache misses</li>
 * <li>Fixed-size headers enable efficient array storage</li>
 * <li>Type-based dispatch avoids virtual method calls</li>
 * <li>Direct memory access patterns for predictable performance</li>
 * </ul>
 * 
 * <h2>Thread Safety</h2>
 * 
 * <p>
 * Descriptors are immutable once created and can be safely shared between
 * threads. However, descriptor creation and modification should be performed by
 * a single thread or protected by appropriate synchronization.
 * 
 * @see PacketDescriptor
 * @see DescriptorType
 * @see PacketTag
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public interface Descriptor {

	/**
	 * Returns the type of this descriptor.
	 * 
	 * <p>
	 * The descriptor type determines the level of detail and available operations.
	 * Higher type numbers generally indicate more comprehensive descriptors with
	 * additional metadata and functionality.
	 * 
	 * <h3>Type Characteristics</h3>
	 * <table border="1">
	 * <caption>Descriptor Type Comparison</caption>
	 * <tr>
	 * <th>Type</th>
	 * <th>Size</th>
	 * <th>Features</th>
	 * <th>Use Case</th>
	 * </tr>
	 * <tr>
	 * <td>TYPE1</td>
	 * <td>16-32 bytes</td>
	 * <td>Basic protocol presence</td>
	 * <td>Fast filtering, routing decisions</td>
	 * </tr>
	 * <tr>
	 * <td>TYPE2</td>
	 * <td>64-128 bytes</td>
	 * <td>Header offsets and lengths</td>
	 * <td>Protocol analysis, statistics</td>
	 * </tr>
	 * <tr>
	 * <td>TYPE3</td>
	 * <td>256+ bytes</td>
	 * <td>Full metadata and annotations</td>
	 * <td>Deep packet inspection, forensics</td>
	 * </tr>
	 * </table>
	 * 
	 * <h3>Example: Type-Based Processing</h3>
	 * 
	 * <pre>{@code
	 * public void processDescriptor(Descriptor desc) {
	 * 	DescriptorType type = desc.type();
	 * 
	 * 	// Log descriptor type for monitoring
	 * 	logger.debug("Processing {} descriptor, ID: {}, Length: {}",
	 * 			type, desc.id(), desc.length());
	 * 
	 * 	// Dispatch based on type
	 * 	switch (type) {
	 * 	case TYPE1 -> processMinimal(desc);
	 * 	case TYPE2 -> processStandard(desc);
	 * 	case TYPE3 -> processExtended(desc);
	 * 	default -> logger.warn("Unknown descriptor type: {}", type);
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * @return the descriptor type, never {@code null}
	 * @see DescriptorType
	 */
	default DescriptorType descriptorType() {
		return descriptorInfo();
	}

	DescriptorInfo descriptorInfo();

	/**
	 * Returns the unique identifier for this descriptor.
	 * 
	 * <p>
	 * The ID serves multiple purposes depending on the descriptor context:
	 * <ul>
	 * <li>For packet descriptors: Packet sequence number or flow ID</li>
	 * <li>For header descriptors: Protocol ID (e.g., 6 for TCP, 17 for UDP)</li>
	 * <li>For NetTags: Tag type identifier</li>
	 * </ul>
	 * 
	 * <h3>ID Ranges</h3>
	 * <p>
	 * IDs are typically organized in ranges for different purposes:
	 * 
	 * <pre>
	 * 0x0000-0x00FF : Core protocols (Ethernet, IP, TCP, UDP)
	 * 0x0100-0x01FF : Application protocols (HTTP, DNS, TLS)
	 * 0x0200-0x02FF : Enterprise protocols (LDAP, SMB, Database)
	 * 0x0300-0x03FF : Telecom protocols (SIP, RTP, Diameter)
	 * 0x1000-0xFFFF : User-defined and experimental protocols
	 * </pre>
	 * 
	 * <h3>Example: Protocol Identification</h3>
	 * 
	 * <pre>{@code
	 * public String getProtocolName(Descriptor desc) {
	 * 	int id = desc.id();
	 * 
	 * 	return switch (id) {
	 * 	case 0x0001 -> "Ethernet";
	 * 	case 0x0800 -> "IPv4";
	 * 	case 0x86DD -> "IPv6";
	 * 	case 0x0006 -> "TCP";
	 * 	case 0x0011 -> "UDP";
	 * 	case 0x0050 -> "HTTP";
	 * 	default -> "Unknown (0x" + Integer.toHexString(id) + ")";
	 * 	};
	 * }
	 * }</pre>
	 * 
	 * @return the descriptor identifier, typically non-negative
	 */
	default int descriptorId() {
		return descriptorInfo().descriptorId();
	}

	/**
	 * Returns the total length of this descriptor in bytes.
	 * 
	 * <p>
	 * The length includes both the descriptor header and any variable-length data
	 * associated with the descriptor. This value is critical for:
	 * <ul>
	 * <li>Memory allocation and buffer management</li>
	 * <li>Descriptor traversal in chained structures</li>
	 * <li>Validation and bounds checking</li>
	 * <li>Serialization and deserialization</li>
	 * </ul>
	 * 
	 * <h3>Length Calculation</h3>
	 * 
	 * <pre>
	 * Total Length = Fixed Header Size + Variable Data Size
	 * 
	 * For Type1: 16 bytes (fixed)
	 * For Type2: 16 bytes (header) + protocol data
	 * For Type3: 32 bytes (header) + metadata + annotations
	 * </pre>
	 * 
	 * <h3>Example: Descriptor Chain Traversal</h3>
	 * 
	 * <pre>{@code
	 * public void traverseDescriptorChain(ByteBuffer buffer) {
	 * 	while (buffer.hasRemaining()) {
	 * 		// Read descriptor header
	 * 		int position = buffer.position();
	 * 		Descriptor desc = readDescriptor(buffer);
	 * 
	 * 		// Validate descriptor length
	 * 		int length = desc.length();
	 * 		if (length <= 0 || length > buffer.remaining()) {
	 * 			throw new MalformedDescriptorException(
	 * 					"Invalid descriptor length: " + length);
	 * 		}
	 * 
	 * 		// Process descriptor
	 * 		processDescriptor(desc);
	 * 
	 * 		// Move to next descriptor
	 * 		buffer.position(position + length);
	 * 	}
	 * }
	 * }</pre>
	 * 
	 * <h3>Memory Efficiency</h3>
	 * 
	 * <pre>{@code
	 * // Calculate memory usage for descriptor array
	 * public long calculateMemoryUsage(Descriptor[] descriptors) {
	 * 	long totalBytes = 0;
	 * 
	 * 	for (Descriptor desc : descriptors) {
	 * 		totalBytes += desc.length();
	 * 	}
	 * 
	 * 	// Add object overhead (estimated)
	 * 	totalBytes += descriptors.length * 16; // Object headers
	 * 
	 * 	return totalBytes;
	 * }
	 * }</pre>
	 * 
	 * @return the total length in bytes, always positive
	 */
	long length();
}
