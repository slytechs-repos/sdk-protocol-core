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

/**
 * Protocol pack management and SPI discovery for modular protocol deployment.
 *
 * <p>
 * A protocol pack is a self-contained module that provides a set of related
 * protocol definitions to the SDK. Packs are discovered at runtime via
 * {@link java.util.ServiceLoader} through the
 * {@link com.slytechs.sdk.protocol.core.spi.PackProvider} SPI interface,
 * allowing protocol support to be added or removed simply by including or
 * excluding the corresponding module on the module path.
 * </p>
 *
 * <h2>Pack Architecture</h2>
 *
 * <p>
 * Each protocol pack consists of three components:
 * </p>
 *
 * <dl>
 * <dt>Protocol ID table (e.g. {@code Tcpip} enum)</dt>
 * <dd>A {@link com.slytechs.sdk.protocol.core.id.ProtocolId} enum that declares
 * the protocols in the pack, referencing int constants from
 * {@link com.slytechs.sdk.protocol.core.id.ProtocolIds}.</dd>
 *
 * <dt>Pack metadata (e.g. {@code TcpipPack})</dt>
 * <dd>A {@link com.slytechs.sdk.protocol.core.pack.ProtocolPack} implementation
 * providing pack identity, lifecycle state, and the list of protocol IDs.</dd>
 *
 * <dt>Pack provider (e.g. {@code TcpipProvider})</dt>
 * <dd>A {@link com.slytechs.sdk.protocol.core.spi.PackProvider} implementation
 * registered via {@code module-info.java} that maps protocol IDs to
 * {@link com.slytechs.sdk.protocol.core.Protocol} instances.</dd>
 * </dl>
 *
 * <h2>Available Packs</h2>
 *
 * <p>
 * The SDK ships with the following protocol packs, each in its own module:
 * </p>
 *
 * <table>
 * <caption>Protocol pack modules</caption>
 * <tr>
 * <th>{@link com.slytechs.sdk.protocol.core.pack.PackId PackId}</th>
 * <th>Module</th>
 * <th>Description</th>
 * </tr>
 * <tr>
 * <td>{@link com.slytechs.sdk.protocol.core.pack.PackId#BUILTIN BUILTIN}</td>
 * <td>{@code sdk-protocol-core}</td>
 * <td>System protocols (PAYLOAD, UNKNOWN, PAD)</td>
 * </tr>
 * <tr>
 * <td>{@link com.slytechs.sdk.protocol.core.pack.PackId#TCPIP TCPIP}</td>
 * <td>{@code sdk-protocol-tcpip}</td>
 * <td>Core TCP/IP stack (Ethernet, IP, TCP, UDP, etc.)</td>
 * </tr>
 * <tr>
 * <td>{@link com.slytechs.sdk.protocol.core.pack.PackId#WEB WEB}</td>
 * <td>{@code sdk-protocol-web}</td>
 * <td>Application layer (HTTP, HTML, TLS, DNS, etc.)</td>
 * </tr>
 * </table>
 *
 * <h2>Pack Discovery</h2>
 *
 * <p>
 * Pack providers are discovered automatically when a protocol lookup is
 * performed. The static methods on
 * {@link com.slytechs.sdk.protocol.core.spi.PackProvider} extract the pack ID
 * from a protocol ID, route to the correct provider, and cache results for
 * subsequent lookups.
 * </p>
 *
 * {@snippet :
 * // Lookup is transparent — SPI discovery and caching happen automatically
 * Protocol tcp = PackProvider.lookupProtocol(ProtocolIds.TCP);
 * HeaderFactory<?> factory = PackProvider.lookupHeaderFactory(ProtocolIds.IPv4);
 *
 * // Pack metadata is available through the provider
 * PackProvider provider = PackProvider.lookupProvider(ProtocolIds.PACK_TCPIP);
 * ProtocolPack pack = provider.protocolPack();
 * System.out.println(pack.name());        // "TCP/IP"
 * System.out.println(pack.isEnabled());   // true
 * System.out.println(pack.isLicensed());  // true
 * }
 *
 * <h2>Module Registration</h2>
 *
 * <p>
 * Each pack module registers its provider in {@code module-info.java}:
 * </p>
 *
 * {@snippet :
 * module com.slytechs.sdk.protocol.tcpip {
 * 	provides com.slytechs.sdk.protocol.core.spi.PackProvider
 * 			with com.slytechs.sdk.protocol.tcpip.impl.TcpipProvider;
 * }
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see com.slytechs.sdk.protocol.core.spi.PackProvider
 * @see com.slytechs.sdk.protocol.core.id.ProtocolIds
 */
package com.slytechs.sdk.protocol.core.pack;