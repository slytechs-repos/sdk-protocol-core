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
package com.slytechs.sdk.protocol.core.spi;

import java.util.ServiceLoader;

import com.slytechs.sdk.protocol.core.Protocol;
import com.slytechs.sdk.protocol.core.header.HeaderFactory;
import com.slytechs.sdk.protocol.core.pack.ProtocolPack;

/**
 * SPI entry point for protocol pack discovery and protocol lookup.
 *
 * <p>
 * Each protocol pack module provides a {@code PackProvider} implementation via
 * {@link ServiceLoader}. The provider serves as the single point of access for
 * all pack-level services including protocol metadata and header factory
 * lookup.
 * </p>
 *
 * <p>
 * Static lookup methods handle pack routing and caching transparently. The
 * first call for a given protocol ID triggers SPI discovery; subsequent calls
 * return cached results immediately.
 * </p>
 *
 * <h2>Usage</h2>
 *
 * {@snippet :
 * // Cached lookups — SPI only on first access
 * Protocol proto = PackProvider.lookupProtocol(ProtocolIds.IPv4);
 * HeaderFactory<?> factory = PackProvider.lookupHeaderFactory(ProtocolIds.TCP);
 *
 * // Direct provider access
 * PackProvider provider = PackProvider.lookupProvider(ProtocolIds.PACK_TCPIP);
 * ProtocolPack pack = provider.pack();
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see Protocol
 * @see ProtocolPack
 */
public interface PackProvider {

	/**
	 * Returns the protocol pack served by this provider.
	 *
	 * @return the protocol pack metadata
	 */
	ProtocolPack protocolPack();

	/**
	 * Finds a protocol by its full protocol ID within this pack.
	 *
	 * @param protocolId the full 32-bit protocol ID
	 * @return the protocol, or {@code null} if not found in this pack
	 */
	Protocol findProtocol(int protocolId);

	/**
	 * Finds a header factory for the given protocol ID within this pack.
	 *
	 * <p>
	 * Default implementation delegates to {@link #findProtocol(int)}. Providers may
	 * override for direct lookup.
	 * </p>
	 *
	 * @param protocolId the full 32-bit protocol ID
	 * @return the header factory, or {@code null} if not found
	 */
	default HeaderFactory<?> findHeaderFactory(int protocolId) {
		Protocol p = findProtocol(protocolId);
		return (p != null) ? p.headerFactory() : null;
	}

	/**
	 * Looks up the provider responsible for the given pack or protocol ID.
	 *
	 * @param packOrProtocolId a pack ID or full protocol ID
	 * @return the provider, or {@code null} if no pack is registered
	 */
	static PackProvider lookupProvider(int packOrProtocolId) {
		return PackProviderCache.findProvider(packOrProtocolId);
	}

	/**
	 * Looks up a protocol by its full protocol ID across all loaded packs.
	 *
	 * <p>
	 * Extracts the pack ID, routes to the correct provider, and caches the result.
	 * First call triggers SPI discovery if the pack has not been loaded yet.
	 * </p>
	 *
	 * @param protocolId the full 32-bit protocol ID
	 * @return the protocol, or {@code null} if not found
	 */
	static Protocol lookupProtocol(int protocolId) {
		return PackProviderCache.lookupProtocol(protocolId);
	}

	/**
	 * Looks up a header factory by protocol ID across all loaded packs.
	 *
	 * <p>
	 * This is the primary hot-path method for {@code Packet.toString()} and similar
	 * operations that need to instantiate headers by protocol ID. Results are
	 * cached after first lookup.
	 * </p>
	 *
	 * @param protocolId the full 32-bit protocol ID
	 * @return the header factory, or {@code null} if not found
	 */
	static HeaderFactory<?> lookupHeaderFactory(int protocolId) {
		return PackProviderCache.lookupHeaderFactory(protocolId);
	}
}