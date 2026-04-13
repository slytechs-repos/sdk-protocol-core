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
package com.slytechs.sdk.protocol.core.spi;

import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;

import com.slytechs.sdk.protocol.core.Protocol;
import com.slytechs.sdk.protocol.core.header.HeaderFactory;
import com.slytechs.sdk.protocol.core.id.ProtocolIds;

/**
 * Lazy SPI discovery and caching for pack provider lookups.
 *
 * @apiNote Internal implementation detail. Do not use directly.
 */
final class PackProviderCache {

	private static final ServiceLoader<PackProvider> loader = ServiceLoader.load(PackProvider.class);
	private static final ConcurrentHashMap<Integer, PackProvider> providers = new ConcurrentHashMap<>();
	private static final ConcurrentHashMap<Integer, Protocol> protocols = new ConcurrentHashMap<>();
	private static final ConcurrentHashMap<Integer, HeaderFactory<?>> factories = new ConcurrentHashMap<>();
	private static volatile boolean loaded;

	private PackProviderCache() {}

	private static void ensureLoaded() {
		if (!loaded) {
			synchronized (PackProviderCache.class) {
				if (!loaded) {
					loader.stream()
							.map(ServiceLoader.Provider::get)
							.forEach(p -> providers.put(p.protocolPack().packId().id(), p));
					loaded = true;
				}
			}
		}
	}

	public static PackProvider findProvider(int packOrProtocolId) {
		ensureLoaded();
		int packId = ProtocolIds.packId(packOrProtocolId);
		return providers.get(packId);
	}

	public static Protocol lookupProtocol(int protocolId) {
		int key = ProtocolIds.descriptorId(protocolId);
		Protocol cached = protocols.get(key);
		if (cached != null)
			return cached;

		PackProvider provider = findProvider(protocolId);
		if (provider == null)
			return null;

		Protocol protocol = provider.findProtocol(protocolId);
		if (protocol != null)
			protocols.put(key, protocol);

		return protocol;
	}

	public static HeaderFactory<?> lookupHeaderFactory(int protocolId) {
		int key = ProtocolIds.descriptorId(protocolId);
		HeaderFactory<?> cached = factories.get(key);
		if (cached != null)
			return cached;

		PackProvider provider = findProvider(protocolId);
		if (provider == null)
			return null;

		HeaderFactory<?> factory = provider.findHeaderFactory(protocolId);
		if (factory != null)
			factories.put(key, factory);

		return factory;
	}
}