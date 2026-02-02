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
package com.slytechs.sdk.protocol.core.pack;

import java.util.List;

import com.slytechs.sdk.protocol.core.id.ProtocolId;

/**
 * Metadata and lifecycle state for a protocol pack module.
 *
 * <p>
 * A protocol pack groups related protocol definitions into a deployable unit.
 * Each pack is identified by a {@link PackId}, provides a human-readable name
 * and description, and exposes the list of protocol IDs it contains.
 * </p>
 *
 * <p>
 * Packs carry minimal runtime state: enabled/disabled status for administrative
 * control, and licensing status for commercially licensed packs. Protocol lookup
 * and header factory resolution are handled by
 * {@link com.slytechs.sdk.protocol.core.spi.PackProvider}, not by this
 * interface.
 * </p>
 *
 * <h2>Usage</h2>
 *
 * {@snippet :
 * PackProvider provider = PackProvider.lookupProvider(ProtocolIds.PACK_TCPIP);
 * ProtocolPack pack = provider.protocolPack();
 *
 * System.out.println(pack.name());          // "TCP/IP"
 * System.out.println(pack.packId());        // TCPIP
 * System.out.println(pack.protocols());     // [ETHERNET, VLAN, MPLS, IPv4, ...]
 * System.out.println(pack.isLicensed());    // true
 *
 * pack.setEnabled(false);                   // disable all protocols in this pack
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see PackId
 * @see com.slytechs.sdk.protocol.core.spi.PackProvider
 */
public interface ProtocolPack {

	/**
	 * Returns the pack identifier.
	 *
	 * @return the pack ID constant
	 */
	PackId packId();

	/**
	 * Returns the human-readable name of this pack.
	 *
	 * @return the pack name (e.g. "TCP/IP", "Web")
	 */
	String name();

	/**
	 * Returns a brief description of this pack's contents and purpose.
	 *
	 * @return the pack description
	 */
	String description();

	/**
	 * Checks whether this pack is currently enabled.
	 *
	 * <p>
	 * Disabled packs are excluded from protocol discovery and header resolution.
	 * </p>
	 *
	 * @return {@code true} if this pack is enabled
	 */
	boolean isEnabled();

	/**
	 * Enables or disables this pack.
	 *
	 * <p>
	 * Disabling a pack prevents its protocols from being discovered by
	 * {@link com.slytechs.sdk.protocol.core.spi.PackProvider} lookups. Already
	 * cached protocol references remain valid but will not be returned for new
	 * lookups.
	 * </p>
	 *
	 * @param enabled {@code true} to enable, {@code false} to disable
	 */
	void setEnabled(boolean enabled);

	/**
	 * Checks whether this pack is licensed for use.
	 *
	 * <p>
	 * All standard packs are freely licensed and return {@code true} by default.
	 * Specialized packs may require license activation, in which case this method
	 * reflects the current license state.
	 * </p>
	 *
	 * @return {@code true} if this pack is licensed (default: {@code true})
	 */
	default boolean isLicensed() {
		return true;
	}

	/**
	 * Returns the list of protocol IDs provided by this pack.
	 *
	 * <p>
	 * The returned list corresponds to the pack's protocol ID enum constants
	 * (e.g. {@code Tcpip.values()}). This is the pack's manifest of available
	 * protocols, not their full {@link com.slytechs.sdk.protocol.core.Protocol}
	 * definitions.
	 * </p>
	 *
	 * @return an unmodifiable list of protocol IDs in this pack
	 */
	List<? extends ProtocolId> protocols();
}