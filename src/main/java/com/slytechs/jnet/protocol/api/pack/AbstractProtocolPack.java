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
package com.slytechs.jnet.protocol.api.pack;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Base implementation for all protocol packs.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public abstract class AbstractProtocolPack implements ProtocolPack {

	private final int id;
	private final String name;
	private final String description;
	protected final AtomicBoolean loaded = new AtomicBoolean();
	protected final AtomicBoolean enabled = new AtomicBoolean();

	public AbstractProtocolPack(int id, String name, String description) {
		this.id = id;
		this.name = name;
		this.description = description;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.pack.ProtocolPack#name()
	 */
	@Override
	public final String name() {
		return name;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.pack.ProtocolPack#description()
	 */
	@Override
	public final String description() {
		return description;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.pack.ProtocolPack#isLoaded()
	 */
	@Override
	public final boolean isLoaded() {
		return loaded.get();
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.pack.ProtocolPack#isEnabled()
	 */
	@Override
	public final boolean isEnabled() {
		return enabled.get();
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.pack.ProtocolPack#setEnable(boolean)
	 */
	@Override
	public final void setEnable(boolean b) {
		if (b && enabled.compareAndSet(false, true)) {

		}
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.pack.ProtocolPack#id()
	 */
	@Override
	public final int id() {
		return id;
	}

}
