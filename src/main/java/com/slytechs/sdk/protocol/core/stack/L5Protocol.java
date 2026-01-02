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
package com.slytechs.sdk.protocol.core.stack;

/**
 * Marker interface for Layer 5+ (Application) protocol configurations.
 * 
 * <p>
 * L5 protocols include: HTTP, TLS, DNS, DHCP, SSH, etc.
 * </p>
 * 
 * <p>
 * jNetPcap caps at L4, so L5+ protocols are automatically disabled when
 * using ProtocolStack with jNetPcap:
 * </p>
 * <pre>{@code
 * // In NetPcap.create():
 * stack.disableLayer(L5Protocol.class);
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface L5Protocol extends LayerMarker {
    // Marker interface
}