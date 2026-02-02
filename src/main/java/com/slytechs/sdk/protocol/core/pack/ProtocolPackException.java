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
package com.slytechs.sdk.protocol.core.pack;

/**
 * Signals an error during protocol pack operations.
 *
 * <p>
 * Thrown when a pack-related operation fails, such as SPI discovery errors,
 * pack initialization failures, or licensing violations. This is an unchecked
 * exception since pack errors typically represent configuration or deployment
 * problems rather than recoverable runtime conditions.
 * </p>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see ProtocolPack
 */
public class ProtocolPackException extends RuntimeException {

	private static final long serialVersionUID = -7249663824308873319L;

	/**
	 * Constructs a new protocol pack exception with no detail message.
	 */
	public ProtocolPackException() {}

	/**
	 * Constructs a new protocol pack exception with the specified detail message.
	 *
	 * @param message the detail message
	 */
	public ProtocolPackException(String message) {
		super(message);
	}

	/**
	 * Constructs a new protocol pack exception with the specified cause.
	 *
	 * @param cause the cause
	 */
	public ProtocolPackException(Throwable cause) {
		super(cause);
	}

	/**
	 * Constructs a new protocol pack exception with the specified detail message
	 * and cause.
	 *
	 * @param message the detail message
	 * @param cause   the cause
	 */
	public ProtocolPackException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Constructs a new protocol pack exception with full control over the
	 * exception properties.
	 *
	 * @param message            the detail message
	 * @param cause              the cause
	 * @param enableSuppression  whether suppression is enabled
	 * @param writableStackTrace whether the stack trace is writable
	 */
	public ProtocolPackException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

}