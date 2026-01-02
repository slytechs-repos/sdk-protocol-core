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
 * Exception thrown for protocol stack configuration and initialization errors.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public class ProtocolStackException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new exception with the specified message.
     *
     * @param message the detail message
     */
    public ProtocolStackException(String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the specified message and cause.
     *
     * @param message the detail message
     * @param cause   the cause
     */
    public ProtocolStackException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new exception with the specified cause.
     *
     * @param cause the cause
     */
    public ProtocolStackException(Throwable cause) {
        super(cause);
    }
}