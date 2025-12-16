/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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
package com.slytechs.jnet.protocol.api.table;

/**
 * Exception thrown when a requested table or protocol is not found.
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public class TableNotFoundException extends RuntimeException {

	private static final long serialVersionUID = 2652736480136164538L;

	/**
	 * Constructs a new TableNotFoundException with the specified message.
	 *
	 * @param message the detail message
	 */
	public TableNotFoundException(String message) {
		super(message);
	}

	/**
	 * Constructs a new TableNotFoundException with the specified message and cause.
	 *
	 * @param message the detail message
	 * @param cause   the cause of the exception
	 */
	public TableNotFoundException(String message, Throwable cause) {
		super(message, cause);
	}
}