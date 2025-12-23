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
package com.slytechs.sdk.protocol.core;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public record HeaderFactory<T extends Header>(
		Class<T> headerClass,
		ProxyCreated<T> proxy,
		ArenaAllocated<T> allocated,
		Reinterpreted<T> reintrepreted,
		Binding<T> binding) {

	public HeaderFactory(Class<T> headerClass) {
		this(headerClass,
				proxy(headerClass),
				allocated(headerClass),
				reinterpreted(headerClass),
				binding(headerClass)

		);
	}

	public interface ProxyCreated<T extends Header> {
		T newHeader();
	}

	public interface ArenaAllocated<T extends Header> {
		T newHeader(Arena arena);
	}

	public interface Reinterpreted<T extends Header> {
		T newHeader(MemorySegment pointer);
	}

	public interface Binding<T extends Header> {
		T newHeader(MemorySegment segment, long offset);
	}

	private static <T extends Header> ProxyCreated<T> proxy(Class<T> cl) {
		try {
			var con = cl.getDeclaredConstructor();
			if (isQualifed(cl, con) == false)
				return null;

			return () -> {
				try {
					return con.newInstance();
				} catch (InstantiationException | IllegalAccessException | IllegalArgumentException
						| InvocationTargetException e) {
					throw new IllegalStateException("unable to create header " + con, e);
				}
			};
		} catch (NoSuchMethodException | SecurityException e) {
			return null;
		}
	}

	private static <T extends Header> ArenaAllocated<T> allocated(Class<T> cl) {
		try {
			var con = cl.getDeclaredConstructor(Arena.class);
			if (isQualifed(cl, con) == false)
				return null;

			return arena -> {
				try {
					return con.newInstance(arena);
				} catch (InstantiationException | IllegalAccessException | IllegalArgumentException
						| InvocationTargetException e) {
					throw new IllegalStateException("unable to create header " + con, e);
				}
			};
		} catch (NoSuchMethodException | SecurityException e) {
			return null;
		}
	}

	private static <T extends Header> Reinterpreted<T> reinterpreted(Class<T> cl) {
		try {
			var con = cl.getDeclaredConstructor(MemorySegment.class);
			if (isQualifed(cl, con) == false)
				return null;

			return segment -> {
				try {
					return con.newInstance(segment);
				} catch (InstantiationException | IllegalAccessException | IllegalArgumentException
						| InvocationTargetException e) {
					throw new IllegalStateException("unable to create header " + con, e);
				}
			};
		} catch (NoSuchMethodException | SecurityException e) {
			return null;
		}
	}

	private static boolean isQualifed(Class<?> cl, Constructor<?> constructor) {
		// Qualify public constructors in non-abstract classes
		return (constructor.getModifiers() & Modifier.PUBLIC) != 0
				&& (cl.getModifiers() & Modifier.ABSTRACT) == 0;
	}

	private static <T extends Header> Binding<T> binding(Class<T> cl) {
		try {
			var con = cl.getDeclaredConstructor(MemorySegment.class, Long.class);
			if (isQualifed(cl, con) == false)
				return null;

			return (segment, offset) -> {
				try {
					return con.newInstance(segment, offset);
				} catch (InstantiationException | IllegalAccessException | IllegalArgumentException
						| InvocationTargetException e) {
					throw new IllegalStateException("unable to create header " + con, e);
				}
			};
		} catch (NoSuchMethodException | SecurityException e) {
			return null;
		}
	}
}
