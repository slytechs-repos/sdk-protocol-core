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
package com.slytechs.jnet.protocol.api.table;

import java.lang.ref.WeakReference;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * A weak reference wrapper for TableLookup instances.
 * <p>
 * This class maintains a weak reference to an underlying TableLookup instance,
 * allowing it to be garbage collected when not in use. If the underlying table
 * is garbage collected, it will be automatically re-created on the next access
 * using the provided supplier function.
 * </p>
 * <p>
 * This design is ideal for use as static final constants in protocol definition
 * classes, as it provides efficient access while avoiding permanent memory
 * retention of potentially large lookup tables.
 * </p>
 * 
 * <h2>Usage Example:</h2>
 * 
 * <pre>{@code
 * public class TcpProtocol {
 * 	private static final TableLookup TCP_PORT_TABLE = new WeakTableLookup("tcpip", "tcp_port",
 * 			() -> TableRegistry.getInstance().getTable("tcpip", "tcp_port"));
 * 
 * 	public static String lookupPort(int port) {
 * 		StringTableValue value = TCP_PORT_TABLE.lookupString(String.valueOf(port));
 * 		return value != null ? value.getValue() : "Unknown";
 * 	}
 * }
 * }</pre>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @since 1.0
 */
public class WeakTableLookup implements TableLookup {

	private final String protocol;
	private final String tableName;
	private final Supplier<TableLookup> tableSupplier;
	private volatile WeakReference<TableLookup> tableRef;

	private Function<Object, String> keyFormatter = "%s"::formatted;

	private Function<String, String> unknownValue = "Unknown value (%s)"::formatted;

	public WeakTableLookup withUnknown(Function<String, String> unknownValue) {
		this.unknownValue = unknownValue;

		return this;
	}

	/**
	 * Creates a new WeakTableLookup with the specified parameters.
	 * 
	 * @param protocol      the protocol name (e.g., "tcpip", "web")
	 * @param tableName     the table name (e.g., "tcp_port", "ether_type")
	 * @param tableSupplier a supplier function that creates/retrieves the
	 *                      underlying table
	 * @throws NullPointerException if any parameter is null
	 */
	public WeakTableLookup(String protocol, String tableName, Supplier<TableLookup> tableSupplier) {
		this.protocol = Objects.requireNonNull(protocol, "protocol cannot be null");
		this.tableName = Objects.requireNonNull(tableName, "tableName cannot be null");
		this.tableSupplier = Objects.requireNonNull(tableSupplier, "tableSupplier cannot be null");
		this.tableRef = new WeakReference<>(null);
	}

	/**
	 * Creates a new WeakTableLookup that uses TableRegistry to retrieve tables.
	 * 
	 * @param protocol  the protocol name (e.g., "tcpip", "web")
	 * @param tableName the table name (e.g., "tcp_port", "ether_type")
	 * @throws NullPointerException if any parameter is null
	 */
	public WeakTableLookup(String protocol, String tableName) {
		this(protocol, tableName, () -> registryTableLookup(protocol, tableName));
	}

	private static TableLookup registryTableLookup(String protocol, String tableName) {
		TableRegistry registry = TableRegistry.getInstance();

		return registry.getTable(protocol, tableName);
	}

	/**
	 * Gets the underlying table, creating it if necessary.
	 * 
	 * @throws TableNotFoundException if the table cannot be created
	 */
	public TableLookup getTable() {
		TableLookup table = tableRef.get();

		if (table == null) {
			synchronized (this) {
				// Double-check after acquiring lock
				table = tableRef.get();
				if (table == null) {
					table = tableSupplier.get();
					if (table == null) {
						throw new TableNotFoundException(
								"Failed to create table: " + protocol + "/" + tableName);
					}
					tableRef = new WeakReference<>(table);
				}
			}
		}

		return table;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getProtocol() {
		return protocol;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getTableName() {
		return tableName;
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * This method retrieves the underlying table (creating it if necessary) and
	 * delegates the lookup operation to it.
	 * </p>
	 */
	@Override
	public StringTableValue lookupString(String key) {
		var val = getTable().lookupString(key);

		if (val == null)
			return new StringTableValue(unknownValue.apply(key));

		return val;
	}

	@Override
	public StringTableValue lookupString(int key) {
		var val = getTable().lookupString(keyFormatter.apply(key));

		if (val == null)
			return new StringTableValue(unknownValue.apply(keyFormatter.apply(key)));

		return val;
	}

	@Override
	public StringTableValue lookupString(int key, Locale locale) {
		var val = getTable().lookupString(keyFormatter.apply(key), locale);

		if (val == null)
			return new StringTableValue(unknownValue.apply(keyFormatter.apply(key)));

		return val;
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * This method retrieves the underlying table (creating it if necessary) and
	 * delegates the lookup operation to it.
	 * </p>
	 */
	@Override
	public StringTableValue lookupString(String key, Locale locale) {
		var val = getTable().lookupString(key, locale);

		if (val == null)
			return new StringTableValue(unknownValue.apply(key));

		return val;
	}

	/**
	 * Clears the weak reference to the underlying table, allowing it to be garbage
	 * collected immediately.
	 * <p>
	 * This method can be useful in memory-constrained environments where you want
	 * to proactively release the table memory.
	 * </p>
	 */
	public void clear() {
		synchronized (this) {
			tableRef = new WeakReference<>(null);
		}
	}

	/**
	 * Checks if the underlying table is currently loaded in memory.
	 * 
	 * @return true if the table is currently in memory, false if it has been
	 *         garbage collected or never loaded
	 */
	public boolean isLoaded() {
		return tableRef.get() != null;
	}

	/**
	 * Pre-loads the underlying table into memory.
	 * <p>
	 * This method can be useful to eagerly load the table during application
	 * initialization to avoid lazy loading delays during first access.
	 * </p>
	 * 
	 * @return this WeakTableLookup instance for method chaining
	 */
	public WeakTableLookup preload() {
		getTable();
		return this;
	}

	public WeakTableLookup usingKeyFormatter(Function<Object, String> keyFormatter) {
		this.keyFormatter = keyFormatter;
		return this;
	}

	@Override
	public String toString() {
		return String.format("WeakTableLookup[protocol=%s, table=%s, loaded=%s]",
				protocol, tableName, isLoaded());
	}
}