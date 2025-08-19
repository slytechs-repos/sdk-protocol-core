package com.slytechs.jnet.protocol.api.flag;

/**
 * Interface for individual flag definitions. Each flag represents a single bit
 * or bit field within a bitmask.
 */
public interface Flag {
	/**
	 * Returns the name of this flag.
	 */
	String name();

	/**
	 * Returns the bit mask for this flag.
	 */
	long mask();

	/**
	 * Returns the bit position (0-based) of this flag. For multi-bit flags, returns
	 * the position of the least significant bit.
	 */
	int position();

	/**
	 * Returns the number of bits this flag occupies.
	 */
	default int width() {
		return Long.bitCount(mask());
	}

	/**
	 * Returns true if this flag occupies only a single bit.
	 */
	default boolean isSingleBit() {
		return width() == 1;
	}

	/**
	 * Returns true if this flag occupies multiple bits (a bit field).
	 */
	default boolean isBitField() {
		return width() > 1;
	}

	/**
	 * Returns the maximum value this flag can hold.
	 */
	default long maxValue() {
		return mask() >>> position();
	}

	/**
	 * Validates that a value is valid for this flag.
	 */
	default boolean isValidValue(long value) {
		return value >= 0 && value <= maxValue();
	}
}