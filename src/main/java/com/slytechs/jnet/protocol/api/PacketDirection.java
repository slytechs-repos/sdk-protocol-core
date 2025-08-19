package com.slytechs.jnet.protocol.api;

public enum PacketDirection {
	RX(0), TX(1), UNKNOWN(-1);

	private final int value;

	PacketDirection(int value) {
		this.value = value;
	}

	public int value() {
		return value;
	}

	public static PacketDirection valueOf(int value) {
		return switch (value) {
		case 0 -> RX;
		case 1 -> TX;
		case -1 -> UNKNOWN;

		default -> throw new IllegalArgumentException("unkown direction value " + value);
		};
	}
}