package com.slytechs.jnet.protocol.api.descriptor;
public interface ContextInfo {
    /**
     * Gets the port index the packet was received on or will be transmitted to.
     *
     * @return the port index
     */
    int port();

    /**
     * Gets the packet direction as a binary integer (0=RX, 1=TX, -1=UNKNOWN).
     *
     * @return the direction
     */
    int direction();

    /**
     * Gets the packet direction as an enum.
     *
     * @return the PacketDirection enum
     */
    PacketDirection directionEnum();

    /**
     * Gets application-specific user data.
     *
     * @return the user data
     */
    long userData();
}