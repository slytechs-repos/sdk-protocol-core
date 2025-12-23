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
package com.slytechs.sdk.protocol.core.descriptor;

import java.util.EnumSet;

/**
 * Packet flag enum with metadata.
 * 
 * <p>
 * Implements {@link PacketFlag} for type-safe usage while providing
 * rich functionality like flag testing and set operations.
 * </p>
 *
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 */
public enum PacketFlagInfo implements PacketFlag {

    // ========== RX FLAGS (bits 0-20) ==========
    
    RX_VLAN(PacketFlag.RX_VLAN, "RX_VLAN", "VLAN tag present"),
    RX_RSS_HASH(PacketFlag.RX_RSS_HASH, "RX_RSS_HASH", "RSS hash computed"),
    RX_FDIR(PacketFlag.RX_FDIR, "RX_FDIR", "Flow Director match"),
    RX_L4_CKSUM_BAD(PacketFlag.RX_L4_CKSUM_BAD, "RX_L4_CKSUM_BAD", "L4 checksum bad"),
    RX_IP_CKSUM_BAD(PacketFlag.RX_IP_CKSUM_BAD, "RX_IP_CKSUM_BAD", "IP checksum bad"),
    RX_OUTER_IP_CKSUM_BAD(PacketFlag.RX_OUTER_IP_CKSUM_BAD, "RX_OUTER_IP_CKSUM_BAD", "Outer IP checksum bad"),
    RX_VLAN_STRIPPED(PacketFlag.RX_VLAN_STRIPPED, "RX_VLAN_STRIPPED", "VLAN tag stripped by hardware"),
    RX_IP_CKSUM_GOOD(PacketFlag.RX_IP_CKSUM_GOOD, "RX_IP_CKSUM_GOOD", "IP checksum good"),
    RX_L4_CKSUM_GOOD(PacketFlag.RX_L4_CKSUM_GOOD, "RX_L4_CKSUM_GOOD", "L4 checksum good"),
    RX_IEEE1588_PTP(PacketFlag.RX_IEEE1588_PTP, "RX_IEEE1588_PTP", "IEEE1588 PTP packet"),
    RX_IEEE1588_TMST(PacketFlag.RX_IEEE1588_TMST, "RX_IEEE1588_TMST", "IEEE1588 timestamp present"),
    RX_FCS(PacketFlag.RX_FCS, "RX_FCS", "FCS present"),
    RX_OUTER_L4_CKSUM_BAD(PacketFlag.RX_OUTER_L4_CKSUM_BAD, "RX_OUTER_L4_CKSUM_BAD", "Outer L4 checksum bad"),
    RX_OUTER_L4_CKSUM_GOOD(PacketFlag.RX_OUTER_L4_CKSUM_GOOD, "RX_OUTER_L4_CKSUM_GOOD", "Outer L4 checksum good"),
    RX_FDIR_ID(PacketFlag.RX_FDIR_ID, "RX_FDIR_ID", "Flow Director ID present"),
    RX_QINQ_STRIPPED(PacketFlag.RX_QINQ_STRIPPED, "RX_QINQ_STRIPPED", "QinQ VLAN stripped"),
    RX_LRO(PacketFlag.RX_LRO, "RX_LRO", "Large Receive Offload"),
    RX_SEC_OFFLOAD(PacketFlag.RX_SEC_OFFLOAD, "RX_SEC_OFFLOAD", "Security offload processed"),
    RX_SEC_OFFLOAD_FAILED(PacketFlag.RX_SEC_OFFLOAD_FAILED, "RX_SEC_OFFLOAD_FAILED", "Security offload failed"),
    RX_MACSEC_STRIPPED(PacketFlag.RX_MACSEC_STRIPPED, "RX_MACSEC_STRIPPED", "MACsec stripped"),
    RX_QINQ(PacketFlag.RX_QINQ, "RX_QINQ", "QinQ VLAN present"),

    // ========== TX PROTOCOL/VERSION FLAGS (bits 32-37) ==========
    
    TX_IPV4(PacketFlag.TX_IPV4, "TX_IPV4", "TX packet is IPv4"),
    TX_IPV6(PacketFlag.TX_IPV6, "TX_IPV6", "TX packet is IPv6"),
    TX_OUTER_IP_CKSUM(PacketFlag.TX_OUTER_IP_CKSUM, "TX_OUTER_IP_CKSUM", "Compute outer IP checksum"),
    TX_OUTER_UDP_CKSUM(PacketFlag.TX_OUTER_UDP_CKSUM, "TX_OUTER_UDP_CKSUM", "Compute outer UDP checksum"),
    TX_OUTER_IPV4(PacketFlag.TX_OUTER_IPV4, "TX_OUTER_IPV4", "Outer header is IPv4"),
    TX_OUTER_IPV6(PacketFlag.TX_OUTER_IPV6, "TX_OUTER_IPV6", "Outer header is IPv6"),

    // ========== TX TUNNEL FLAGS (bits 43-52) ==========
    
    TX_TUNNEL_VXLAN(PacketFlag.TX_TUNNEL_VXLAN, "TX_TUNNEL_VXLAN", "VXLAN tunnel"),
    TX_TUNNEL_GRE(PacketFlag.TX_TUNNEL_GRE, "TX_TUNNEL_GRE", "GRE tunnel"),
    TX_TUNNEL_IPIP(PacketFlag.TX_TUNNEL_IPIP, "TX_TUNNEL_IPIP", "IP-in-IP tunnel"),
    TX_TUNNEL_GENEVE(PacketFlag.TX_TUNNEL_GENEVE, "TX_TUNNEL_GENEVE", "GENEVE tunnel"),
    TX_TUNNEL_MPLSOUDP(PacketFlag.TX_TUNNEL_MPLSOUDP, "TX_TUNNEL_MPLSOUDP", "MPLS over UDP tunnel"),
    TX_TUNNEL_VXLAN_GPE(PacketFlag.TX_TUNNEL_VXLAN_GPE, "TX_TUNNEL_VXLAN_GPE", "VXLAN-GPE tunnel"),
    TX_TUNNEL_GTP(PacketFlag.TX_TUNNEL_GTP, "TX_TUNNEL_GTP", "GTP tunnel"),
    TX_TUNNEL_ESP(PacketFlag.TX_TUNNEL_ESP, "TX_TUNNEL_ESP", "ESP tunnel"),
    TX_TUNNEL_L2TP(PacketFlag.TX_TUNNEL_L2TP, "TX_TUNNEL_L2TP", "L2TP tunnel"),
    TX_TUNNEL_UDP(PacketFlag.TX_TUNNEL_UDP, "TX_TUNNEL_UDP", "Generic UDP tunnel"),

    // ========== TX OFFLOAD FLAGS (bits 53-63) ==========
    
    TX_MACSEC(PacketFlag.TX_MACSEC, "TX_MACSEC", "MACsec offload"),
    TX_SEC_OFFLOAD(PacketFlag.TX_SEC_OFFLOAD, "TX_SEC_OFFLOAD", "Security offload"),
    TX_QINQ(PacketFlag.TX_QINQ, "TX_QINQ", "Insert QinQ VLAN"),
    TX_TCP_SEG(PacketFlag.TX_TCP_SEG, "TX_TCP_SEG", "TCP segmentation offload"),
    TX_UDP_SEG(PacketFlag.TX_UDP_SEG, "TX_UDP_SEG", "UDP segmentation offload"),
    TX_IEEE1588_TMST(PacketFlag.TX_IEEE1588_TMST, "TX_IEEE1588_TMST", "IEEE1588 timestamp insertion"),
    TX_TCP_CKSUM(PacketFlag.TX_TCP_CKSUM, "TX_TCP_CKSUM", "Compute TCP checksum"),
    TX_SCTP_CKSUM(PacketFlag.TX_SCTP_CKSUM, "TX_SCTP_CKSUM", "Compute SCTP checksum"),
    TX_UDP_CKSUM(PacketFlag.TX_UDP_CKSUM, "TX_UDP_CKSUM", "Compute UDP checksum"),
    TX_IP_CKSUM(PacketFlag.TX_IP_CKSUM, "TX_IP_CKSUM", "Compute IP checksum"),
    TX_VLAN(PacketFlag.TX_VLAN, "TX_VLAN", "Insert VLAN tag"),

    ;

    private final long value;
    private final String label;
    private final String description;

    PacketFlagInfo(long value, String label, String description) {
        this.value = value;
        this.label = label;
        this.description = description;
    }

    @Override
    public long getPacketFlag() {
        return value;
    }

    /**
     * Gets the short label for this flag.
     *
     * @return the label
     */
    public String getLabel() {
        return label;
    }

    /**
     * Gets the human-readable description.
     *
     * @return the description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Tests if this flag is set in the given flags value.
     *
     * @param flags the flags to test
     * @return true if this flag is set
     */
    public boolean isSet(long flags) {
        return (flags & value) != 0;
    }

    /**
     * Gets the bit position of this flag.
     *
     * @return the bit position (0-63)
     */
    public int getBitPosition() {
        return Long.numberOfTrailingZeros(value);
    }

    /**
     * Checks if this is an RX flag.
     *
     * @return true if RX flag (bits 0-20)
     */
    public boolean isRxFlag() {
        return getBitPosition() <= 20;
    }

    /**
     * Checks if this is a TX flag.
     *
     * @return true if TX flag (bits 32+)
     */
    public boolean isTxFlag() {
        return getBitPosition() >= 32;
    }

    /**
     * Checks if this is a tunnel flag.
     *
     * @return true if tunnel flag (bits 43-52)
     */
    public boolean isTunnelFlag() {
        int bit = getBitPosition();
        return bit >= 43 && bit <= 52;
    }

    // ========== Static utility methods ==========

    /**
     * Converts flags to an EnumSet.
     *
     * @param flags the flags value
     * @return EnumSet containing all set flags
     */
    public static EnumSet<PacketFlagInfo> toEnumSet(long flags) {
        EnumSet<PacketFlagInfo> set = EnumSet.noneOf(PacketFlagInfo.class);
        for (PacketFlagInfo f : values()) {
            if (f.isSet(flags)) {
                set.add(f);
            }
        }
        return set;
    }

    /**
     * Converts enum values to flags.
     *
     * @param flags the flags to combine
     * @return combined flags value
     */
    public static long toFlags(PacketFlagInfo... flags) {
        long result = 0;
        for (PacketFlagInfo f : flags) {
            result |= f.value;
        }
        return result;
    }

    /**
     * Combines multiple flag values.
     *
     * @param flags the flag values to combine
     * @return combined flags value
     */
    public static long combine(long... flags) {
        long result = 0;
        for (long f : flags) {
            result |= f;
        }
        return result;
    }

    /**
     * Resolves a flag value to its enum constant.
     *
     * @param flag the single flag value (must be a power of 2)
     * @return the enum constant, or null if not found
     */
    public static PacketFlagInfo valueOf(long flag) {
        for (PacketFlagInfo f : values()) {
            if (f.value == flag) {
                return f;
            }
        }
        return null;
    }

    /**
     * Formats flags as a human-readable string.
     *
     * @param flags the flags value
     * @return space-separated list of flag labels
     */
    public static String formatFlags(long flags) {
        if (flags == 0) {
            return "none";
        }
        
        StringBuilder sb = new StringBuilder();
        for (PacketFlagInfo f : values()) {
            if (f.isSet(flags)) {
                if (sb.length() > 0) {
                    sb.append(' ');
                }
                sb.append(f.label);
            }
        }
        return sb.toString();
    }

    /**
     * Formats flags as a compact string showing only RX flags.
     *
     * @param flags the flags value
     * @return space-separated list of RX flag labels
     */
    public static String formatRxFlags(long flags) {
        if (flags == 0) {
            return "none";
        }
        
        StringBuilder sb = new StringBuilder();
        for (PacketFlagInfo f : values()) {
            if (f.isRxFlag() && f.isSet(flags)) {
                if (sb.length() > 0) {
                    sb.append(' ');
                }
                sb.append(f.label);
            }
        }
        return sb.length() > 0 ? sb.toString() : "none";
    }

    /**
     * Formats flags as a compact string showing only TX flags.
     *
     * @param flags the flags value
     * @return space-separated list of TX flag labels
     */
    public static String formatTxFlags(long flags) {
        if (flags == 0) {
            return "none";
        }
        
        StringBuilder sb = new StringBuilder();
        for (PacketFlagInfo f : values()) {
            if (f.isTxFlag() && f.isSet(flags)) {
                if (sb.length() > 0) {
                    sb.append(' ');
                }
                sb.append(f.label);
            }
        }
        return sb.length() > 0 ? sb.toString() : "none";
    }
}