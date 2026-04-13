package com.slytechs.sdk.protocol.core.dissector;

import java.lang.foreign.MemorySegment;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.slytechs.sdk.protocol.core.descriptor.PacketDescriptor.BindingInfo;
import com.slytechs.sdk.protocol.core.id.L2FrameTypes;
import com.slytechs.sdk.protocol.core.id.ProtocolIds;

/**
 * Iterates over all protocol headers in a packet by probing the most likely
 * next-layer protocols at each step.
 *
 * <p>
 * Uses the existing stateless {@link OnDemandPacketDissector} methods
 * (package-private) to resolve each protocol. No dissection logic is duplicated
 * — the iterator simply drives the dissector with targeted probes ordered by
 * likelihood.
 * </p>
 *
 * {@snippet :
 * var iter = new ProtocolIterator(L2FrameTypes.ETHER, seg, base, limit);
 * while (iter.hasNext()) {
 * 	BindingInfo info = iter.next();
 * 	System.out.printf("#%d id=0x%04X offset=%d len=%d%n",
 * 			info.order(), info.id(), info.offset(), info.length());
 * }
 * }
 *
 * {@snippet :
 * // Or as a stream
 * var iter = new ProtocolIterator(L2FrameTypes.ETHER, seg, base, limit);
 * iter.stream().forEach(System.out::println);
 * }
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see OnDemandPacketDissector
 * @see BindingInfo
 * @since 1.0
 */
public final class ProtocolIterator implements Iterator<BindingInfo> {

	private static final int DESC_ETHERNET = ProtocolIds.ETHERNET & ProtocolIds.MASK_DESCRIPTOR;
	private static final int DESC_VLAN = ProtocolIds.VLAN & ProtocolIds.MASK_DESCRIPTOR;
	private static final int DESC_VLAN_8021Q = ProtocolIds.VLAN_8021Q & ProtocolIds.MASK_DESCRIPTOR;
	private static final int DESC_VLAN_8021AD = ProtocolIds.VLAN_8021AD & ProtocolIds.MASK_DESCRIPTOR;
	private static final int DESC_IPV4 = ProtocolIds.IPv4 & ProtocolIds.MASK_DESCRIPTOR;
	private static final int DESC_IPV6 = ProtocolIds.IPv6 & ProtocolIds.MASK_DESCRIPTOR;
	private static final int DESC_UDP = ProtocolIds.UDP & ProtocolIds.MASK_DESCRIPTOR;
	private static final int DESC_GRE = ProtocolIds.GRE & ProtocolIds.MASK_DESCRIPTOR;
	private static final int DESC_VXLAN = ProtocolIds.VXLAN & ProtocolIds.MASK_DESCRIPTOR;
	private static final int DESC_MPLS = ProtocolIds.MPLS & ProtocolIds.MASK_DESCRIPTOR;

	// @formatter:off
	private static final int[] AFTER_L2 = {
		ProtocolIds.VLAN,    ProtocolIds.IPv4,  ProtocolIds.IPv6,
		ProtocolIds.ARP,     ProtocolIds.MPLS,
	};
	private static final int[] AFTER_IPV4 = {
		ProtocolIds.TCP,     ProtocolIds.UDP,   ProtocolIds.ICMPv4,
		ProtocolIds.SCTP,    ProtocolIds.GRE,   ProtocolIds.IPv4,
		ProtocolIds.IPv6,
	};
	private static final int[] AFTER_IPV6 = {
		ProtocolIds.TCP,     ProtocolIds.UDP,   ProtocolIds.ICMPv6,
		ProtocolIds.SCTP,    ProtocolIds.GRE,   ProtocolIds.IPv4,
		ProtocolIds.IPv6,
	};
	private static final int[] AFTER_UDP   = { ProtocolIds.VXLAN };
	private static final int[] AFTER_GRE   = { ProtocolIds.IPv4, ProtocolIds.IPv6, ProtocolIds.ETHERNET };
	private static final int[] AFTER_VXLAN = { ProtocolIds.ETHERNET };
	private static final int[] AFTER_MPLS  = { ProtocolIds.IPv4, ProtocolIds.IPv6 };
	private static final int[] TERMINAL    = {};
	// @formatter:on

	private final int l2FrameType;
	private final MemorySegment seg;
	private final long base;
	private final long limit;

	private int order;
	private BindingInfo prefetched;

	public ProtocolIterator(int l2FrameType, MemorySegment seg, long base, long limit) {
		this.l2FrameType = l2FrameType;
		this.seg = seg;
		this.base = base;
		this.limit = limit;

		prefetch();
	}

	@Override
	public boolean hasNext() {
		return prefetched != null;
	}

	@Override
	public BindingInfo next() {
		if (prefetched == null)
			throw new NoSuchElementException();

		BindingInfo current = prefetched;
		prefetched = null;

		advance(current);

		return current;
	}

	/**
	 * Returns a sequential stream over the remaining protocol bindings.
	 *
	 * @return stream of {@link BindingInfo} in stack order
	 */
	public Stream<BindingInfo> stream() {
		return StreamSupport.stream(
				Spliterators.spliteratorUnknownSize(this, Spliterator.ORDERED),
				false);
	}

	private void prefetch() {
		long encoded = OnDemandPacketDissector.mapProtocol(
				l2FrameType, l2FrameTypeToProtocolId(l2FrameType), 0,
				seg, base, limit);

		if (encoded >= 0) {
			int id = l2FrameTypeToProtocolId(l2FrameType);
			int off = BindingInfo.decodeOffset(encoded);
			int len = BindingInfo.decodeLength(encoded);
			prefetched = new BindingInfo(order++, id, off, len);
		}
	}

	private void advance(BindingInfo current) {
		int desc = current.id() & ProtocolIds.MASK_DESCRIPTOR;
		int minOffset = (int) (current.offset() + current.length());
		int[] candidates = candidatesAfter(desc);

		for (int id : candidates) {
			long encoded = OnDemandPacketDissector.mapProtocol(
					l2FrameType, id, 0, seg, base, limit);

			if (encoded >= 0) {
				int off = BindingInfo.decodeOffset(encoded);
				int len = BindingInfo.decodeLength(encoded);

				if (off >= minOffset) {
					prefetched = new BindingInfo(order++, id, off, len);
					return;
				}
			}
		}
	}

	private static int[] candidatesAfter(int desc) {
		return switch (desc) {
		case DESC_ETHERNET, DESC_VLAN, DESC_VLAN_8021Q, DESC_VLAN_8021AD -> AFTER_L2;
		case DESC_IPV4 -> AFTER_IPV4;
		case DESC_IPV6 -> AFTER_IPV6;
		case DESC_UDP -> AFTER_UDP;
		case DESC_GRE -> AFTER_GRE;
		case DESC_VXLAN -> AFTER_VXLAN;
		case DESC_MPLS -> AFTER_MPLS;
		default -> TERMINAL;
		};
	}

	private static int l2FrameTypeToProtocolId(int l2FrameType) {
		return switch (l2FrameType) {
		case L2FrameTypes.ETHER -> ProtocolIds.ETHERNET;
		case L2FrameTypes.RAW_IP4 -> ProtocolIds.IPv4;
		case L2FrameTypes.RAW_IP6 -> ProtocolIds.IPv6;
		default -> 0;
		};
	}
}