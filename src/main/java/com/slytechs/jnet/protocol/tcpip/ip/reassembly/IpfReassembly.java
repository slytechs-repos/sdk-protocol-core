/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
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
package com.slytechs.jnet.protocol.tcpip.ip.reassembly;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.slytechs.jnet.platform.api.util.IntSegment;
import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.protocol.api.core.L3FrameType;
import com.slytechs.jnet.protocol.tcpip.ip.impl.IpfReassemblyLayout;

/**
 * Ip fragmentation descriptor. A fragmentation descriptor provides information
 * about tracking and reassembly of IP fragments.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class IpfReassembly extends IpfDescriptor {

	private static class Record implements IntSegment {

		static Record newHole(int offset, int length) {
			return new Record(-1, offset, length, 0, false);
		}

		long index;
		int offset;
		int length;
		int overlay;
		boolean isData = true;

		public Record(long index, int offset, int length, int overlay, boolean isData) {
			this(index, offset, length, overlay);

			this.isData = isData;
		}

		public Record(long index, int offset, int length, int overlay) {
			super();
			this.index = index;
			this.offset = offset;
			this.length = length;
			this.overlay = overlay;
		}

		@Override
		public String toString() {
			String type = "payload";
			String indx = Long.toString(index);
			String extended;

			if (!isData && index == -1) {
				type = "missing";
				indx = "-";
				extended = "(%4d bytes - hole!)".formatted(length);

			} else if (this.overlay > 0) {
				type = "overlay";
				extended = "(%4d bytes - %d duplicate!)".formatted(length, this.overlay);

			} else {
				extended = "(%4d bytes)".formatted(length);

			}

			return "[FrameHeader: %3s, %s: %4d-%4d %s]"
					.formatted(indx, type, offset, offset + length - 1, extended);
		}

		/**
		 * @see com.slytechs.jnet.jnetruntime.util.IntSegment#start()
		 */
		@Override
		public int start() {
			return offset;
		}

		/**
		 * @see com.slytechs.jnet.jnetruntime.util.IntSegment#length()
		 */
		@Override
		public int length() {
			return length;
		}

		private static Record[] insertHoles(Record[] records) {
			List<Record> exp = new ArrayList<>(records.length + 4);

			int total = IntSegment.disjoint(records, (int offset, int hole, Record seg) -> {
				if (hole > 0)
					exp.add(Record.newHole(offset, hole));

				exp.add(seg);
			});

			if (total > 0)
				return exp.toArray(Record[]::new);

			return records;
		}
	}

	/**
	 * Instantiates a new ipf descriptor.
	 */
	public IpfReassembly() {
		super(IpfDescriptorType.IPF_REASSEMBLY);
	}

	public IpfReassembly(ByteBuffer buffer) {
		super(IpfDescriptorType.IPF_REASSEMBLY);

		bind(buffer);
	}

	public int flags() {
		return IpfReassemblyLayout.FLAGS.getUnsignedByte(buffer());
	}

	public boolean isReassembled() {
		return IpfReassemblyLayout.IP_IS_REASSEMBLED.getBit(buffer());
	}

	public boolean isComplete() {
		return IpfReassemblyLayout.IP_IS_COMPLETE.getBit(buffer());
	}

	public boolean isTimeout() {
		return IpfReassemblyLayout.IP_IS_TIMEOUT.getBit(buffer());
	}

	public boolean isHole() {
		return IpfReassemblyLayout.IP_IS_HOLE.getBit(buffer());
	}

	public boolean isOverlap() {
		return IpfReassemblyLayout.IP_IS_OVERLAP.getBit(buffer());
	}

	public int tableSize() {
		return IpfReassemblyLayout.TABLE_SIZE.getUnsignedByte(buffer());
	}

	public int reassembledBytes() {
		return IpfReassemblyLayout.REASSEMBLED_BYTES.getUnsignedShort(buffer());
	}

	public int holeBytes() {
		return IpfReassemblyLayout.HOLE_BYTES.getUnsignedShort(buffer());
	}

	public int overlapBytes() {
		return IpfReassemblyLayout.OVERLAP_BYTES.getUnsignedShort(buffer());
	}

	public long reassembledInMilli() {
		return IpfReassemblyLayout.REASSEMBLED_MILLI.getLong(buffer());
	}

	public long fragmentFrameNo(int index) {
		return IpfReassemblyLayout.FRAG_PKT_INDEX.getLong(buffer(), index);
	}

	public int fragmentOffset(int index) {
		return IpfReassemblyLayout.FRAG_OFFSET.getUnsignedShort(buffer(), index);
	}

	public int fragmentLength(int index) {
		return IpfReassemblyLayout.FRAG_LENGTH.getUnsignedShort(buffer(), index);
	}

	public int fragmentOverlayBytes(int index) {
		return IpfReassemblyLayout.FRAG_OVERLAY_BYTES.getUnsignedShort(buffer(), index);
	}

	public boolean isIp4() {
		return IpfReassemblyLayout.IP_TYPE.getBit(buffer());
	}

	public boolean isIp46() {
		return !IpfReassemblyLayout.IP_TYPE.getBit(buffer());
	}

	public L3FrameType ipFrameType() {
		return isIp4() ? L3FrameType.IPv4 : L3FrameType.IPv6;
	}

	private Record[] toRecordArray() {
		var records = new Record[tableSize()];

		for (int i = 0; i < records.length; i++)
			records[i] = new Record(fragmentFrameNo(i), fragmentOffset(i), fragmentLength(i), fragmentOverlayBytes(i));

		return records;
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#buildDetailedString(java.lang.StringBuilder,
	 *      com.slytechs.jnet.platform.api.util.format.jnetruntime.util.Detail)
	 */
	@Override
	protected StringBuilder buildDetailedString(StringBuilder toAppendTo, Detail detail) {
		if (detail == Detail.SUMMARY) {
			toAppendTo
					.append("%d %s Fragments (%d bytes): %s"
							.formatted(
									tableSize(),
									ipFrameType(),
									reassembledBytes(),
									IntStream.range(0, tableSize())
											.mapToObj(i -> "#%d(%d)".formatted(i, fragmentLength(i)))
											.collect(Collectors.joining(", "))))

			;

		} else if (detail == Detail.MEDIUM) {
			toAppendTo
//					.append("ipType=%s".formatted(ipTypeAsL3FrameType()))
					.append("")

			;

		} else { // Detail.HIGH
			toAppendTo
					.append("  flags            = 0x%02X%n".formatted(flags()))
					.append("    ip frame type  = %s%n".formatted(ipFrameType()))
					.append("    is reassembled = %s%n".formatted(isReassembled()))
					.append("    is complete    = %s%n".formatted(isComplete()))
					.append("    is timeout     = %s%n".formatted(isTimeout()))
					.append("    is hole        = %s%n".formatted(isHole()))
					.append("    is overlap     = %s%n".formatted(isOverlap()))

					.append("  reassembled      = %,d bytes (%.1f%%)%n".formatted(reassembledBytes(), 100. - perc(
							holeBytes())))
					.append("  hole             = %,d bytes (%.1f%%)%n".formatted(holeBytes(), perc(holeBytes())))
					.append("  overlap          = %,d bytes (%.1f%%)%n".formatted(overlapBytes(), perc(overlapBytes())))
					.append("  duration         = %.09f seconds%n".formatted((reassembledInMilli())
							/ 1000_000.))

					.append("  table size       = %d records%n".formatted(tableSize()))

			;

			Record[] records = Record.insertHoles(toRecordArray());
			for (int i = 0; i < records.length; i++) {
				Record r = records[i];

				toAppendTo
						.append("    %s%n".formatted(r.toString()))
//						.append("    [FrameHeader: %d, payload: %4d-%4d (%4d bytes)]%n"
//								.formatted(
//										record.index,
//										record.offset,
//										record.offset + record.length - 1,
//										record.length))

				;

			}
		}

		return toAppendTo;
	}

	private double perc(int bytes) {
		int reassembledBytes = reassembledBytes();
		if (reassembledBytes == 0)
			return 0;

		double fraction = (double) bytes / (double) reassembledBytes;

		return fraction * 100.;
	}
}
