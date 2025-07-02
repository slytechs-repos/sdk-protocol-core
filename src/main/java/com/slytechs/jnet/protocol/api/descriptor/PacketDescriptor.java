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
package com.slytechs.jnet.protocol.api.descriptor;

import com.slytechs.jnet.platform.api.util.StringBuildable;
import com.slytechs.jnet.platform.api.util.time.TimestampUnit;
import com.slytechs.jnet.protocol.api.common.HeaderLookup;
import com.slytechs.jnet.protocol.api.core.L2FrameType;
import com.slytechs.jnet.protocol.api.core.PacketDescriptorType;
import com.slytechs.jnet.protocol.api.meta.Meta;
import com.slytechs.jnet.protocol.api.meta.Meta.MetaType;

/**
 * Base class for all packet descriptors.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 */
public abstract class PacketDescriptor
		extends Descriptor
		implements HeaderLookup, StringBuildable {

	/** The frame no. */
	@Meta(MetaType.ATTRIBUTE)
	private long frameNo;

	private int portNo;
	private String portName = "";

	/** The flags. */
	private int flags;

	/** The timestamp unit. */
	@Meta(MetaType.ATTRIBUTE)
	private TimestampUnit timestampUnit = TimestampUnit.EPOCH_MICRO;

	/**
	 * Instantiates a new packet descriptor.
	 *
	 * @param type the type
	 */
	protected PacketDescriptor(PacketDescriptorType type) {
		super(type);
	}

	/**
	 * Byte size.
	 *
	 * @return the int
	 */
	public abstract int byteSize();

	/**
	 * Byte size max.
	 *
	 * @return the int
	 */
	public int byteSizeMax() {
		return byteSize();
	}

	/**
	 * Byte size min.
	 *
	 * @return the int
	 */
	public int byteSizeMin() {
		return byteSize();
	}

	/**
	 * Capture length.
	 *
	 * @return the int
	 */
	public abstract int captureLength();

	/**
	 * Additional flags copied from the dissector.
	 *
	 * @return Bit flags
	 */
	public final int flags() {
		return flags;
	}

	/**
	 * Sets new dissector flags.
	 *
	 * @param flags the new dissector flags
	 */
	public final void setFlags(int flags) {
		this.flags = flags;
	}

	/**
	 * FrameHeader no.
	 *
	 * @return the long
	 */
	public long frameNo() {
		return frameNo;
	}

	public int portNo() {
		return portNo;
	}

	public String portName() {
		return portName;
	}

	public void setPortNo(int portNo) {
		this.portNo = portNo;
	}

	public void setPortName(String name) {
		this.portName = name;
	}

	/**
	 * FrameHeader no.
	 *
	 * @param newNumber the new number
	 * @return the packet descriptor
	 */
	public PacketDescriptor setFrameNo(long newNumber) {
		this.frameNo = newNumber;

		return this;
	}

	/**
	 * L 2 frame type.
	 *
	 * @return the int
	 */
	public int l2FrameType() {
		return L2FrameType.L2_FRAME_TYPE_UNKNOWN; // Layer2 frame type unknown
	}

	/**
	 * Timestamp.
	 *
	 * @return the long
	 */
	public abstract long timestamp();

	/**
	 * Timestamp unit.
	 *
	 * @return the timestamp unit
	 */
	public TimestampUnit timestampUnit() {
		return this.timestampUnit;
	}

	/**
	 * Timestamp unit.
	 *
	 * @param timestampUnit the timestamp unit
	 */
	public void setTimestampUnit(TimestampUnit timestampUnit) {
		this.timestampUnit = timestampUnit;
	}

	/**
	 * Type.
	 *
	 * @return the packet descriptor type
	 */
	@Override
	public final PacketDescriptorType type() {
		return (PacketDescriptorType) super.type();
	}

	/**
	 * Wire length.
	 *
	 * @return the int
	 */
	public abstract int wireLength();

}
