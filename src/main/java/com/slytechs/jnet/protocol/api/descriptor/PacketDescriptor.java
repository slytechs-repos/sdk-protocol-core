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
package com.slytechs.jnet.protocol.api.descriptor;

import com.slytechs.jnet.protocol.api.HeaderAccessor;

/**
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface PacketDescriptor extends Descriptor, HeaderAccessor {

	int captureLength();

	void setCaptureLength(int length);

	int wireLength();

	void setWireLength(int length);

	/**
	 * Packet flag bitmask. Contains a bitmask, 1 flag for every bit, of all the
	 * packet flags. This is typically hardware generated bitmask.
	 * 
	 * <p>
	 * To check if any checksum failures occurred
	 * {@snippet :
	 * long badFlags = packetFlagBitmask() & PacketFlag.Constants.PKT_MASK_ALL_BAD;
	 * if (badFlags != 0)
	 * 	log.warning("corrupted packet");
	 * }
	 *
	 * @return the long
	 * @see PacketFlag
	 * @see PacketFlag.Constants
	 */
	long packetFlagBitmask();
	
	int l2Offset();
	int l3Offset();
	int l4Offset();
	
	int l2Lenght();
	int l3Length();
	int l4Length();
	
	int l2OffsetOuter();
	int l3OffsetOuter();
	
	int l2LengthOuter();
	int l3LengthOuter();
	
	int tsoSegmentSize();
	
	long hash();
}
