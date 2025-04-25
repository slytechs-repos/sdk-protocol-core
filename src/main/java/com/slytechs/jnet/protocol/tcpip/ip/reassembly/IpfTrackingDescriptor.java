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

import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.protocol.tcpip.ip.impl.IpfTrackingLayout;

/**
 * Ip fragmentation descriptor. A fragmentation descriptor provides information
 * about tracking and reassembly of IP fragments.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public class IpfTrackingDescriptor extends IpfDescriptor {

	/**
	 * Instantiates a new ipf descriptor.
	 */
	public IpfTrackingDescriptor() {
		super(IpfDescriptorType.IPF_TRACKING);
	}

	public int flags() {
		return IpfTrackingLayout.FLAGS.getInt(buffer());
	}

	/**
	 * @see com.slytechs.jnet.protocol.api.descriptor.Descriptor#buildDetailedString(java.lang.StringBuilder,
	 *      com.slytechs.jnet.platform.api.util.format.jnetruntime.util.Detail)
	 */
	@Override
	protected StringBuilder buildDetailedString(StringBuilder b, Detail detail) {
		throw new UnsupportedOperationException("not implemented yet");
	}
}
