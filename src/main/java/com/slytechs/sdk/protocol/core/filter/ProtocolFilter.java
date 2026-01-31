/*
 * Copyright 2005-2026 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.protocol.core.filter;

import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.UnaryOperator;

import com.slytechs.sdk.common.util.Registration;
import com.slytechs.sdk.protocol.core.filter.VlanFilter.VlanBuilder;

public interface ProtocolFilter {

	default ProtocolFilter ah() {
		return b -> this.emit(b).and().protocol("ah");
	}

	default ProtocolFilter ah(UnaryOperator<IpSecFilter.IpSecBuilder> header) {
		return b -> header.apply(IpSecFilter.of()).emit(this.emit(b).and().protocol("ah"));
	}

	default ProtocolFilter anyOf(HeaderFilter... alternatives) {
		return b -> {
			this.emit(b).and().group();
			for (int i = 0; i < alternatives.length; i++) {
				if (i > 0)
					b.or();
				alternatives[i].emit(b);
			}
			return b.endGroup();
		};
	}

	default ProtocolFilter anyOf(ProtocolFilter... alternatives) {
		return b -> {
			this.emit(b).and().group();
			for (int i = 0; i < alternatives.length; i++) {
				if (i > 0)
					b.or();
				alternatives[i].emit(b);
			}
			return b.endGroup();
		};
	}

	// Broadcast/Multicast
	default ProtocolFilter broadcast() {
		return b -> this.emit(b).and().broadcast();
	}

	default ProtocolFilter dstHost(String ip) {
		return b -> this.emit(b).and().dstHost(ip);
	}

	default ProtocolFilter dstNet(String cidr) {
		return b -> this.emit(b).and().dstNet(cidr);
	}

	default ProtocolFilter dstPort(int port) {
		return b -> this.emit(b).and().dstPort(port);
	}

	FilterBuilder emit(FilterBuilder b);

	default ProtocolFilter esp() {
		return b -> this.emit(b).and().protocol("esp");
	}

	default ProtocolFilter esp(UnaryOperator<IpSecFilter.IpSecBuilder> header) {
		return b -> header.apply(IpSecFilter.of()).emit(this.emit(b).and().protocol("esp"));
	}

	default ProtocolFilter ethernet() {
		return b -> this.emit(b).and().protocol("eth");
	}

	default ProtocolFilter ethernet(UnaryOperator<EthernetFilter.EthernetBuilder> header) {
		return b -> header.apply(EthernetFilter.of()).emit(this.emit(b).and().protocol("eth"));
	}

	default ProtocolFilter host(byte[] ip) {
		return b -> this.emit(b).and().host(ip);
	}

	// Host - matches src OR dst
	default ProtocolFilter host(String ip) {
		return b -> this.emit(b).and().host(ip);
	}

	default ProtocolFilter ip4() {
		return b -> this.emit(b).and().protocol("ip4");
	}

	default ProtocolFilter ip4(UnaryOperator<Ip4Filter.Ip4Builder> header) {
		return b -> header.apply(Ip4Filter.of()).emit(this.emit(b).and().protocol("ip4"));
	}

	default ProtocolFilter ip6() {
		return b -> this.emit(b).and().protocol("ip6");
	}

	default ProtocolFilter ip6(UnaryOperator<Ip6Filter.Ip6Builder> header) {
		return b -> header.apply(Ip6Filter.of()).emit(this.emit(b).and().protocol("ip6"));
	}

	// ProtocolFilter additions

	// Packet length
	default ProtocolFilter length(int len) {
		return b -> this.emit(b).and().length(FilterBuilder.Op.EQ, len);
	}

	default ProtocolFilter lengthGreater(int len) {
		return b -> this.emit(b).and().length(FilterBuilder.Op.GT, len);
	}

	default ProtocolFilter lengthLess(int len) {
		return b -> this.emit(b).and().length(FilterBuilder.Op.LT, len);
	}

	default ProtocolFilter mpls() {
		return b -> this.emit(b).and().protocol("mpls");
	}

	default ProtocolFilter mpls(UnaryOperator<MplsFilter.MplsBuilder> header) {
		return b -> header.apply(MplsFilter.of()).emit(this.emit(b).and().protocol("mpls"));
	}

	default ProtocolFilter multicast() {
		return b -> this.emit(b).and().multicast();
	}

	// Network/CIDR
	default ProtocolFilter net(String cidr) {
		return b -> this.emit(b).and().net(cidr);
	}

	default ProtocolFilter onExpressionAssert(Function<String, Boolean> debugAction) {
		return onExpression(value -> {
			if (!debugAction.apply(value))
				throw new IllegalStateException("expression output error :" + value);
		});
	}

	default ProtocolFilter onExpression(Consumer<String> debugAction) {
		return b -> this.emit(b).onExpressionAction(debugAction, _ -> {});
	}

	default ProtocolFilter onExpression(Consumer<String> debugAction, Consumer<Registration> registration) {
		return b -> this.emit(b).onExpressionAction(debugAction, registration);
	}

	default ProtocolFilter or(UnaryOperator<ProtocolFilter> other) {
		return b -> other.apply(PacketFilter.of()).emit(this.emit(b).or());
	}

	default ProtocolFilter orFilter(ProtocolFilter other) {
		return b -> other.emit(this.emit(b).or());
	}

	default ProtocolFilter port(int port) {
		return b -> this.emit(b).and().port(port);
	}

	default ProtocolFilter portRange(int start, int end) {
		return b -> this.emit(b).and().portRange(start, end);
	}

	default ProtocolFilter srcHost(String ip) {
		return b -> this.emit(b).and().srcHost(ip);
	}

	default ProtocolFilter srcNet(String cidr) {
		return b -> this.emit(b).and().srcNet(cidr);
	}

	default ProtocolFilter srcPort(int port) {
		return b -> this.emit(b).and().srcPort(port);
	}

	default ProtocolFilter tcp() {
		return b -> this.emit(b).and().protocol("tcp");
	}

	default ProtocolFilter tcp(UnaryOperator<TcpFilter.TcpBuilder> header) {
		return b -> header.apply(TcpFilter.of()).emit(this.emit(b).and().protocol("tcp"));
	}

	default ProtocolFilter udp() {
		return b -> this.emit(b).and().protocol("udp");
	}

	default ProtocolFilter udp(UnaryOperator<UdpFilter.UdpBuilder> header) {
		return b -> header.apply(UdpFilter.of()).emit(this.emit(b).and().protocol("udp"));
	}

	default ProtocolFilter vlan() {
		return b -> this.emit(b).and().protocol("vlan");
	}

	default ProtocolFilter vlan(UnaryOperator<VlanBuilder> header) {
		return b -> header.apply(VlanFilter.of()).emit(this.emit(b).and().protocol("vlan"));
	}

	default ProtocolFilter vlanFilter(VlanBuilder header) {
		return b -> header.emit(this.emit(b));
	}

}