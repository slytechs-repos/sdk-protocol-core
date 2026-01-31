package com.slytechs.sdk.protocol.core.filter;

import java.util.function.UnaryOperator;

import com.slytechs.sdk.protocol.core.filter.EthernetFilter.EthernetBuilder;
import com.slytechs.sdk.protocol.core.filter.Ip4Filter.Ip4Builder;
import com.slytechs.sdk.protocol.core.filter.Ip6Filter.Ip6Builder;
import com.slytechs.sdk.protocol.core.filter.IpSecFilter.IpSecBuilder;
import com.slytechs.sdk.protocol.core.filter.MplsFilter.MplsBuilder;
import com.slytechs.sdk.protocol.core.filter.TcpFilter.TcpBuilder;
import com.slytechs.sdk.protocol.core.filter.UdpFilter.UdpBuilder;
import com.slytechs.sdk.protocol.core.filter.VlanFilter.VlanBuilder;

public interface PacketFilter {

	static ProtocolFilter anyOf(HeaderFilter... alternatives) {
		return of().anyOf(alternatives);
	}

	static ProtocolFilter anyOf(ProtocolFilter... alternatives) {
		return of().anyOf(alternatives);
	}

	static ProtocolFilter or(UnaryOperator<ProtocolFilter> other) {
		return of().or(other);
	}

	static ProtocolFilter ah() {
		return of().ah();
	}

	static ProtocolFilter ah(UnaryOperator<IpSecBuilder> header) {
		return of().ah(header);
	}

	static ProtocolFilter esp() {
		return of().esp();
	}

	static ProtocolFilter esp(UnaryOperator<IpSecBuilder> header) {
		return of().esp(header);
	}

	static ProtocolFilter ethernet() {
		return of().ethernet();
	}

	static ProtocolFilter ethernet(UnaryOperator<EthernetBuilder> header) {
		return of().ethernet(header);
	}

	static ProtocolFilter ip4() {
		return of().ip4();
	}

	static ProtocolFilter ip4(UnaryOperator<Ip4Builder> header) {
		return of().ip4(header);
	}

	static ProtocolFilter ip6() {
		return of().ip6();
	}

	static ProtocolFilter ip6(UnaryOperator<Ip6Builder> header) {
		return of().ip6(header);
	}

	static ProtocolFilter mpls() {
		return of().mpls();
	}

	static ProtocolFilter mpls(UnaryOperator<MplsBuilder> header) {
		return of().mpls(header);
	}

	static ProtocolFilter of() {
		return b -> b;
	}

	static ProtocolFilter tcp() {
		return of().tcp();
	}

	static ProtocolFilter tcp(UnaryOperator<TcpBuilder> header) {
		return of().tcp(header);
	}

	static ProtocolFilter udp() {
		return of().udp();
	}

	static ProtocolFilter udp(UnaryOperator<UdpBuilder> header) {
		return of().udp(header);
	}

	static ProtocolFilter vlan() {
		return of().vlan();
	}

	static ProtocolFilter vlan(UnaryOperator<VlanBuilder> header) {
		return of().vlan(header);
	}

	static ProtocolFilter host(String ip) {
		return of().host(ip);
	}

	static ProtocolFilter srcHost(String ip) {
		return of().srcHost(ip);
	}

	static ProtocolFilter dstHost(String ip) {
		return of().dstHost(ip);
	}

	static ProtocolFilter net(String cidr) {
		return of().net(cidr);
	}

	static ProtocolFilter srcNet(String cidr) {
		return of().srcNet(cidr);
	}

	static ProtocolFilter dstNet(String cidr) {
		return of().dstNet(cidr);
	}

	static ProtocolFilter port(int port) {
		return of().port(port);
	}

	static ProtocolFilter portRange(int start, int end) {
		return of().portRange(start, end);
	}

	static ProtocolFilter lengthGreater(int len) {
		return of().lengthGreater(len);
	}

	static ProtocolFilter lengthLess(int len) {
		return of().lengthLess(len);
	}

	static ProtocolFilter broadcast() {
		return of().broadcast();
	}

	static ProtocolFilter multicast() {
		return of().multicast();
	}

	String toExpression();
}
