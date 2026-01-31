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

import com.slytechs.sdk.protocol.core.filter.FilterBuilder.Op;

/**
 * Filter for IPSec protocols (AH and ESP).
 * 
 * <p>AH (Authentication Header) - IP Protocol 51</p>
 * <p>ESP (Encapsulating Security Payload) - IP Protocol 50</p>
 */
//IpSecFilter.java
public interface IpSecFilter {

 static IpSecBuilder of() {
     return b -> b;
 }

 static IpSecBuilder espSpi(long spi) {
     return of().espSpi(spi);
 }

 static IpSecBuilder ahSpi(long spi) {
     return of().ahSpi(spi);
 }

 interface IpSecBuilder extends HeaderFilter {

     default IpSecBuilder espSpi(long spi) {
         return b -> this.emit(b).and().field("esp.spi", 0, 32, Op.EQ, spi);
     }

     default IpSecBuilder espSeq(long seq) {
         return b -> this.emit(b).and().field("esp.seq", 4, 32, Op.EQ, seq);
     }

     default IpSecBuilder ahSpi(long spi) {
         return b -> this.emit(b).and().field("ah.spi", 4, 32, Op.EQ, spi);
     }

     default IpSecBuilder ahSeq(long seq) {
         return b -> this.emit(b).and().field("ah.seq", 8, 32, Op.EQ, seq);
     }
 }
}