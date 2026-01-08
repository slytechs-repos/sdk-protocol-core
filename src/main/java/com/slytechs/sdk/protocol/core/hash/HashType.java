/*
 * Apache License, Version 2.0
 * 
 * Copyright 2025 Sly Technologies Inc.
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
package com.slytechs.sdk.protocol.core.hash;

/**
 * Hash type constants for packet distribution across channels.
 * 
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface HashType {

    int NONE                      = 0;
    int ROUND_ROBIN               = 1;
    int HASH_2_TUPLE              = 2;
    int HASH_2_TUPLE_SORTED       = 3;
    int HASH_5_TUPLE              = 4;
    int HASH_5_TUPLE_SORTED       = 5;
    int HASH_INNER_2_TUPLE        = 6;
    int HASH_INNER_2_TUPLE_SORTED = 7;
    int HASH_INNER_5_TUPLE        = 8;
    int HASH_INNER_5_TUPLE_SORTED = 9;
    int HASH_5_TUPLE_SCTP         = 10;
    int HASH_5_TUPLE_SCTP_SORTED  = 11;
    int HASH_3_TUPLE_GTP          = 12;
    int HASH_3_TUPLE_GTP_SORTED   = 13;
    int HASH_LAST_MPLS_LABEL      = 14;
    int HASH_ALL_MPLS_LABELS      = 15;
    int HASH_LAST_VLAN_ID         = 16;
    int HASH_ALL_VLAN_IDS         = 17;

    int id();
}