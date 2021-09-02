/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
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
package org.ice4j.pseudotcp;

/**
 * TCP states defined for pseudoTCP
 * @author Pawel Domas
 */
public enum PseudoTcpState
{
    /**
     * Initial state, can accept connection
     */
    TCP_LISTEN, // = 0,
    /**
     * SYN sent to remote peer, wits for SYN
     */
    TCP_SYN_SENT, // = 1,
    /**
     * SYN received from remote peer, sends back SYN
     */
    TCP_SYN_RECEIVED, // = 2;
    /**
     * SYN sent and received - connection established
     */
    TCP_ESTABLISHED, // = 3;
    /**
     * Closed state. In current implementation reached on error
     * or explicite by close method with force option
     * TODO: closing procedure
     */
    TCP_CLOSED // = 4;
}
