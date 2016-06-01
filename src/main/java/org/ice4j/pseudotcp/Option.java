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
 * Options used in PseudoTCP
 *
 * @author Pawel Domas
 */
public enum Option
{
    /**
     * Whether to enable Nagle's algorithm (0 == off)
     */
    OPT_NODELAY,
    /**
     * The Delayed ACK timeout (0 == off).
     */
    OPT_ACKDELAY,
    /**
     * Set the receive buffer size, in bytes.
     */
    OPT_RCVBUF,
    /**
     * Set the send buffer size, in bytes.
     */
    OPT_SNDBUF,
    /**
     * Timeout in ms for read operations(0 - no timeout)
     */
    OPT_READ_TIMEOUT,
    /**
     * Timeout in ms for write operations(0 - no timeout)
     */
    OPT_WRITE_TIMEOUT
}
