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
package org.ice4j.stack;

/**
 * The interface which interested implementers will use in order
 * to track and log packets send and received by this stack.
 * 
 * @author Damian Minkov
 */
public interface PacketLogger
{
    /**
     * Logs a incoming or outgoing packet.
     *
     * @param sourceAddress the source address of the packet.
     * @param sourcePort the source port.
     * @param destinationAddress the destination address of the packet.
     * @param destinationPort the destination port.
     * @param packetContent the content of the packet.
     * @param sender whether we are sending or not the packet.
     */
    public void logPacket(
            byte[] sourceAddress,
            int sourcePort,
            byte[] destinationAddress,
            int destinationPort,
            byte[] packetContent,
            boolean sender);

    /**
     * Checks whether the logger is enabled. 
     * @return <tt>true</tt> if the logger is enabled, <tt>false</tt>
     *  otherwise.
     */
    public boolean isEnabled();
}
