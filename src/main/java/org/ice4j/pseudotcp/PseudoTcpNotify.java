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

import java.io.*;

/**
 * Notification of tcp events.
 * Is implemented by <tt>PseudoTcpSocketImpl</tt> to expose stream functionality.
 *
 * @author Pawel Domas
 */
public interface PseudoTcpNotify
{
    /**
     * Called when TCP enters opened state
     * @param tcp the socket that was opened
     */
    void onTcpOpen(PseudoTCPBase tcp);

    /**
     * Called when any data is available in read buffer
     * @param tcp the socket that became readable
     */
    void onTcpReadable(PseudoTCPBase tcp);

    /**
     * Called when there is free space available in the send buffer
     * @param tcp the socket that became writable
     */
    void onTcpWriteable(PseudoTCPBase tcp);

    /**
     * Called when tcp enters closed state
     * @param tcp the socket that was closed
     * @param e null means no error
     */
    void onTcpClosed(PseudoTCPBase tcp, IOException e);

    /**
     * Called when protocol requests packet transfer through the network.
     * @param tcp the socket on which the write occurred
     * @param buffer the data that was written
     * @param len data length
     * @return the result, see {@link WriteResult} description for more info
     */
    WriteResult tcpWritePacket(PseudoTCPBase tcp, byte[] buffer, int len);
}
