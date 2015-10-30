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

import org.ice4j.*;

/**
 * The class represents a binary STUN message as well as the address and port
 * of the host that sent it and the address and port where it was received
 * (locally).
 *
 * @author Emil Ivov
 */
public class RawMessage
{
    /**
     * The message itself.
     */
    private final byte[] messageBytes;

    /**
     * The length of the message.
     */
    private final int messageLength;

    /**
     * The address and port where the message was sent from.
     */
    private final TransportAddress remoteAddress;

    /**
     * The address that this message was received on.
     */
    private final TransportAddress localAddress;

    /**
     * Constructs a raw message with the specified field values. All parameters
     * are cloned before being assigned to class members.
     *
     * @param messageBytes the message itself.
     * @param messageLength the number of bytes currently stored in the
     * <tt>messageBytes</tt> array.
     * @param remoteAddress the address where the message came from.
     * @param localAddress the <tt>TransportAddress</tt> that the message was
     * received on.
     *
     * @throws NullPointerException if one or more of the parameters were null.
     */
    RawMessage(byte[]           messageBytes,
               int              messageLength,
               TransportAddress remoteAddress,
               TransportAddress localAddress)
    {
        /*
         * Let NullPointerException go out.
         * 
         * The length of the array messgeBytes may be enormous while
         * messageLength may be tiny so it does not make sense to clone
         * messageBytes.
         */
        this.messageBytes  = new byte[messageLength];
        System.arraycopy(messageBytes, 0, this.messageBytes, 0, messageLength);
        this.messageLength = messageLength;
        this.localAddress  = localAddress;
        this.remoteAddress = remoteAddress;
    }

    /**
     * Returns the message itself.
     *
     * @return a binary array containing the message data.
     */
    public byte[] getBytes()
    {
        return messageBytes;
    }

    /**
     * Returns the message length.
     *
     * @return a the length of the message.
     */
    public int getMessageLength()
    {
        return messageLength;
    }

    /**
     * Returns the address and port of the host that sent the message
     *
     * @return the [address]:[port] pair that sent the message.
     */
    public TransportAddress getRemoteAddress()
    {
        return this.remoteAddress;
    }

    /**
     * Returns the address that this message was received on.
     *
     * @return the address that this message was received on.
     */
    public TransportAddress getLocalAddress()
    {
        return localAddress;
    }

    /**
     * Use builder pattern to allow creation of immutable RawMessage instances,
     * from outside the current package.
     *
     * @param messageBytes the message itself.
     * @param messageLength the number of bytes currently stored in the
     * <tt>messageBytes</tt> array.
     * @param remoteAddress the address where the message came from.
     * @param localAddress the <tt>TransportAddress</tt> that the message was
     * received on.
     * @return RawMessage instance
     */
    public static RawMessage build(byte[] messageBytes, int messageLength,
        TransportAddress remoteAddress, TransportAddress localAddress)
    {
        return new RawMessage(messageBytes, messageLength, remoteAddress,
            localAddress);
    }

}
