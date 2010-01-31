/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.stack;

import java.net.*;

import org.ice4j.*;

/**
 * The class represents a binary STUN message as well as the address and port
 * of the host that sent it and the address and port where it was received
 * (locally).
 *
 * @author Emil Ivov
 */
class RawMessage
{
    /**
     * The message itself.
     */
    private byte[] messageBytes = null;

    /**
     * The length of the message.
     */
    private int messageLength = -1;

    /**
     * The address and port where the message was sent from.
     */
    private InetSocketAddress remoteAddress = null;

    /**
     * Constructs a raw message with the specified field values. All parameters
     * are cloned before being assigned to class members.
     *
     * @param messageBytes the message itself.
     * @param messageLength the number of bytes currently stored in the
     * <tt>messageBytes</tt> array.
     * @param remoteAddress the address where the message came from.
     * @param remotePort the port where the message came from.
     *
     * @throws NullPointerException if one or more of the parameters were null.
     */
    RawMessage(byte[]      messageBytes,
               InetAddress remoteAddress,
               int         messageLength,
               int         remotePort)
    {
        //... don't do a null check - let it throw an NP exception

        this.messageBytes  = new byte[messageBytes.length];
        this.messageLength = messageLength;
        System.arraycopy(messageBytes, 0, this.messageBytes,
                                                       0, messageBytes.length);

        this.remoteAddress = new InetSocketAddress(remoteAddress, remotePort);
    }

    /**
     * Returns the message itself.
     *
     * @return a binary array containing the message data.
     */
    byte[] getBytes()
    {
        return messageBytes;
    }

    /**
     * Returns the message length.
     *
     * @return a the length of the message.
     */
    int getMessageLength()
    {
        return messageLength;
    }

    /**
     * Returns the address and port of the host that sent the message
     * @return the [address]:[port] pair that sent the message.
     */
    InetSocketAddress getRemoteAddress()
    {
        return this.remoteAddress;
    }
}
