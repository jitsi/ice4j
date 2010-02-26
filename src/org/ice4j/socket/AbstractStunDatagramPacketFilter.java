/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.socket;

import java.net.*;

/**
 * Implements a <tt>DatagramPacketFilter</tt> which only accepts
 * <tt>DatagramPacket</tt>s which represent STUN messages.
 *
 * @author Lubomir Marinov
 */
public abstract class AbstractStunDatagramPacketFilter
    implements DatagramPacketFilter
{

    /**
     * Determines whether a specific <tt>DatagramPacket</tt> represents a STUN
     * message.
     *
     * @param p the <tt>DatagramPacket</tt> which is to be checked whether it is
     * a STUN message
     * @return <tt>true</tt> if <tt>p</tt> represents a STUN message; otherwise,
     * <tt>false</tt>
     */
    public boolean accept(DatagramPacket p)
    {
        /*
         * All STUN messages MUST start with a 20-byte header followed by zero
         * or more Attributes.
         */
        if (p.getLength() >= 20)
        {
            /*
             * The most significant 2 bits of every STUN message MUST be zeroes.
             * This can be used to differentiate STUN packets from other
             * protocols when STUN is multiplexed with other protocols on the
             * same port.
             */
            byte[] data = p.getData();
            int offset = p.getOffset();
            byte b0 = data[offset];

            if ((b0 & 0xC0) == 0)
            {
                byte b1 = data[offset + 1];
                char method = (char) ((b0 & 0xFE) | (b1 & 0xEF));

                return acceptMethod(method);
            }
        }
        return false;
    }

    /**
     * Determines whether this <tt>DatagramPacketFilter</tt> accepts a
     * <tt>DatagramPacket</tt> which represents a STUN message with a specific
     * STUN method.
     *
     * @param method the STUN method of a STUN message represented by a
     * <tt>DatagramPacket</tt> to be checked whether it is accepted by this
     * <tt>DatagramPacketFilter</tt>
     * @return <tt>true</tt> if this <tt>DatagramPacketFilter</tt> accepts the
     * <tt>DatagramPacket</tt> which represents a STUN message with the
     * specified STUN method; otherwise, <tt>false</tt>
     */
    protected abstract boolean acceptMethod(char method);
}
