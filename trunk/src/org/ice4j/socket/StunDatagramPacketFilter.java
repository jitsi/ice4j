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
public class StunDatagramPacketFilter
    implements DatagramPacketFilter
{

    /**
     * Determines whether a specific <tt>DatagramPacket</tt> represents a STUN
     * message.
     *
     * @param p the <tt>DatagramPacket</tt> which is to be checked whether it is
     * a STUN message
     * @return <tt>true</tt> if <tt>p</tt> represents a STUN message
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
            byte b0 = p.getData()[p.getOffset()];

            return ((b0 & 0xC0) == 0);
        }
        return false;
    }
}
