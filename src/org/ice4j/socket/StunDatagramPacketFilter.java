/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.socket;

import org.ice4j.message.*;

/**
 * Implements a <tt>DatagramPacketFilter</tt> which only accepts
 * <tt>DatagramPacket</tt>s which represent STUN messages defined in RFC 5389
 * "Session Traversal Utilities for NAT (STUN)" i.e. with method Binding or the
 * reserved method 0x000 and 0x002/SharedSecret.
 *
 * @author Lubomir Marinov
 */
public class StunDatagramPacketFilter
    extends AbstractStunDatagramPacketFilter
{

    /**
     * Determines whether this <tt>DatagramPacketFilter</tt> accepts a
     * <tt>DatagramPacket</tt> which represents a STUN message with a specific
     * STUN method. <tt>StunDatagramPacketFilter</tt> only accepts the method
     * Binding and the reserved methods 0x000 and 0x002/SharedSecret.
     *
     * @param method the STUN method of a STUN message represented by a
     * <tt>DatagramPacket</tt> to be checked whether it is accepted by this
     * <tt>DatagramPacketFilter</tt>
     * @return <tt>true</tt> if this <tt>DatagramPacketFilter</tt> accepts the
     * <tt>DatagramPacket</tt> which represents a STUN message with the
     * specified STUN method; otherwise, <tt>false</tt>
     * @see AbstractStunDatagramPacketFilter#acceptMethod(char)
     */
    public boolean acceptMethod(char method)
    {
        switch (method)
        {
        case Message.STUN_METHOD_BINDING:
        case 0x0000:
        case 0x0002:
            return true;
        default:
            return false;
        }
    }
}
