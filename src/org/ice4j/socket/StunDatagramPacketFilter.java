/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.socket;

import java.net.*;

import org.ice4j.*;
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
    implements DatagramPacketFilter
{

    /**
     * The <tt>TransportAddress</tt> of the STUN server <tt>DatagramPacket</tt>s
     * representing STUN messages from and to which are accepted by this
     * instance.
     */
    protected final TransportAddress stunServer;

    /**
     * Initializes a new <tt>StunDatagramPacketFilter</tt> which will accept
     * <tt>DatagramPacket</tt>s which represent STUN messages and which are part
     * of the communication with a specific STUN server.
     *
     * @param turnServer the <tt>TransportAddress</tt> of the STUN server
     * <tt>DatagramPacket</tt>s representing STUN messages from and to which
     * will be accepted by the new instance
     */
    public StunDatagramPacketFilter(TransportAddress stunServer)
    {
        this.stunServer = stunServer;
    }

    /**
     * Determines whether a specific <tt>DatagramPacket</tt> represents a STUN
     * message which is part of the communication with the STUN server
     * associated with this instance.
     *
     * @param p the <tt>DatagramPacket</tt> which is to be checked whether it is
     * a STUN message which is part of the communicator with the STUN server
     * associated with this instance
     * @return <tt>true</tt> if the specified <tt>DatagramPacket</tt> represents
     * a STUN message which is part of the communication with the STUN server
     * associated with this instance; otherwise, <tt>false</tt>
     */
    public boolean accept(DatagramPacket p)
    {
        if (stunServer.equals(p.getSocketAddress()))
        {
            /*
             * All STUN messages MUST start with a 20-byte header followed by
             * zero or more Attributes.
             */
            if (p.getLength() >= 20)
            {
                /*
                 * The most significant 2 bits of every STUN message MUST be
                 * zeroes. This can be used to differentiate STUN packets from
                 * other protocols when STUN is multiplexed with other protocols
                 * on the same port.
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
        }
        return false;
    }

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
     */
    protected boolean acceptMethod(char method)
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
