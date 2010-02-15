/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.stack;

import org.ice4j.*;

/**
 * Handles incoming requests.
 *
 * @author Emil Ivov
 */

public interface RequestListener
{
    /**
     * Called when delivering incoming STUN requests.
     *
     * @param evt the event containing the incoming STUN request.
     */
    public void requestReceived(StunMessageEvent evt);
}
