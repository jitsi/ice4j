/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

import org.ice4j.*;
import org.ice4j.stack.*;
/**
 * @author Emil Ivov
 */
public class ConnectivityCheckServer
    implements RequestListener
{
    StunStack stunStack = StunStack.getInstance();

    public ConnectivityCheckServer()
    {
        stunStack.addRequestListener(this);
    }

    public void startListening(LocalCandidate candidate)
    {
        stunStack.addSocket(candidate.getSocket());
    }

    public void stopListenint(LocalCandidate candidate)
    {
        stunStack.removeSocket(candidate.getTransportAddress());
    }

    public void requestReceived(StunMessageEvent evt)
    {
        System.out.println("evt=" + evt);
    }

}
