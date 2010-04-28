/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice.checks;

import org.ice4j.*;

/**
 * This interface is used by {@link ConnectivityCheckServer}s to deliver remote
 * addresses that they see while handling incoming connectivity checks.
 * Implementations of this interface should determine whether these addresses
 * were (or will be) advertised by the remote peer and, if not, consider them
 * as new, peer reflexive candidates.
 *
 * @author Emil Ivov
 */
public interface RemoteAddressHandler
{
    /**
     * Notifies the implementation that the {@link ConnectivityCheckServer} has
     * just received a message on <tt>localAddress</tt> originating at
     * <tt>remoteAddress</tt> carrying the specified <tt>priority</tt>.
     *
     * @param remoteAddress the address that we've just seen, and that is
     * potentially a peer-reflexive address.
     * @param localAddress the address that we were contacted on.
     * @param priority the priority that the remote party assigned to
     * @param remoteUFrag the user fragment that we should be using when and if
     * we decide to send a check to <tt>remoteAddress</tt>.
     *
     */
    public void handleRemoteAddress(TransportAddress remoteAddress,
                                  TransportAddress localAddress,
                                  long             priority,
                                  String           remoteUFrag);
}
