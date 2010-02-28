/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.net.*;

import org.ice4j.*;

/**
 * <tt>HostCandidate</tt>s are obtained by binding to a specific port from an
 * IP address on the host that is running us. This includes IP addresses on
 * physical interfaces and logical ones, such as ones obtained through
 * Virtual Private Networks (VPNs), Mobile IPv6, Realm Specific IP (RSIP) etc.
 * <p>
 * At this point this class only supports UDP candidates. Implementation of
 * support for other transport protocols should mean that this class should
 * become abstract and some transport specific components like to socket for
 * example should be brought down the inheritance chain.
 * </p>
 *
 * @author Emil Ivov
 */
public class HostCandidate extends LocalCandidate
{

    /**
     * If this is a local candidate the field contains the socket that is
     * actually associated with the candidate.
     */
    private final DatagramSocket socket;

    /**
     * Creates a HostCandidate for the specified transport address.
     *
     * @param socket the {@link DatagramSocket} that communication associated
     * with this <tt>Candidate</tt> will be going through.
     * @param parentComponent the <tt>Component</tt> that this candidate
     * belongs to.
     */
    public HostCandidate(DatagramSocket socket,
                         Component      parentComponent)
    {
        super(new TransportAddress(socket.getLocalAddress(),
                        socket.getLocalPort(), Transport.UDP),
              parentComponent,
              CandidateType.HOST_CANDIDATE);

        this.socket = socket;
        setBase(this);
    }

    /**
     * Gets the <tt>DatagramSocket</tt> associated with this <tt>Candidate</tt>.
     *
     * @return the <tt>DatagramSocket</tt> associated with this
     * <tt>Candidate</tt>
     * @see LocalCandidate#getSocket()
     */
    public DatagramSocket getSocket()
    {
        return socket;
    }
}
