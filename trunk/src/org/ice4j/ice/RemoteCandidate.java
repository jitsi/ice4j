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
 * <tt>RemoteCandidate</tt>s are candidates that an agent received in an offer
 * or an answer from its peer, and that it would use to form candidate pairs
 * after combining them with its local candidates.
 *
 * @author Emil Ivov
 */
public class RemoteCandidate
    extends Candidate
{

    /**
     * Creates a <tt>RemoteCandidate</tt> instance for the specified transport
     * address and properties.
     *
     * @param transportAddress  the transport address that this candidate is
     * encapsulating.
     * @param parentComponent the <tt>Component</tt> that this candidate
     * belongs to.
     * @param type the <tt>CandidateType</tt> for this <tt>Candidate</tt>.
     */
    public RemoteCandidate(TransportAddress transportAddress,
                           Component        parentComponent,
                           CandidateType    type)
    {
        super(transportAddress, parentComponent, type);
    }
}
