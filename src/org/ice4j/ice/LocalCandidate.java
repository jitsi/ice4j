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
 * <tt>LocalCandidate</tt>s are obtained by an agent for every stream component
 * and are then included in outgoing offers or answers.
 *
 * @author Emil Ivov
 */
public abstract class LocalCandidate
    extends Candidate
{

    /**
     * Creates a <tt>LocalCandidate</tt> instance for the specified transport
     * address and properties.
     *
     * @param transportAddress  the transport address that this candidate is
     * encapsulating.
     * @param parentComponent the <tt>Component</tt> that this candidate
     * belongs to.
     * @param type the <tt>CandidateType</tt> for this <tt>Candidate</tt>.
     */
    public LocalCandidate(TransportAddress transportAddress,
                          Component        parentComponent,
                          CandidateType    type)
    {
        super(transportAddress, parentComponent, type);
    }

    /**
     * Gets the <tt>DatagramSocket</tt> associated with this <tt>Candidate</tt>.
     *
     * @return the <tt>DatagramSocket</tt> associated with this
     * <tt>Candidate</tt>
     */
    public abstract DatagramSocket getSocket();

    /**
     * Frees resources allocated by this candidate such as its
     * <tt>DatagramSocket</tt> for example.
     */
    protected void free()
    {
        getSocket().close();
    }
}
