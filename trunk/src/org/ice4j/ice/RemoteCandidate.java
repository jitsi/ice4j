/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice;

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
     * The related address that the remote party sent in SDP, if it did.
     */
    private TransportAddress raddr;

    /**
     * Creates a <tt>RemoteCandidate</tt> instance for the specified transport
     * address and properties.
     *
     * @param transportAddress  the transport address that this candidate is
     * encapsulating.
     * @param parentComponent the <tt>Component</tt> that this candidate
     * belongs to.
     * @param type the <tt>CandidateType</tt> for this <tt>Candidate</tt>.
     * @param foundation the <tt>RemoteCandidate</tt>'s foundation as reported
     * by the session description protocol.
     * @param priority the <tt>RemoteCandidate</tt>'s priority as reported
     * by the session description protocol.
     */
    public RemoteCandidate(TransportAddress transportAddress,
                           Component        parentComponent,
                           CandidateType    type,
                           String           foundation,
                           long             priority)
    {
        super(transportAddress, parentComponent, type);
        setFoundation(foundation);
        setPriority(priority);
    }

    /**
     * Sets the priority of this <tt>RemoteCandidate</tt>. Priority is a unique
     * priority number that MUST be a positive integer between 1 and
     * (2**32 - 1). This priority will be set and used by ICE algorithms to
     * determine the order of the connectivity checks and the relative
     * preference for candidates.
     *
     * @param priority the priority number between 1 and (2**32 - 1).
     */
    public void setPriority(long priority)
    {
        super.priority = priority;
    }

    /**
     * Determines whether this <tt>Candidate</tt> is the default one for its
     * parent component.
     *
     * @return <tt>true</tt> if this <tt>Candidate</tt> is the default for its
     * parent component and <tt>false</tt> if it isn't or if it has no parent
     * Component yet.
     */
    @Override
    public boolean isDefault()
    {
        Component parentCmp = getParentComponent();

        if (parentCmp == null)
            return false;

        return equals(parentCmp.getDefaultRemoteCandidate());
    }

    /**
     * Returns the <tt>TransportAddress</tt> that the remote party indicated
     * as "related" for this <tt>Candidate</tt>.
     * <p>
     * Related addresses are present for server reflexive, peer reflexive and
     * relayed candidates. If a candidate is server or peer reflexive,
     * the related address is equal to the base of this <tt>Candidate</tt>.
     * If the candidate is relayed, the returned address is equal to the mapped
     * address. If the candidate is a host candidate then the method returns
     * <tt>null</tt>.
     *
     * @return the <tt>TransportAddress</tt> that the remote party indicated
     * as "related" for this <tt>Candidate</tt> or <tt>null</tt> if they didn't
     * include it in SDP.
     */
    @Override
    public TransportAddress getRelatedAddress()
    {
        return raddr;
    }

    /**
     * Specifies the <tt>TransportAddress</tt> that the remote party indicated
     * as "related" for this <tt>Candidate</tt>.
     *
     * @param relatedAddr the <tt>TransportAddress</tt> that the remote party
     * indicated as "related" for this <tt>Candidate</tt>.
     */
    public void setRelatedAddress(TransportAddress relatedAddr)
    {
        this.raddr = relatedAddr;
    }
}
