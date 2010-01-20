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
 * A candidate represents a transport address that is a potential point of
 * contact for receipt of media. Candidates also have properties - their
 * type (server reflexive, relayed or host), priority, foundation,
 * and base.
 *
 * @author Emil Ivov
 */
public class Candidate
{
    /**
     * The transport address represented by this candidate.
     */
    private TransportAddress transportAddress = null;

    /**
     * The type of this candidate. At this point the ICE specification (and
     * hence this implementation) only defines for candidate types: host,
     * server reflexive, peer reflexive and relayed candidates. Others may be
     * added in the future.
     */
    private CandidateType candidateType = null;

    /**
     * An arbitrary string that is the same for two candidates
     * that have the same type, base IP address, protocol (UDP, TCP,
     * etc.) and STUN or TURN server. If any of these are different then
     * the foundation will be different. Two candidate pairs with the
     * same foundation pairs are likely to have similar network
     * characteristics. Foundations are used in the frozen algorithm.
     */
    private String foundation = null;

    /**
     * The base of a server reflexive candidate is the host candidate
     * from which it was derived. A host candidate is also said to have
     * a base, equal to that candidate itself. Similarly, the base of a
     * relayed candidate is that candidate itself.
     */
    private Candidate base = null;

    /**
     * A unique priority number that MUST be a positive integer between 1 and
     * (2**32 - 1). This priority will be set and used by ICE algorithms to
     * determine the order of the connectivity checks and the relative
     * preference for candidates.
     */
    private long priority = 0;

    /**
     * The component that this candidate was created for. Every candidate is
     * always associated with a specific component for which it is a candidate.
     */
    private Component parentComponent = null;

    /**
     * Creates a candidate for the specified transport address and properties.
     *
     * @param transportAddress  the transport address that this candidate is
     * encapsulating.
     * @param parentComponent the <tt>Component</tt> that this candidate
     * belongs to.
     */
    public Candidate(TransportAddress transportAddress,
                     Component        parentComponent)
    {
        this.transportAddress = transportAddress;
        this.parentComponent = parentComponent;
    }

    /**
     * Returns the type of this candidate which should be an instance of the
     * {@link CandidateType} enumeration.
     *
     * @return a <tt>CandidateType</tt> indicating the type of this
     * <tt>Candidate</tt>.
     */
    public CandidateType getCandidateType()
    {
        return candidateType;
    }

    /**
     * Sets the type of this candidate which should be an instance of the
     * {@link CandidateType} enumeration.
     *
     * @param candidateType a <tt>CandidateType</tt> instance indicating the
     * type of this <tt>Candidate</tt>.
     */
    public void setCandidateType(CandidateType candidateType)
    {
        this.candidateType = candidateType;
    }

    /**
     * Returns a <tt>String</tt> containing the foundation of this
     * <tt>Candidate</tt>. A foundation is an arbitrary <tt>String</tt> that is
     * the same for candidates that have the same type, base IP address,
     * transport protocol (UDP, TCP, etc.) and STUN or TURN server. If any of
     * these are different then the foundation will be different. Two candidate
     * pairs with the same foundation pairs are likely to have similar network
     * characteristics. Typically, candidates for RTP and RTCP streams will
     * share the same foundation. Foundations are used in the frozen algorithm.
     *
     * @return the foundation of this <tt>Candidate</tt>.
     */
    public String getFoundation()
    {
        return foundation;
    }

    /**
     * Sets this <tt>Candidate</tt>'s foundation. A foundation is an arbitrary
     * string is alsways the same for candidates that have the same type, base
     * IP address, protocol (UDP, TCP, etc.) and STUN or TURN server. If any of
     * these are different then the foundation will be different. Two candidate
     * pairs with the same foundation pairs are likely to have similar network
     * characteristics. Foundations are used in the frozen algorithm.
     *
     * @param foundation the foundation of this <tt>Candidate</tt>.
     */
    public void setFoundation(String foundation)
    {
        this.foundation = foundation;
    }

    /**
     * Returns this <tt>Candidate</tt>'s base. The base of a server
     * reflexive candidate is the host candidate from which it was derived.
     * A host candidate is also said to have a base, equal to that candidate
     * itself. Similarly, the base of a relayed candidate is that candidate
     * itself.
     *
     * @return the base <tt>Candidate</tt> for this <tt>Candidate</tt>.
     */
    public Candidate getBase()
    {
        return base;
    }

    /**
     * Sets this <tt>Candidate</tt>'s base. The base of a server
     * reflexive candidate is the host candidate from which it was derived.
     * A host candidate is also said to have a base, equal to that candidate
     * itself. Similarly, the base of a relayed candidate is that candidate
     * itself.
     *
     * @param base the base <tt>Candidate</tt> of this <tt>Candidate</tt>.
     */
    public void setBase(Candidate base)
    {
        this.base = base;
    }

    /**
     * Returns the priority of this candidate. Priority is a unique priority
     * number that MUST be a positive integer between 1 and (2**32 - 1). This
     * priority will be set and used by ICE algorithms to  determine the order
     * of the connectivity checks and the relative preference for candidates.
     *
     * @return a number between 1 and (2**32 - 1) indicating the priority of
     * this candidate.
     */
    public long getPriority()
    {
        return priority;
    }

    /**
     * Sets the priority for this candidate.
     *
     * @param priority A unique priority number that MUST be a positive integer
     * between 1 and (2**32 - 1). This priority will be set and used by ICE
     * algorithms to determine the order of the connectivity checks and the
     * relative preference for candidates.
     */
    public void setPriority(long priority)
    {
        this.priority = priority;
    }

    /**
     * Returns the transport address that this candidate is representing.
     *
     * @return the TransportAddress encapsulated by this Candidate.
     */
    public TransportAddress getTransportAddress()
    {
        return transportAddress;
    }

    /**
     * Indicates whether some other Candidate is "equal to" this one. We
     * consider candidates equal when they are redundant, i.e.
     * <p>
     * @param obj the reference object with which to compare.
     * <p>
     * @return <code>true</code> if this <tt>Candidate</tt> is equal to the
     * obj argument; <code>false</code> otherwise.
     *
     * @throws java.lang.NullPointerException if <tt>obj</tt> is null;
     */
    public boolean equals(Object obj)
        throws NullPointerException
    {
        if(obj == this)
            return true;

        if( ! (obj instanceof Candidate))
            return false;

        Candidate targetCandidate = (Candidate)obj;

        //compare candidate addresses
        if( ! targetCandidate.getTransportAddress()
                .equals(getTransportAddress()))
            return false;

        //compare bases
        if( getBase() == null )
        {
            if (targetCandidate.getBase() != null)
                return false;
        }

        //compare other properties
        if(getBase().equals(targetCandidate.getBase())
            && getPriority() == targetCandidate.getPriority()
            && getCandidateType() == targetCandidate.getCandidateType()
            && getFoundation().equals(targetCandidate.getFoundation()))
        {
            return true;
        }
        return false;
    }

    /**
     * Returns a reference to the <tt>Component</tt> that this candidate belongs
     * to.
     *
     * @return a reference to the <tt>Component</tt> that this candidate belongs
     * to.
     */
    public Component getParentComponent()
    {
        return parentComponent;
    }

    /**
     * Returns a <tt>String</tt> representation of this <tt>Candidate</tt>
     *
     * @return a <tt>String</tt> representation of this Candidate.
     */
    public String toString()
    {
        return "Candidate-"+getTransportAddress()+", Priority="+getPriority();
    }
}
