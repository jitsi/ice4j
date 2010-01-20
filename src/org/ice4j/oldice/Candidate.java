/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.oldice;

import org.ice4j.*;

/**
 * A candidate represents a transport address that is a potential point of
 * contact for receipt of media. Candidates also have properties - their
 * type (server reflexive, relayed or host), priority, foundation,
 * and base.
 *
 * @author Emil Ivov
 * @author Namal Senarathne
 */
public class Candidate
{
    /**
     * The transport address represented by this candidate.
     */
    private TransportAddress transportAddress = null;

    /**
     * Peer Reflexive Candidate: A candidate whose IP address and port are
     * a binding allocated by a NAT for an agent when it sent a STUN
     * Binding Request through the NAT to its peer.
     */
    public static final String PEER_REFLEXIVE_CANDIDATE = "prflx";

    /**
     * A Server Reflexive Candidate is a candidate whose IP address and port
     * are a binding allocated by a NAT for an agent when it sent a
     * packet through the NAT to a server. Server reflexive candidates
     * can be learned by STUN servers using the Binding Request, or TURN
     * servers, which provides both a Relayed and Server Reflexive
     * candidate.
     */
    public static final String SERVER_REFLEXIVE_CANDIDATE = "srflx";

    /**
     * A Relayed Candidate is a candidate obtained by sending a TURN Allocate
     * request from a host candidate to a TURN server. The relayed candidate is
     * resident on the TURN server, and the TURN server relays packets back
     * towards the agent.
     */
    public static final String RELAYED_CANDIDATE = "relay";

    /**
     * A candidate obtained by binding to a specific port
     * from an interface on the host. This includes both physical
     * interfaces and logical ones, such as ones obtained through Virtual
     * Private Networks (VPNs) and Realm Specific IP (RSIP) [RFC3102]
     * (which lives at the operating system level).
     */
    public static final String HOST_CANDIDATE = "host";

    /**
     * The type of this candidate. At this point the ICE specification (and
     * hence this implementation) only defines for candidate types: host,
     * server reflexive, peer reflexive and relayed candidates. Others may be
     * added in the future.
     */
    private String candidateType = null;

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
     * Returns the type of this candidate which should be one of the
     * XXX_CANDIDATE fields of this class. At this point the ICE specification
     * (and hence this implementation) only defines for candidate types: host,
     * server reflexive, peer reflexive and relayed candidates. Others may be
     * added in the future.
     *
     * @return a String equal to one of the XXX_CANDIDATE fields defined in
     * this class.
     */
    public String getCandidateType()
    {
        return candidateType;
    }

    public void setCandidateType(String candidateType)
    {
        this.candidateType = candidateType;
    }

    /**
     * Returns a String containing the foundation of this candidate. A
     * foundation is an arbitrary string that is the same for two candidates
     * that have the same type, base IP address, protocol (UDP, TCP, etc.) and
     * STUN or TURN server. If any of these are different then the foundation
     * will be different. Two candidate pairs with the same foundation pairs
     * are likely to have similar network characteristics. Foundations are
     * used in the frozen algorithm.
     *
     * @return the foundation of this candiate.
     */
    public String getFoundation()
    {
        return foundation;
    }

    public void setFoundation(String foundation)
    {
        this.foundation = foundation;
    }

    /**
     * The base of a server reflexive candidate is the host candidate from
     * which it was derived. A host candidate is also said to have a base,
     * equal to that candidate itself. Similarly, the base of a relayed
     * candidate is that candidate itself.
     *
     * @return the base <tt>Candidate</tt> for this <tt>Candidate</tt>.
     */
    public Candidate getBase()
    {
        return base;
    }

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
            && getCandidateType().equals(targetCandidate.getCandidateType())
            && getFoundation().equals(targetCandidate.getFoundation()))
        {
            return true;
        }
        return false;
    }

    /**
     * Returns a reference to the <tt>IceAgent</tt> that this candidate belongs
     * to.
     *
     * @return a reference to the <tt>IceAgent</tt> that this candidate belongs
     * to.
     */
    public IceAgent getParentAgent()
    {
        return parentComponent.getParentAgent();
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

    /**
     * Computes the priority for the specified candidate
     *
     * @param candidate
     * @return priority
     */
    public static long computePriority(Candidate candidate)
    {
        long priority;
        String candidateType = candidate.getCandidateType();
        int componentId = candidate.getParentComponent().getComponentID();

        int typePreference;
        if(candidateType.equals(Candidate.HOST_CANDIDATE))
        {
            typePreference = 126; // highest
        }
        else if(candidateType.equals(Candidate.PEER_REFLEXIVE_CANDIDATE))
        {
            typePreference = 110;
        }
        else if(candidateType.equals(Candidate.SERVER_REFLEXIVE_CANDIDATE))
        {
            typePreference = 100;
        }
        else // this is for relayed candidates
        {
            typePreference = 0;
        }

        priority = (long)Math.pow(2, 24)*typePreference +
                   (long)Math.pow(2, 8)*getLocalPreference(candidate) +
                   (long)(256 - componentId);

        return priority;
    }

    // TODO : look for RFC 3484 to implement this
    private static int getLocalPreference(Candidate candidate)
    {
        /*if(candidate.getParentAgent().isMultiHomed())
        {

        }
        else
        {
            return 65535;
        }*/

        return 65535;
    }
}
