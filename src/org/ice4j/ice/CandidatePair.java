/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.util.logging.*;

/**
 * <tt>CandidatePair</tt>s map local to remote <tt>Candidate</tt>s so that they
 * could be added to check lists. Connectivity in ICE is always verified by
 * pairs: i.e. STUN packets are sent from the local candidate of a pair to the
 * remote candidate of a pair. To see which pairs work, an agent schedules a
 * series of <tt>ConnectivityCheck</tt>s. Each check is a STUN request/response
 * transaction that the client will perform on a particular candidate pair by
 * sending a STUN request from the local candidate to the remote candidate.
 *
 * @author Emil Ivov
 */
public class CandidatePair
    implements Comparable<CandidatePair>
{
    /**
     * The <tt>Logger</tt> used by the <tt>CandidatePair</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger = Logger
                    .getLogger(CandidatePair.class.getName());

    /**
     * The local candidate of this pair.
     */
    private final LocalCandidate localCandidate;

    /**
     * The remote candidate of this pair.
     */
    private final RemoteCandidate remoteCandidate;

    /**
     * Priority of the candidate-pair
     */
    private final long priority;

    /**
     * Each candidate pair has a a state that is assigned once the check list
     * for each media stream has been computed. The ICE RFC defines five
     * potential values that the state can have and they are all represented
     * in the <tt>CandidatePairState</tt> enumeration.
     */
    private CandidatePairState state = CandidatePairState.WAITING;

    /**
     * Creates a <tt>CandidatePair</tt> instance mapping <tt>localCandidate</tt>
     * to <tt>remoteCandidate</tt>.
     *
     * @param localCandidate the local candidate of the pair.
     * @param remoteCandidate the remote candidate of the pair.
     */
    public CandidatePair(LocalCandidate localCandidate,
                         RemoteCandidate remoteCandidate)
    {

        this.localCandidate = localCandidate;
        this.remoteCandidate = remoteCandidate;

        priority = computePriority();
    }

    /**
     * Returns the foundation of this <tt>CandidatePair</tt>. The foundation
     * of a <tt>CandidatePair</tt> is just the concatenation of the foundations
     * of its two candidates. Initially, only the candidate pairs with unique
     * foundations are tested. The other candidate pairs are marked "frozen".
     * When the connectivity checks for a candidate pair succeed, the other
     * candidate pairs with the same foundation are unfrozen. This avoids
     * repeated checking of components which are superficially more attractive
     * but in fact are likely to fail.
     *
     * @return the foundation of this candidate pair, which is a concatenation
     * of the foundations of the remote and local candidates.
     */
    public String getFoundation()
    {
        return localCandidate.getFoundation()
            + remoteCandidate.getFoundation();
    }

    /**
     * Returns the <tt>LocalCandidate</tt> of this <tt>CandidatePair</tt>.
     *
     * @return the local <tt>Candidate</tt> of this <tt>CandidatePair</tt>.
     */
    public LocalCandidate getLocalCandidate()
    {
        return localCandidate;
    }

    /**
     * Returns the remote candidate of this <tt>CandidatePair</tt>.
     *
     * @return the remote <tt>Candidate</tt> of this <tt>CandidatePair</tt>.
     */
    public RemoteCandidate getRemoteCandidate()
    {
        return remoteCandidate;
    }

    /**
     * Returns the state of this <tt>CandidatePair</tt>. Each candidate pair has
     * a state that is assigned once the check list for each media stream has
     * been computed. The ICE RFC defines five potential values that the state
     * can have. They are represented here with the <tt>CandidatePairState</tt>
     * enumeration.
     *
     * @return the <tt>CandidatePairState</tt> that this candidate pair is
     * currently in.
     */
    public CandidatePairState getState()
    {
        return state;
    }

    /**
     * Sets the <tt>CandidatePairState</tt> of this pair to <tt>state</tt>. This
     * method should only be called by the ice agent, during the execution of
     * the ICE procedures.
     *
     * @param state the state that this candidate pair is to enter.
     */
    protected void setState(CandidatePairState state)
    {
        this.state = state;
    }

    /**
     * Determines whether this candidate pair is frozen or not. Initially, only
     * the candidate pairs with unique foundations are tested. The other
     * candidate pairs are marked "frozen". When the connectivity checks for a
     * candidate pair succeed, the other candidate pairs with the same
     * foundation are unfrozen.
     *
     * @return true if this candidate pair is frozen and false otherwise.
     */
    public boolean isFrozen()
    {
        return this.getState().equals(CandidatePairState.FROZEN);
    }

    /**
     * Returns the candidate in this pair that belongs to the controlling agent.
     *
     * @return a reference to the <tt>Candidate</tt> instance that comes from
     * the controlling agent.
     */
    public Candidate getControllingAgentCandidate()
    {
        return (getLocalCandidate().getParentComponent().getParentStream()
                        .getParentAgent().isControlling())
                    ? getLocalCandidate()
                    : getRemoteCandidate();
    }

    /**
     * Returns the candidate in this pair that belongs to the controlled agent.
     *
     * @return a reference to the <tt>Candidate</tt> instance that comes from
     * the controlled agent.
     */
    public Candidate getControlledAgentCandidate()
    {
        return (getLocalCandidate().getParentComponent().getParentStream()
                        .getParentAgent().isControlling())
                    ? getRemoteCandidate()
                    : getLocalCandidate();
    }


    /**
     * A candidate pair priority is computed the following way:<br>
     * Let G be the priority for the candidate provided by the controlling
     * agent. Let D be the priority for the candidate provided by the
     * controlled agent. The priority for a pair is computed as:
     * <p>
     * <i>pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)</i>
     * <p>
     * This formula ensures a unique priority for each pair. Once the priority
     * is assigned, the agent sorts the candidate pairs in decreasing order of
     * priority. If two pairs have identical priority, the ordering amongst
     * them is arbitrary.
     *
     * @return a long indicating the priority of this candidate pair.
     */
    private long computePriority()
    {
        //use G and D as local and remote candidate priority names to fit the
        //definition in the RFC.
        long G = getControllingAgentCandidate().getPriority();
        long D = getControlledAgentCandidate().getPriority();

        return (long)Math.pow(2, 32)*Math.min(G,D)
                + 2*Math.max(G,D)
                + (G>D?1l:0l);
    }

    /**
     * Returns the priority of this pair.
     *
     * @return the priority of this pair.
     */
    public long getPriority()
    {
        return priority;
    }

    /**
     * Compares this <tt>CandidatePair</tt> with the specified object for order.
     * Returns a negative integer, zero, or a positive integer as this
     * <tt>CandidatePair</tt> is less than, equal to, or greater than the
     * specified object.<p>
     *
     * @param   candidatePair the Object to be compared.
     * @return  a negative integer, zero, or a positive integer as this
     * <tt>CandidatePair</tt> is less than, equal to, or greater than the
     * specified object.
     *
     * @throws ClassCastException if the specified object's type prevents it
     *         from being compared to this Object.
     */
    public int compareTo(CandidatePair candidatePair)
    {
        return (int)(getPriority() - candidatePair.getPriority());
    }

    /**
     * Returns a String representation of this <tt>CandidatePair</tt>.
     *
     * @return a String representation of the object.
     */
    public String toString()
    {
        return "CandidatePair (State=" + getState()
            + " Priority=" + getPriority()
            + "):\n\tLocalCandidate=" + getLocalCandidate()
            + "\n\tRemoteCandidate=" + getRemoteCandidate();
    }
}
