/**
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.oldice;

/**
 * A candidate pair is a pairing containing a local candidate and a remote
 * candidate. Connectivity in ICE is always verified by pairs: i.e. stun
 * packets are sent from the local candidate of a pair to the remote candidate
 * of a pair. To see which pairs work, an agent schedules a series of
 * <tt>ConnectivityCheck</tt>s. Each check is a STUN request/response
 * transaction that the client will perform on a particular candidate pair by
 * sending a STUN request from the local candidate to the remote candidate.
 *
 * @author Emil Ivov
 */
public class CandidatePair
        implements Comparable
{
    /**
     * The local candidate of this <tt>CandidatePaire</tt>.
     */
    private Candidate localCandidate = null;

    /**
     * The remote candidate for this <tt>CandidatePair</tt>.
     */
    private Candidate remoteCandidate = null;
    
    /**
     * Priority of the candidate-pair
     */
    private long priority = 0;

    /**
     * Indicates that the candidate pair is in a Waiting state which means that
     * a check has not been performed for this pair, and can be performed as
     * soon as it is the highest priority Waiting pair on the check list.
     */
    public static final String STATE_WAITING = "Waiting";

    /**
     * Indicates that the candidate pair is in a "In-Progress" state which means that
     * a check has been sent for this pair, but the transaction is in progress.
     */
    public static final String STATE_IN_PROGRESS = "In-Progress";

    /**
     * Indicates that the candidate pair is in a "Succeeded" state which means
     * that a check for this pair was already done and produced a successful
     * result.
     */
    public static final String STATE_SUCCEEDED = "Succeeded";

    /**
     * Indicates that the candidate pair is in a "Failed" state which means that
     * a check for this pair was already done and failed, either never producing
     * any response or producing an unrecoverable failure response.
     */
    public static final String STATE_FAILED = "Failed";

    /**
     * Indicates that the candidate pair is in a "Frozen" state which means that
     * a check for this pair hasn't been performed, and it can't yet be
     * performed until some other check succeeds, allowing this pair to unfreeze
     * and move into the Waiting state.
     */
    public static final String STATE_FROZEN = "Frozen";

    /**
     * Each candidate pair has a a state that is assigned once the check list
     * for each media stream has been computed. The ICE RFC defines five
     * potential values that the state can have. They are represented here with
     * the STATE_XXX class fields.
     */
    private String state = STATE_FROZEN;

    /**
     * Creates an instance of a <tt>CandiatePair</tt> with the specified local
     * and remote candidates.
     *
     * @param localCandidate the local <tt>Candidate</tt> of the
     * <tt>CandidatePair</tt>.
     *
     * @param remoteCandidate the remote <tt>Candidate</tt> of the
     * <tt>CandidatePair</tt>.
     *
     * @throws java.lang.IllegalArgumentException either of the parameters is
     * null.
     */
    public CandidatePair(Candidate localCandidate, Candidate remoteCandidate)
        throws IllegalArgumentException
    {
        if(localCandidate == null || remoteCandidate == null)
            throw new IllegalArgumentException(
                "The local and remote candidate params must not be null when "
                +"creating a CandidatePair! LocalCandidate was: "
                + localCandidate + " RemoteCandidate was: "
                + remoteCandidate);

        this.localCandidate = localCandidate;
        this.remoteCandidate = remoteCandidate;
    }

    /**
     * Returns the foundation of this <tt>CandidatePair</tt>. The foundation
     * of a candidate pari is just the concatenation of the foundations of its
     * two candidates. Initially, only the candidate pairs with unique
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
     * Returns the local candidate of this <tt>CandidatePair</tt>.
     *
     * @return the local <tt>Candidate</tt> of this <tt>CandidatePair</tt>.
     */
    public Candidate getLocalCandidate()
    {
        return localCandidate;
    }
    
    /**
     * 
     */
    public void setLocalCandidate(Candidate localCandidate)
    {
        this.localCandidate = localCandidate;
    }

    /**
     * Returns the remote candidate of this <tt>CandidatePair</tt>.
     *
     * @return the remote <tt>Candidate</tt> of this <tt>CandidatePair</tt>.
     */
    public Candidate getRemoteCandidate()
    {
        return remoteCandidate;
    }

    /**
     * Specifies whether this candidate pair should be frozen or not. Initially,
     * only the candidate pairs with unique foundations are tested. The other
     * candidate pairs are marked "frozen". When the connectivity checks for a
     * candidate pair succeed, the other candidate pairs with the same
     * foundation are unfrozen.
     *
     * @param frozen true if this candidate pair is to be frozen and false
     * otherwise.
     */
    public void setFrozen(boolean frozen)
    {
        this.getState().equals(STATE_FROZEN);
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
    /*public boolean isFrozen()
    {
        return isFrozen;
    }*/

    /**
     * Returns the candidate in this pair that belongs to the controlling agent.
     *
     * @return a reference to the <tt>Candidate</tt> instance that comes from
     * the controlling agent.
     */
    public Candidate getControllingAgentCandidate()
    {
        return (!getLocalCandidate().getParentAgent().isControlling())
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
        return !(getLocalCandidate().getParentAgent().isControlling())
                    ? getLocalCandidate()
                    : getRemoteCandidate();
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
    public long computePriority()
    {
        //use G and D as local and remote candidate priority names to fit the
        //definition in the RFC.
        long G = getControllingAgentCandidate().getPriority();
        long D = getControlledAgentCandidate().getPriority();

        return (long)Math.pow(2, 32)*Math.min(G,D)
                + 2*Math.max(G,D)
                + (G>D?1l:0l);
    }
    
    public void setPriority(long priority)
    {
        this.priority = priority;
    }
    
    public long getPriority()
    {
        return priority;
    }

    /**
     * Returns the state of this <tt>CandidatePair</tt>. Each candidate pair has
     * a state that is assigned once the check list for each media stream has
     * been computed. The ICE RFC defines five potential values that the state
     * can have. They are represented here with the STATE_XXX class fields.
     *
     * @return one of the STATE_XXX fields defined in this class indicating the
     * state that this candidate pair is currently in.
     */
    public String getState()
    {
        return state;
    }

    /**
     * Sets the state of this candidate pair to be <tt>state</tt>. This method
     * should only be called by a local ice agent, during the execution of the
     * ICE procedures.
     *
     * @param state the state that this candidate pair is to enter.
     */
    protected void setState(String state)
    {
        this.state = state;
    }

    /**
     * Compares this <tt>CandidatePair</tt> with the specified object for order.
     * Returns a negative integer, zero, or a positive integer as this
     * <tt>CandidatePair</tt> is less than, equal to, or greater than the
     * specified object.<p>
     *
     * @param   obj the Object to be compared.
     * @return  a negative integer, zero, or a positive integer as this
     * <tt>CandidatePair</tt> is less than, equal to, or greater than the
     * specified object.
     *
     * @throws ClassCastException if the specified object's type prevents it
     *         from being compared to this Object.
     */
    public int compareTo(Object obj)
    {
        return (int)(computePriority()
                     - ((CandidatePair)obj).computePriority());
    }

    /**
     * Returns a String representation of this <tt>CandidatePair</tt>.
     *
     * @return a String representation of the object.
     */
    public String toString()
    {
        return "CandidatePair[LocalCandidate="
            + getLocalCandidate().getTransportAddress()
            + " RemoteCandidate="
            + getRemoteCandidate().getTransportAddress()
            + " State=" + getState()
            + " Priority=" + computePriority()
            +  "]";
    }
}
