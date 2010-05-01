/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.util.*;

/**
 * A check list is a list of <tt>CandidatePair</tt>s with a state (i.e. a
 * <tt>CheckListState</tt>). The pairs in a check list are those that an ICE
 * agent will run STUN connectivity checks for. There is one check list per
 * in-use media stream resulting from the offer/answer exchange.
 * <p>
 * Given the asynchronous nature of ice, a check list may be accessed from
 * different locations. This class therefore stores pairs in a <tt>Vector</tt>
 * @author Emil Ivov
 */
public class CheckList
    extends Vector<CandidatePair>
{
    /**
     * A dummy serialization id.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The state of this check list.
     */
    private CheckListState state = CheckListState.RUNNING;

    /**
     * The <tt>triggeredCheckQueue</tt> is a FIFO queue containing candidate
     * pairs for which checks are to be sent at the next available opportunity.
     * A pair would get into a triggered check queue as soon as we receive
     * a check on its local candidate.
     */
    private final List<CandidatePair> triggeredCheckQueue
                                          = new LinkedList<CandidatePair>();

    /**
     * Returns the state of this check list.
     *
     * @return the <tt>CheckListState</tt> of this check list.
     */
    public CheckListState getState()
    {
        return state;
    }

    /**
     * Sets the state of this list.
     *
     * @param state the <tt>CheckListState</tt> for this list.
     */
    public void setState(CheckListState state)
    {
        this.state = state;
    }

    /**
     * Adds <tt>pair</tt> to the local triggered check queue unless it's already
     * there. Additionally, the method sets the pair's state to {@link
     * CandidatePairState#WAITING}.
     *
     * @param pair the pair to schedule a triggered check for.
     */
    protected void scheduleTriggeredCheck(CandidatePair pair)
    {
        synchronized(triggeredCheckQueue)
        {
            if(!triggeredCheckQueue.contains(pair))
            {
                triggeredCheckQueue.add(pair);
                pair.setState(CandidatePairState.WAITING, null);
            }
        }
    }

    /**
     * Returns the first {@link CandidatePair} in the triggered check queue or
     * <tt>null</tt> if that queue is empty.
     *
     * @return the first {@link CandidatePair} in the triggered check queue or
     * <tt>null</tt> if that queue is empty.
     */
    public CandidatePair popTriggeredCheck()
    {
        synchronized(triggeredCheckQueue)
        {
            if(triggeredCheckQueue.size() > 0)
                return triggeredCheckQueue.remove(0);
        }

        return null;
    }

    /**
     * Returns the next {@link CandidatePair} that is eligible for a regular
     * connectivity check. According to RFC 5245 this would be the highest
     * priority pair that is in the <tt>Waiting</tt> state or, if there is
     * no such pair, the highest priority <tt>Frozen</tt> {@link CandidatePair}.
     *
     * @return the next {@link CandidatePair} that is eligible for a regular
     * connectivity check, which would either be the highest priority
     * <tt>Waiting</tt> pair or, when there's no such pair, the highest priority
     * <tt>Frozen</tt> pair or <tt>null</tt> otherwise
     *
     */
    public synchronized CandidatePair getNextOrdinaryPairToCheck()
    {
        if (size() < 1)
            return null;

        CandidatePair highestPriorityWaitingPair = null;
        CandidatePair highestPriorityFrozenPair = null;

        for (CandidatePair pair : this)
        {
            if (pair.getState() == CandidatePairState.WAITING)
            {
                if(highestPriorityWaitingPair == null
                   || pair.getPriority()
                                    > highestPriorityWaitingPair.getPriority())
                {
                        highestPriorityWaitingPair = pair;
                }
            }
            else if (pair.getState() == CandidatePairState.FROZEN)
            {
                if(highestPriorityFrozenPair == null
                   || pair.getPriority()
                                > highestPriorityFrozenPair.getPriority())
                    highestPriorityFrozenPair = pair;
            }
        }

        if(highestPriorityWaitingPair != null)
            return highestPriorityWaitingPair;
        else
            return highestPriorityFrozenPair; //return even if null
    }

    /**
     * Returns a <tt>String</tt> representation of this check list. It
     * consists of a list of the <tt>CandidatePair</tt>s in the order they
     * were inserted and enclosed in square brackets (<tt>"[]"</tt>). The method
     * would also call and use the content returned by every member
     * <tt>CandidatePair</tt>.
     *
     * @return A <tt>String</tt> representation of this collection.
     */
    public String toString()
    {
        StringBuffer buff = new StringBuffer("CheckList. (num pairs=");
        buff.append(size() + ")\n");

        Iterator<CandidatePair> pairs = iterator();

        while(pairs.hasNext())
        {
            buff.append(pairs.next().toString()).append("\n");
        }

        return buff.toString();
    }
}
