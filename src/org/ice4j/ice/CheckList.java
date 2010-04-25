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
 *
 * @author Emil Ivov
 */
public class CheckList
    extends LinkedList<CandidatePair>
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
    protected void setState(CheckListState state)
    {
        this.state = state;
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
