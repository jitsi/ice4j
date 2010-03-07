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
}
