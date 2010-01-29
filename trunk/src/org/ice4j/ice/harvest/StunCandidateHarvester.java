/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice.harvest;

import org.ice4j.ice.*;

/**
 * A <tt>StunCandidateHarvester</tt> gathers STUN <tt>Candidate</tt>s for a
 * specified {@link org.ice4j.ice.Component}.
 *
 * @author Emil Ivov
 */
public class StunCandidateHarvester
    implements CandidateHarvester
{
    /**
     * Gathers STUN candidates for all host <tt>Candidate</tt>s that are already
     * present in the specified <tt>component</tt>.
     *
     * @param component the {@link Component} that we'd like to gather candidate
     * STUN <tt>Candidate</tt>s for.
     */
    public void harvest(Component component)
    {
        //todo implement
    }
}
