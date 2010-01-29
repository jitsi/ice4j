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
 * A <tt>CandidateHarvester</tt> gathers a certain kind of <tt>Candidate</tt>s
 * (e.g. host, reflexive, or relayed) for a specified {@link
 * org.ice4j.ice.Component}.
 *
 * @author Emil Ivov
 */
public interface CandidateHarvester
{

    /**
     * Gathers all candidate addresses of the type that this
     * <tt>CandidateHarvester</tt>
     *
     * @param component the {@link Component} that we'd like to gather candidate
     * addresses for.
     */
    public void harvest(Component component);
}
