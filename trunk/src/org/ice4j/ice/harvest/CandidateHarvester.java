/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice.harvest;

import java.util.*;

import org.ice4j.ice.*;

/**
 * A <tt>CandidateHarvester</tt> gathers a certain kind of <tt>Candidate</tt>s
 * (e.g. host, reflexive, or relayed) for a specified {@link
 * org.ice4j.ice.Component}.
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 */
public abstract class CandidateHarvester
{
    /**
     * Manages statisics about harvesting time.
     */
    private HarvestingTimeStat harvestingTimeStat = new HarvestingTimeStat();

    /**
     * Gathers all candidate addresses of the type that this
     * <tt>CandidateHarvester</tt> supports. The gathered candidate addresses
     * are to be added by this <tt>CandidateHarvester</tt> to the specified
     * <tt>Component</tt> using
     * {@link Component#addLocalCandidate(LocalCandidate)} as soon as they are
     * discovered.
     *
     * @param component the {@link Component} that we'd like to gather candidate
     * addresses for.
     * @return  the <tt>LocalCandidate</tt>s gathered by this
     * <tt>CandidateHarvester</tt>. Though they are to be added by this
     * <tt>CandidateHarvester</tt> to the specified <tt>component</tt> as soon
     * as they are discovered, they should also be returned in order to make
     * sure that the gathering will be considered successful.
     */
    public abstract Collection<LocalCandidate> harvest(Component component);

    /**
     * Starts the harvesting timer. Called when the harvest begins.
     */
    public void startHarvesting()
    {
        this.harvestingTimeStat.startHarvesting();
    }

    /**
     * Stops the harvesting timer. Called when the harvest ends.
     */
    public void stopHarvesting()
    {
        this.harvestingTimeStat.stopHarvesting();
    }

    /**
     * Returns the current harvesting time in ms. If this harvester is not
     * currently harvesting, then returns the value of the last harvesting time.
     * 0 if this harvester has nerver harvested.
     *
     * @return The current harvesting time in ms. If this harvester is not
     * currently harvesting, then returns the value of the last harvesting time.
     * 0 if this harvester has nerver harvested.
     */
    public long getHarvestingTime()
    {
        return this.harvestingTimeStat.getHarvestingTime();
    }

    /**
     * Returns the number of harvesting for this harvester.
     *
     * @return The number of harvesting for this harvester.
     */
    public int getNbHarvesting()
    {
        return this.harvestingTimeStat.getNbHarvesting();
    }
}
