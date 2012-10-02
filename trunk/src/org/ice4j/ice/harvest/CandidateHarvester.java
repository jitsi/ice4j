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
     * The last harvest start time for this harvester. -1 if this harvester is
     * not currently harvesting.
     */
    private long lastStartHarvestingTime = -1;

    /**
     * The last ended harvesting time for this harvester. -1 if this harvester
     * has never harvested yet.
     */
    private long lastHarvestingTime = -1;

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
        // Remember the start date of this harvester.
        this.lastStartHarvestingTime = System.currentTimeMillis();
        // Reset the last harvesting time.
        this.lastHarvestingTime = -1;
    }

    /**
     * Stops the harvesting timer. Called when the harvest ends.
     */
    public void stopHarvesting()
    {
        // Remember the last harvesting time.
        this.lastHarvestingTime = this.getHarvestingTime();
        // Stops the current timer.
        this.lastStartHarvestingTime = -1;
    }

    /**
     * Returns the current harvesting time in ms. If this harvester is not
     * currently harvesting, then returns the value of the last harvesting time.
     * -1 if this harvester has nerver harvested.
     *
     * @return The current harvesting time in ms. If this harvester is not
     * currently harvesting, then returns the value of the last harvesting time.
     * -1 if this harvester has nerver harvested.
     */
    public long getHarvestingTime()
    {
        if(this.lastStartHarvestingTime != -1)
        {
            long currentHarvestingTime
                = System.currentTimeMillis() - lastStartHarvestingTime;
            // Retest here, while the harvesting may be end while computing the
            // harvsting time.
            if(this.lastStartHarvestingTime != -1)
            {
                return currentHarvestingTime;
            }
        }
        // If we are ont currently harvesting, then returns the value of the
        // last harvesting time.
        return this.lastHarvestingTime;
    }
}
