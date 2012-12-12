/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice.harvest;

/**
 * Manages statisics about harvesting time.
 *
 * @author Vincent Lucas
 */
public class HarvestingTimeStat
{
    /**
     * The number of harvesting for this harvester.
     */
    private int nbHarvesting = 0;

    /**
     * The last harvest start time for this harvester. -1 if this harvester is
     * not currently harvesting.
     */
    private long lastStartHarvestingTime = -1;

    /**
     * The last ended harvesting time for this harvester. -1 if this harvester
     * has never harvested yet.
     */
    private long lastHarvestingTime = 0;

    /**
     * Starts the harvesting timer. Called when the harvest begins.
     */
    public void startHarvesting()
    {
        ++nbHarvesting;
        // Remember the start date of this harvester.
        this.lastStartHarvestingTime = System.currentTimeMillis();
    }

    /**
     * Stops the harvesting timer. Called when the harvest ends.
     */
    public void stopHarvesting()
    {
        // Remember the last harvesting time.
        this.lastHarvestingTime = this.getHarvestingTime();
        // Stops the current timer (must be done after setting the
        // lastHarvestingTime).
        this.lastStartHarvestingTime = -1;
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
        if(this.lastStartHarvestingTime != -1)
        {
            long currentHarvestingTime
                = System.currentTimeMillis() - lastStartHarvestingTime;
            // Retest here, while the harvesting may be end while computing the
            // harvsting time.
            if(this.lastStartHarvestingTime != -1)
            {
                return this.lastHarvestingTime + currentHarvestingTime;
            }
        }
        // If we are ont currently harvesting, then returns the value of the
        // last harvesting time.
        return this.lastHarvestingTime;
    }

    /**
     * Returns the number of harvesting for this harvester.
     *
     * @return The number of harvesting for this harvester.
     */
    public int getNbHarvesting()
    {
        return this.nbHarvesting;
    }
}
