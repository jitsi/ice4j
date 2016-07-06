/*
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ice4j.util;

import java.util.logging.*;
import java.util.logging.Logger; // Disambiguation.

public class QueueStatistics
{
    /**
     * The scale to use for {@link RateStatistics}. This makes their output in
     * units (e.g. packets) per second.
     */
    private static final int SCALE = 1000;

    /**
     * The interval (in number of calls to {@link #add(long)} or
     * {@link #remove(long)}) at which the gathered statistics will be printed.
     */
    private static final int DEFAULT_PRINT_INTERVAL = 500;

    /**
     * Calculate the average rate of addition of packets in a 200ms window.
     */
    private final RateStatistics addRateStatistics = new RateStatistics(200, SCALE);

    /**
     * Calculate the average rate of removal of packets in a 200ms window.
     */
    private final RateStatistics removeRateStatistics = new RateStatistics(200, SCALE);

    /**
     * The {@link Logger} instance used for logging output.
     */
    private final Logger logger;

    private int head = 0;
    private int size = 0;
    private int[] sizes = new int[DEFAULT_PRINT_INTERVAL];
    private long[] timestamps = new long[DEFAULT_PRINT_INTERVAL];
    private long[] addRates = new long[DEFAULT_PRINT_INTERVAL];
    private long[] removeRates = new long[DEFAULT_PRINT_INTERVAL];
    private int[] totalPacketsAddedHistory = new int[DEFAULT_PRINT_INTERVAL];
    private int totalPacketsAdded = 0;
    private String logHeader;

    /**
     * Initializes a new {@link QueueStatistics} instance.
     * 
     * @param id Identifier to distinguish the log output of multiple
     *            {@link QueueStatistics} instances.
     */
    public QueueStatistics(String id)
    {
        logger = Logger.getLogger("QueueStatistics-" + id);
        logHeader = "QueueStatistics-" + id + ": ";

        // We let the users of this class decide whether to enable logging (by
        // creating a QueueStatistic instance) or not.
        logger.setLevel(Level.ALL);
    }

    /**
     * Registers the addition of a packet to the corresponding queue.
     * @param now the time (in milliseconds since the epoch) at which the
     * packet was added.
     */
    public synchronized void add(long now)
    {
        addRateStatistics.update(1, now);
        size++;
        totalPacketsAdded++;
        update(now);
    }

    /**
     * Registers the removal of a packet from the corresponding queue.
     * @param now the time (in milliseconds since the epoch) at which the
     * packet was removed.
     */
    public synchronized void remove(long now)
    {
        removeRateStatistics.update(1, now);
        size--;
        update(now);
    }

    private synchronized void update(long now)
    {
        if (head == sizes.length)
        {
            print();
            head = 0;
        }

        sizes[head] = size;
        timestamps[head] = now;
        addRates[head] = addRateStatistics.getRate(now);
        removeRates[head] = removeRateStatistics.getRate(now);
        totalPacketsAddedHistory[head] = totalPacketsAdded;
        head++;
    }

    private void print()
    {
        StringBuilder s = new StringBuilder();
        for (int i =0; i<sizes.length; i++)
        {
            s.append(logHeader).
                append(timestamps[i]).append(' ').
                append(sizes[i]).append(' ').
                append(addRates[i]).append(' ').
                append(removeRates[i]).append(' ').
                append(totalPacketsAddedHistory[i]).append('\n');
        }
        logger.fine(s.toString());
    }
}
