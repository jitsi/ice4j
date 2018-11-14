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

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.logging.Logger; // Disambiguation.

/**
 * An abstract queue of packets. This is meant to eventually be able to be used
 * in the following classes (in ice4j and libjitsi) in place of their ad-hoc
 * queue implementations (which is the reason the class is parameterized):
 *     <br> RTPConnectorOutputStream.Queue
 *     <br> PushSourceStreamImpl#readQ
 *     <br> OutputDataStreamImpl#writeQ
 *     <br> SinglePortHarvester.MySocket#queue
 *     <br> MultiplexingSocket#received (and the rest of Multiplex* classes).
 *
 * @author Boris Grozev
 */
public abstract class PacketQueue<T>
{
    /**
     * The {@link Logger} used by the {@link PacketQueue} class and its
     * instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(PacketQueue.class.getName());

    /**
     * The default capacity of a {@link PacketQueue}.
     */
    private final static int DEFAULT_CAPACITY = 256;

    /**
     * The capacity of the {@code byte[]} cache, if it is enabled.
     */
    private final static int CACHE_CAPACITY = 100;

    /**
     * ScheduledExecutorService to implement delay during throttling in
     * <tt>AsyncPacketReader</tt>
     */
    private final static ScheduledExecutorService timer
        = Executors.newSingleThreadScheduledExecutor();

    /**
     * The default <tt>ExecutorService</tt> to run <tt>AsyncPacketReader</tt>
     * when there is no user provided executor.
     */
    private final static ExecutorService sharedExecutor
        = Executors.newWorkStealingPool();

    /**
     * Maximum number of packets processed in row before temporary stop
     * reader execution to give possible other users of same {@link #executor}
     * to proceed their execution. This mode of execution, when task is
     * temporary stopped itself to give a chance to other tasks sharing same
     * executor to run is called cooperative multi-tasking.
     */
    private final static int MAX_HANDLED_PACKETS_BEFORE_YIELD = 50;

    /**
     * Returns true if a warning should be logged after a queue has dropped
     * {@code numDroppedPackets} packets.
     * @param numDroppedPackets the number of dropped packets.
     * @return {@code true} if a warning should be logged.
     */
    public static boolean logDroppedPacket(int numDroppedPackets)
    {
        return
            numDroppedPackets == 1 ||
                (numDroppedPackets <= 1000 && numDroppedPackets % 100 == 0) ||
                numDroppedPackets % 1000 == 0;
    }

    /**
     * Executor service to run <tt>AsyncPacketReader</tt>, which asynchronously
     * invokes specified {@link #handler} on queued packets.
     */
    private final ExecutorService executor;

    /**
     * The underlying {@link Queue} which holds packets.
     */
    private final Queue<T> queue;

    /**
     * Whether this {@link PacketQueue} should store the {@code byte[]} or
     * {@code T} instances added to it via one of the {@code add} methods (if
     * {@code false}), or create and store a copy (if {@code true}).
     */
    private final boolean copy;

    /**
     * The capacity of this {@link PacketQueue}. If one of the {@code add}
     * methods is called while the queue holds this many packets, the first
     * packet in the queue will be dropped.
     */
    private final int capacity;

    /**
     * The {@link QueueStatistics} instance optionally used to collect and print
     * detailed statistics about this queue.
     */
    private final QueueStatistics queueStatistics;

    /**
     * The optionally used {@link AsyncPacketReader} to perpetually read packets
     * from {@link #queue} on separate thread and handle them
     * using {@link #handler}.
     */
    private final AsyncPacketReader reader;

    /**
     * The {@link org.ice4j.util.PacketQueue.PacketHandler} optionally used to
     * handle packets read from this queue by {@link #reader}.
     */
    private final PacketHandler<T> handler;

    /**
     * A string used to identify this {@link PacketQueue} for logging purposes.
     */
    private final String id;

    /**
     * Whether this queue has been closed.
     */
    private final AtomicBoolean closed = new AtomicBoolean(false);

    /**
     * The number of packets which were dropped from this {@link PacketQueue} as
     * a result of a packet being added while the queue is at full capacity.
     */
    private int numDroppedPackets = 0;

    /**
     * Initializes a new {@link PacketQueue} instance.
     */
    public PacketQueue()
    {
        this(false, "PacketQueue", null);
    }

    /**
     * Initializes a new {@link PacketQueue} instance.
     * @param enableStatistics whether detailed statistics should be calculated
     * and printed. WARNING: this will produce copious output (one line per
     * packet added or removed).
     * @param id the ID of the packet queue, to be used for logging.
     * @param packetHandler An optional handler to be used by the queue for
     * packets read from it. If a non-null value is passed the queue will
     * start its own thread, which will read packets from the queue and execute
     * {@code handler.handlePacket} on them. If set to null, no thread will be
     * created, and the queue will provide access to the head element via
     * {@link #get()} and {@link #poll()}.
     */
    public PacketQueue(
        boolean enableStatistics, String id, PacketHandler<T> packetHandler)
    {
        this(DEFAULT_CAPACITY, true, enableStatistics, id, packetHandler);
    }

    /**
     * Initializes a new {@link PacketQueue} instance.
     * @param capacity the capacity of the queue.
     * @param copy whether the queue is to store the instances it is given via
     * the various {@code add} methods, or create a copy.
     * @param enableStatistics whether detailed statistics should be calculated
     * and printed. WARNING: this will produce copious output (one line per
     * packet added or removed).
     * @param id the ID of the packet queue, to be used for logging.
     * @param packetHandler An optional handler to be used by the queue for
     * packets read from it. If a non-null value is passed the queue will
     * start its own thread, which will read packets from the queue and execute
     * {@code handler.handlePacket} on them. If set to null, no thread will be
     * created, and the queue will provide access to the head element via
     * {@link #get()} and {@link #poll()}.
     */
    public PacketQueue(int capacity, boolean copy,
                       boolean enableStatistics, String id,
                       PacketHandler<T> packetHandler)
    {
        this(capacity, copy, enableStatistics, id, packetHandler, null);
    }

    /**
     * Initializes a new {@link PacketQueue} instance.
     * @param capacity the capacity of the queue.
     * @param copy whether the queue is to store the instances it is given via
     * the various {@code add} methods, or create a copy.
     * @param enableStatistics whether detailed statistics should be calculated
     * and printed. WARNING: this will produce copious output (one line per
     * packet added or removed).
     * @param id the ID of the packet queue, to be used for logging.
     * @param packetHandler An optional handler to be used by the queue for
     * packets read from it. If a non-null value is passed the queue will
     * start its own thread, which will read packets from the queue and execute
     * {@code handler.handlePacket} on them. If set to null, no thread will be
     * created, and the queue will provide access to the head element via
     * {@link #get()} and {@link #poll()}.
     * @param executor An optional executor service to use to execute
     * packetHandler for items added to queue. If no explicit executor specified
     * then default {@link #sharedExecutor} will be used.
     */
    public PacketQueue(
        int capacity,
        boolean copy,
        boolean enableStatistics,
        String id,
        PacketHandler<T> packetHandler,
        ExecutorService executor)
    {
        this.copy = copy;
        this.capacity = capacity;
        this.id = id;
        queue = new ArrayBlockingQueue<>(capacity);

        queueStatistics
            = enableStatistics ? new QueueStatistics(id) : null;

        this.executor = executor != null ? executor : sharedExecutor;

        if (packetHandler != null)
        {
            handler = packetHandler;
            reader = new AsyncPacketReader();
        }
        else
        {
            reader = null;
            handler = null;
        }

        logger.fine("Initialized a PacketQueue instance with ID " + id);
    }

    /**
     * Adds a packet represented by a {@code byte[]} with a corresponding
     * offset and length to this queue.
     * @param buf the {@code byte[]} to add.
     * @param off the offset into {@code byte[]} where data begins.
     * @param len the length of the data.
     */
    public void add(byte[] buf, int off, int len)
    {
        add(buf, off, len, null);
    }

    /**
     * Adds a packet represented by a {@code byte[]} with a corresponding
     * offset and length, and a context object to this queue.
     * @param buf the {@code byte[]} to add.
     * @param off the offset into {@code byte[]} where data begins.
     * @param len the length of the data.
     * @param context an object which will be added to the queue as part of the
     * packet.
     */
    public void add(byte[] buf, int off, int len, Object context)
    {
        if (copy)
        {
            byte[] newBuf = getByteArray(len);
            System.arraycopy(buf, off, newBuf, 0, len);
            doAdd(createPacket(newBuf, 0, len, context));
        }
        else
        {
            doAdd(createPacket(buf, off, len, context));
        }
    }

    /**
     * Adds a specific packet ({@code T}) instance to the queue.
     * @param pkt the packet to add.
     */
    public void add(T pkt)
    {
        if (copy)
        {
            // create a new instance
            add(getBuffer(pkt), getOffset(pkt), getLength(pkt), getContext(pkt));
        }
        else
        {
            doAdd(pkt);
        }
    }

    /**
     * Get an unused {@link byte[]} instance with length at least {@code len}.
     * @param len the minimum length of the returned instance.
     * @return a {@link byte[]} instance with length at least {@code len}.
     */
    private byte[] getByteArray(int len)
    {
        return new byte[len];
    }

    /**
     * Adds a specific packet ({@code T}) instance to the queue.
     * @param pkt the packet to add.
     */
    private void doAdd(T pkt)
    {
        if (closed.get())
            return;

        synchronized (queue)
        {
            while (queue.size() >= capacity)
            {
                // Drop from the head of the queue.
                T p = queue.poll();
                if (p != null)
                {
                    if (queueStatistics != null)
                    {
                        queueStatistics.remove(System.currentTimeMillis());
                    }
                    if (logDroppedPacket(++numDroppedPackets))
                    {
                        logger.warning(
                            "Packets dropped (id=" + id + "): " + numDroppedPackets);
                    }
                }
            }

            if (queueStatistics != null)
            {
                queueStatistics.add(System.currentTimeMillis());
            }
            queue.offer(pkt);

            if (reader != null)
            {
                reader.schedule();
            }
        }
    }

    /**
     * Removes and returns the packet ({@code T}) at the head of this queue.
     * Blocks until there is a packet in the queue. Returns {@code null} if
     * the queue is closed or gets closed while waiting for a packet to be added.
     * @return the packet at the head of this queue.
     */
    public T get()
    {
        if (handler != null)
        {
            // If the queue was configured with a handler, it is running its
            // own reading thread, and reading from it via this interface would
            // not provide consistent results.
            throw new IllegalStateException(
                "Trying to read from a queue with a configured handler.");
        }

        while (true)
        {
            if (closed.get())
                return null;
            synchronized (queue)
            {
                T pkt = queue.poll();
                if (pkt != null)
                {
                    if (queueStatistics != null)
                    {
                        queueStatistics.remove(System.currentTimeMillis());
                    }
                    return pkt;
                }

                try
                {
                    queue.wait();
                }
                catch (InterruptedException ie)
                {}
            }
        }
    }

    /**
     * Removes and returns the packet ({@code T}) at the head of this queue, if
     * the queue is non-empty. If the queue is closed or empty, returns null
     * without blocking.
     * @return the packet at the head of this queue, or null if the queue is
     * empty.
     */
    public T poll()
    {
        if (closed.get())
            return null;

        if (handler != null)
        {
            // If the queue was configured with a handler, it is running its
            // own reading thread, and reading from it via this interface would
            // not provide consistent results.
            throw new IllegalStateException(
                "Trying to read from a queue with a configured handler.");
        }

        synchronized (queue)
        {
            T pkt = queue.poll();
            if (pkt != null && queueStatistics != null)
            {
                queueStatistics.remove(System.currentTimeMillis());
            }

            return pkt;
        }
    }

    public void close()
    {
        if (closed.compareAndSet(false, true))
        {
            if (reader != null)
            {
                reader.cancel();
            }
        }
    }

    /**
     * Extracts the underlying {@code byte[]} from a packet.
     * @param pkt the packet to get the {@code byte[]} from.
     * @return the underlying {@code byte[]} of {@code pkt}.
     */
    public abstract byte[] getBuffer(T pkt);

    /**
     * Extracts the offset of a packet.
     * @param pkt the packet to get the offset of.
     * @return the offset of {@code pkt}.
     */
    public abstract int getOffset(T pkt);

    /**
     * Extracts the length of a packet.
     * @param pkt the packet to get the length of.
     * @return the length of {@code pkt}.
     */
    public abstract int getLength(T pkt);

    /**
     * Extracts the context of a packet.
     * @param pkt the packet to get the context of.
     * @return the context of {@code pkt}.
     */
    public abstract Object getContext(T pkt);

    /**
     * Creates a new packet ({@link T} instance) with the given {@code byte[]},
     * offset, length and context.
     * @param buf the {@code byte[]} of the new instance.
     * @param off the offset of the new instance.
     * @param len the length of the new instance.
     * @param context the context of the new instance.
     * @return a new packet ({@link T} instance).
     */
    protected abstract T createPacket(
        byte[] buf, int off, int len, Object context);

    /**
     * Releases packet when it is handled by provided {@link #handler}.
     * This method is not called when <tt>PacketQueue</tt> was created without
     * {@link #handler} and hence no automatic queue processing is done.
     * Default implementation is empty, but it might be used to impalement
     * packet pooling to re-use them.
     * @param pkt packet to release
     */
    protected void releasePacket(T pkt)
    {
    }

    /**
     * A simple interface to handle packets.
     * @param <T> the type of the packets.
     */
    public interface PacketHandler<T>
    {
        /**
         * Does something with a packet.
         * @param pkt the packet to do something with.
         * @return {@code true} if the operation was successful, and
         * {@code false} otherwise.
         */
        boolean handlePacket(T pkt);

        /**
         * Specifies max number {@link #handlePacket(Object)} invocation
         * per {@link #perNanos()}
         * @return positive number of allowed pages in case of throttling
         * must be enabled.
         */
        default long maxPackets() {
            return -1;
        }

        /**
         * Specifies time interval in nanoseconds
         * @return positive nanoseconds count in case of throttling must be
         * enabled.
         */
        default long perNanos() {
            return -1;
        }
    }

    /**
     * Helper class to calculate throttle delay when throttling must be enabled
     */
    private class ThrottleCalculator
    {
        /**
         * The number of {@link T}s already processed during the current
         * <tt>perNanos</tt> interval.
         */
        private long packetsHandledWithinInterval = 0;

        /**
         * The time stamp in nanoseconds of the start of the current
         * <tt>perNanos</tt> interval.
         */
        private long intervalStartTimeNanos = 0;

        /**
         * Calculate necessary delay based current time and number packets
         * processed processed during current time interval
         * @return 0 in case delay is not necessary or value in nanos
         */
        long getDelayNanos()
        {
            if (handler == null)
            {
                return Long.MAX_VALUE;
            }

            final long perNanos = handler.perNanos();
            final long maxPackets = handler.maxPackets();

            if (perNanos > 0 && maxPackets > 0)
            {
                final long now = System.nanoTime();
                final long nanosRemainingTime = now - intervalStartTimeNanos;

                if (nanosRemainingTime >= perNanos)
                {
                    intervalStartTimeNanos = now;
                    packetsHandledWithinInterval = 0;
                }
                else if (packetsHandledWithinInterval >= maxPackets)
                {
                    return nanosRemainingTime;
                }
            }
            return 0;
        }

        /**
         * Count number of processed packets
         */
        void onPacketProcessed()
        {
            packetsHandledWithinInterval++;
        }
    }

    /**
     * Asynchronously reads packets from {@link #queue} on separate thread.
     * Thread is not blocked when queue is empty and returned back to
     * {@link #executor} pool. New or existing thread is borrowed from
     * {@link #executor} when queue is non empty and {@link #reader} is not
     * running
     */
    private final class AsyncPacketReader
    {
        /**
         * Throttle calculator which is used for counting handled packets and
         * computing necessary delay before processing next packet when
         * throttling is enabled.
         */
        private final ThrottleCalculator throttler = new ThrottleCalculator();

        /**
         * Stores <tt>Future</tt> of currently executing {@link #reader}
         */
        private Future<?> readerFuture;

        /**
         * Perpetually reads packets from this {@link PacketQueue} and uses
         * {@link #handler} on each of them.
         */
        private final Runnable reader = new Runnable()
        {
            @Override
            public void run()
            {
                int handledPackets = 0;

                while (!closed.get())
                {
                    T pkt;

                    synchronized (queue)
                    {
                        /* All instances of AsyncPacketReader executed on single
                           shared instance of ExecutorService to better use
                           existing threads and to reduce number of idle
                           threads when reader's queue is empty.

                           Having limited number of threads to execute might
                           lead to other problem, when queue is always non-empty
                           reader will keep running, while other readers might
                           suffer from execution starvation. One way to solve
                           this, is to to artificially interrupt current reader
                           execution and pump it via internal executor's queue.
                         */

                        long delay = throttler.getDelayNanos();
                        if (delay > 0)
                        {
                            onDelay(delay, TimeUnit.NANOSECONDS);
                            return;
                        }

                        if (handledPackets > MAX_HANDLED_PACKETS_BEFORE_YIELD)
                        {
                            onYield();
                            return;
                        }

                        pkt = queue.poll();

                        if (pkt == null)
                        {
                            stop(false);
                            return;
                        }
                        handledPackets++;
                        throttler.onPacketProcessed();
                    }

                    if (queueStatistics != null)
                    {
                        queueStatistics.remove(System.currentTimeMillis());
                    }

                    try
                    {
                        handler.handlePacket(pkt);
                    }
                    catch (Exception e)
                    {
                        logger.warning("Failed to handle packet: " + e);
                    }
                    finally
                    {
                        releasePacket(pkt);
                    }
                }
            }
        };

        /**
         * Stores <tt>ScheduledFuture</tt> of currently delayed
         * execution {@link #reader}
         */
        private ScheduledFuture<?> delayedFuture;

        /**
         * Runnable which is scheduled with delay to perform actual schedule of
         * {@link #reader}
         */
        private final Runnable delayedSchedule = new Runnable()
        {
            @Override
            public void run()
            {
                synchronized (queue)
                {
                    delayedFuture = null;
                }
                schedule();
            }
        };

        /**
         * Cancels execution of {@link #reader} if running
         */
        void cancel()
        {
            synchronized (queue)
            {
                stop(true);
            }
        }

        /**
         * Checks if {@link #reader} is running on one of {@link #executor}
         * thread and if no submits execution of {@link #reader} on executor.
         */
        void schedule()
        {
            if (closed.get())
            {
                return;
            }

            if (handler == null)
            {
                logger.warning("No handler set, the reading will not start.");
                return;
            }

            synchronized (queue)
            {
                if ((readerFuture == null || readerFuture.isDone())
                    && delayedFuture == null)
                {
                    readerFuture = executor.submit(reader);
                }
            }
        }

        /**
         * Invoked when execution of {@link #reader} is about to temporary
         * stop and further execution need to be re-scheduled
         */
        private void onYield()
        {
            logger.fine("Yielding AsyncPacketReader associated with "
                + "PacketQueue with ID = " + id);
            stop(false);
            schedule();
        }

        /**
         * Invoked when next execution of {@link #reader} should be delayed
         * @param delay the time from now to delay execution
         * @param unit the time unit of the delay parameter
         */
        private void onDelay(long delay, TimeUnit unit)
        {
            logger.fine("Delaying AsyncPacketReader associated with "
                + "PacketQueue with ID = " + id + " for "
                + unit.toNanos(delay) + "us");
            stop(false);
            delayedFuture = timer.schedule(delayedSchedule, delay, unit);
        }

        /**
         * Stop currently running reader. Assuming called when lock
         * on {@link #queue} is already taken
         * @param mayInterruptIfRunning indicates if {@link #reader} allowed
         * to be interrupted if running
         */
        private void stop(boolean mayInterruptIfRunning)
        {
            if (delayedFuture != null)
            {
                delayedFuture.cancel(mayInterruptIfRunning);
                delayedFuture = null;
            }

            if (readerFuture != null)
            {
                readerFuture.cancel(mayInterruptIfRunning);
                readerFuture = null;
            }
        }
    }
}
