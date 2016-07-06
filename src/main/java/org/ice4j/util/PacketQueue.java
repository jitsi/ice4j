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
     * The {@link Thread} optionally used to perpetually read packets from this
     * queue and handle them using {@link #handler}.
     */
    private final Thread thread;

    /**
     * The {@link org.ice4j.util.PacketQueue.PacketHandler} optionally used to
     * handle packets read from this queue by {@link #thread}.
     */
    private final PacketHandler<T> handler;

    /**
     * A string used to identify this {@link PacketQueue} for logging purposes.
     */
    private final String id;

    /**
     * Whether this queue has been closed.
     */
    private boolean closed = false;

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
        this.copy = copy;
        this.capacity = capacity;
        this.id = id;
        queue = new ArrayBlockingQueue<>(capacity);

        queueStatistics
            = enableStatistics ? new QueueStatistics(id) : null;

        if (packetHandler != null)
        {
            handler = packetHandler;

            thread = new Thread(){
                @Override
                public void run()
                {
                    runInReadingThread();
                }
            };
            thread.setName(getClass().getName() + "-" + id);
            thread.setDaemon(true);
            thread.start();
        }
        else
        {
            thread = null;
            handler = null;
        }

        logger.fine("Initialized a PacketQueue instance with ID " + id);
    }

    /**
     * Perpetually reads packets from this {@link PacketQueue} and uses
     * {@link #handler} on each of them.
     */
    private void runInReadingThread()
    {
        if (Thread.currentThread() != thread)
        {
            logger.warning("runInReadingThread executing in "
                               + Thread.currentThread());
            return;
        }

        if (handler == null)
        {
            logger.warning("No handler set, the reading thread will be stopped.");
            return;
        }

        while (!closed)
        {
            T pkt;

            synchronized (queue)
            {
                pkt = queue.poll();
                if (pkt == null)
                {
                    try
                    {
                        queue.wait(100);
                    }
                    catch (InterruptedException ie)
                    {
                    }
                    continue;
                }
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
        }
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
        if (closed)
            return;

        synchronized (queue)
        {
            if (queue.size() >= capacity)
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

            queue.notifyAll();
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
            if (closed)
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
        if (closed)
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
        if (!closed)
        {
            closed = true;

            synchronized (queue)
            {
                queue.notifyAll();
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
    }
}
