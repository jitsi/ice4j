/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
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
package org.ice4j.socket;

import java.net.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * Implements a buffer of <tt>DatagramPacket</tt>s received by a
 * <tt>DatagramSocket</tt> or a <tt>Socket</tt>. The list enforces the
 * <tt>SO_RCVBUF</tt> option for the associated <tt>DatagramSocket</tt> or
 * <tt>Socket</tt>.
 *
 * @author Lyubomir Marinov
 * @author Yura Yaroshevich
 */
class SocketReceiveBuffer
{
    /**
     * Default size in bytes of socket receive buffer.
     */
    private static final int DEFAULT_RECEIVE_BUFFER_SIZE = 1024 * 1024;

    /**
     * Maxumum number of datagrams buffer is capable to store regardless
     * of total datagram size in bytes.
     */
    private static final int DATAGRAMS_BUFFER_CAPACITY = 10000;

    /**
     * Queue to store received datagrams.
     */
    private final BlockingQueue<DatagramPacket> buffer
        = new ArrayBlockingQueue<>(DATAGRAMS_BUFFER_CAPACITY);

    /**
     * An instance of datagram size tracker to compute total number of bytes
     * stored in datagrams witin {@link #buffer}.
     */
    private final DatagramSizeTracker tracker;

    /**
     * Constructs {@link SocketReceiveBuffer} with user-provided
     * @param receiveBufferSizeSupplier a function to obtain receive buffer
     * size from associated socket.
     */
    public SocketReceiveBuffer(Callable<Integer> receiveBufferSizeSupplier)
    {
        this.tracker = new DatagramSizeTracker(receiveBufferSizeSupplier);
    }

    /**
     * Check if receive buffer is empty
     * @return true if buffer is empty, false - otherwise.
     */
    public boolean isEmpty()
    {
        return buffer.isEmpty();
    }

    /**
     * Adds {@link DatagramPacket} at the end of the socket receive buffer.
     * @param p datagram to add into receive buffer
     */
    public void add(DatagramPacket p)
    {
        while (!buffer.offer(p))
        {
            // ensure buffer capacity restriction enforced
            poll();
        }

        tracker.trackDatagramAdded(p);

        while (tracker.isExceedReceiveBufferSize() && buffer.size() > 1)
        {
            // enforce SO_RCVBUF restriction
            poll();
        }
    }

    /**
     * Polls socket receive buffer for already stored {@link DatagramPacket}
     * @return the first datagram in the buffer, or {@code null} if buffer
     * is empty.
     */
    public DatagramPacket poll()
    {
        DatagramPacket p = buffer.poll();

        // Keep track of the (total) size in bytes of this receive buffer in
        // order to be able to enforce SO_RCVBUF restriction.
        if (p != null)
        {
            tracker.trackDatagramRemoved(p);
        }

        return p;
    }

    /**
     * Scans buffer of received {@link DatagramPacket}s and move
     * datagrams which matches the {@code filter} into returned list.
     * @param filter a predicate to filter {@link DatagramPacket} stored
     * in receive buffer.
     * @return list of datagrams matched to {@code filter}.
     */
    public List<DatagramPacket> scan(DatagramPacketFilter filter)
    {
        List<DatagramPacket> matchedDatagrams = null;
        final Iterator<DatagramPacket> it = buffer.iterator();

        while (it.hasNext())
        {
            final DatagramPacket p = it.next();

            if (filter.accept(p))
            {
                if (matchedDatagrams == null)
                {
                    matchedDatagrams = new ArrayList<>();
                }
                matchedDatagrams.add(p);

                it.remove();

                tracker.trackDatagramRemoved(p);
            }
        }

        if (matchedDatagrams != null)
        {
            return matchedDatagrams;
        }
        return Collections.emptyList();
    }

    /**
     * A helper class to keep track of total size in bytes of all
     * {@link DatagramPacket} instances stored in {@link #buffer} to
     * be able to enforce SO_RCVBUF.
     */
    private final class DatagramSizeTracker
    {
        /**
         * The value of the <tt>SO_RCVBUF</tt> option for the associated
         * <tt>DatagramSocket</tt> or <tt>Socket</tt>. Cached for the sake of
         * performance.
         */
        private int cachedReceiveBufferSize;

        /**
         * The (total) size in bytes of this receive buffer.
         */
        private int totalBuffersByteSize;

        /**
         * Counts total number of datagrams added to buffer.
         */
        private int totalDatagramsAdded;

        /**
         * A user provided getter of receive buffer size, might
         * fail with {@link Exception} when called.
         */
        private final Callable<Integer> receiveBufferSizeSupplier;

        /**
         * Create a tracker of datagram packet size stored in buffer.
         * @param receiveBufferSizeSupplier a function to obtain receive buffer
         * size from associated socket.
         */
        public DatagramSizeTracker(
            Callable<Integer> receiveBufferSizeSupplier)
        {
            this.receiveBufferSizeSupplier = receiveBufferSizeSupplier;
        }

        /**
         * Check if total bytes stored in {@link #buffer} exceeds socket's
         * receive buffer size.
         * @return true if size exceeded, false - otherwise
         */
        boolean isExceedReceiveBufferSize()
        {
            return totalBuffersByteSize > cachedReceiveBufferSize;
        }

        /**
         * Updates computed value of total datagrams size in bytes
         * stored in {@link #buffer} with datagram just added to buffer.
         * @param p datagram packed added to {@link #buffer}
         */
        void trackDatagramAdded(DatagramPacket p)
        {
            ++totalDatagramsAdded;

            final int pSize = p.getLength();
            if (pSize <= 0)
            {
                return;
            }

            totalBuffersByteSize += pSize;

            // If the added packet is the only element of this list, do not
            // drop it because of the enforcement of SO_RCVBUF.
            if (buffer.size() > 1)
            {
                // For the sake of performance, do not invoke the method
                // getReceiveBufferSize() of DatagramSocket or Socket on
                // every packet added to this buffer.
                int receiveBufferSize = this.cachedReceiveBufferSize;

                if ((receiveBufferSize <= 0)
                    || (totalDatagramsAdded % 1000 == 0))
                {
                    try
                    {
                        receiveBufferSize
                            = this.receiveBufferSizeSupplier.call();
                    }
                    catch (Exception e)
                    {
                        // nothing to do
                    }

                    if (receiveBufferSize <= 0)
                    {
                        receiveBufferSize = DEFAULT_RECEIVE_BUFFER_SIZE;
                    }
                    else if (receiveBufferSize
                        < DEFAULT_RECEIVE_BUFFER_SIZE)
                    {
                        // Well, a manual page on SO_RCVBUF talks about
                        // doubling. In order to stay on the safe side and
                        // given that there was no limit on the size of the
                        // buffer before, double the receive buffer size.
                        receiveBufferSize *= 2;
                        if (receiveBufferSize <= 0)
                        {
                            receiveBufferSize
                                = DEFAULT_RECEIVE_BUFFER_SIZE;
                        }
                    }
                    this.cachedReceiveBufferSize = receiveBufferSize;
                }
            }
        }

        /**
         * Updates computed value of total datagrams size in bytes
         * stored in {@link #buffer} with datagram just removed from buffer.
         * @param p datagram packed removed from {@link #buffer}
         */
        void trackDatagramRemoved(DatagramPacket p)
        {
            final int pSize = p.getLength();
            if (pSize <= 0)
            {
                return;
            }

            totalBuffersByteSize -= pSize;
            if (totalBuffersByteSize < 0)
            {
                totalBuffersByteSize = 0;
            }
        }
    }
}
