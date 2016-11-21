/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015-2016 Atlassian Pty Ltd
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

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

/**
 * A {@link DatagramSocket} implementation which merges a set of sockets.
 *
 * It maintains a thread reading from each of the underlying sockets. Thus
 * received datagrams are provided via the {@link #receive(DatagramPacket)}
 * API, in the order in which they were originally received (or close to it,
 * since the implementation is only based on timestamps).
 *
 * One of the underlying sockets is used as a delegate, and handles sending
 * via {@link #send(DatagramPacket)} and calls to
 * {@link #getLocalPort()}, {@link #getLocalAddress()} and
 * {@link #getLocalSocketAddress()}.
 *
 * Currently the delegate is just the first socket, but the intention is to
 * allow it to change dynamically.
 *
 * @author Boris Grozev
 */
public class MergingDatagramSocket
    extends DatagramSocket
{
    /**
     * The {@link Logger} used by the {@link MergingDatagramSocket} class and
     * its instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(MergingDatagramSocket.class.getName());

    /**
     * Used to control access to {@link #socketContainers}.
     */
    private final Object socketContainersSyncRoot = new Object();

    /**
     * Stores the underlying sockets. Copy on write.
     */
    private SocketContainer[] socketContainers = new SocketContainer[0];

    /**
     * Calls to {@link #receive(java.net.DatagramPacket)} will wait on this
     * object in case no packet is available for reading.
     */
    private final Object receiveLock = new Object();

    /**
     * If non-zero, {@link #receive(java.net.DatagramPacket)} will attempt to
     * return within this many milliseconds, and will throw a
     * {@link SocketTimeoutException} if no packet has been read.
     */
    private int soTimeout = 0;

    /**
     * The {@link SocketContainer} considered active, i.e. the one which should
     * be used for sending.
     */
    private SocketContainer active = null;

    /**
     * Initializes a new {@link MergingDatagramSocket} instance.
     * @throws SocketException
     */
    public MergingDatagramSocket()
            throws SocketException
    {}

    /**
     * {@inheritDoc}
     */
    @Override
    public void setSoTimeout(int soTimeout)
    {
        this.soTimeout = soTimeout;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getSoTimeout()
    {
        return soTimeout;
    }

    /**
     * {@inheritDoc}
     * <p/>
     * The current implementation delegates to the first container, but this is
     * subject to change.
     *
     * @param pkt the datagram to send.
     * @throws IOException
     */
    @Override
    public void send(DatagramPacket pkt)
        throws IOException
    {
        SocketContainer active = this.active;
        if (active != null)
        {
            active.send(pkt);
        }
        else
        {
            throw new IOException("No active socket.");
        }

    }

    /**
     * Adds a {@link DelegatingSocket} instance to this merging socket. Note
     * that this will start a thread reading from the added socket.
     * @param socket the socket to add.
     */
    public void add(DelegatingSocket socket)
    {
        Objects.requireNonNull(socket, "socket");
        if (logger.isLoggable(Level.FINE))
        {
            logger.fine("Adding a DelegatingSocket instance: "
                            + socket.getLocalAddress());
        }
        doAdd(socket);
    }

    /**
     * Adds a {@link DatagramSocket} instance to this merging socket. Note
     * that this will start a thread reading from the added socket.
     * @param socket the socket to add.
     */
    public void add(DatagramSocket socket)
    {
        Objects.requireNonNull(socket, "socket");
        if (logger.isLoggable(Level.FINE))
        {
            logger.fine("Adding a DatagramSocket instance: "
                            + socket.getLocalAddress());
        }
        doAdd(socket);
    }

    /**
     * Adds a socket (either a {@link DatagramSocket} or a
     * {@link DelegatingSocket}) to the list of underlying sockets merged by
     * this {@link MergingDatagramSocket}.
     * @param socket the socket to add.
     */
    private void doAdd(Object socket)
    {
        if (!(socket instanceof DelegatingSocket) &&
            !(socket instanceof DatagramSocket))
        {
            logger.severe("Unsupported class: "
                              + (socket == null ? "null" : socket.getClass()));
            return;
        }

        synchronized (socketContainersSyncRoot)
        {
            if (indexOf(socketContainers, socket) != -1)
            {
                logger.warning("Socket already added.");
                return;
            }

            SocketContainer socketContainer;
            if (socket instanceof DelegatingSocket)
            {
                socketContainer = new SocketContainer((DelegatingSocket) socket);
            }
            else
            {
                socketContainer = new SocketContainer((DatagramSocket) socket);
            }

            SocketContainer[] newSocketContainers
                = new SocketContainer[socketContainers.length + 1];
            System.arraycopy(socketContainers, 0,
                             newSocketContainers, 0,
                             socketContainers.length);
            newSocketContainers[socketContainers.length] = socketContainer;

            socketContainers = newSocketContainers;

            if (active == null)
                active = socketContainer;
        }
    }

    /**
     * Removes a specific {@link DatagramSocket} from the list of sockets
     * merged by this {@link MergingDatagramSocket}.
     * @param socket the {@link DatagramSocket} to remove.
     */
    public void remove(DatagramSocket socket)
    {
        doRemove(socket);
    }

    /**
     * Removes a specific {@link DelegatingSocket} from the list of sockets
     * merged by this {@link MergingDatagramSocket}.
     * @param socket the {@link DelegatingSocket} to remove.
     */
    public void remove(DelegatingSocket socket)
    {
        doRemove(socket);
    }

    /**
     * Removes a socket from the list of sockets merged by this
     * {@link MergingDatagramSocket}.
     * @param socket the socket to remove.
     */
    private void doRemove(Object socket)
    {
        SocketContainer socketContainer = null;

        synchronized (socketContainersSyncRoot)
        {
            int i = indexOf(socketContainers, socket);
            if (i > 0)
            {
                socketContainer = socketContainers[i];

                SocketContainer[] newSockets
                    = new SocketContainer[socketContainers.length - 1];
                if (i > 0)
                {
                    System.arraycopy(socketContainers, 0,
                                     newSockets, 0,
                                     i);
                }
                if (i < socketContainers.length - 1)
                {
                    System.arraycopy(socketContainers, i + 1,
                                     newSockets, i,
                                     socketContainers.length - i - 1);
                }

                socketContainers = newSockets;

                // Until we receive data on one of the other sockets, use the
                // first one as the active socket.
                if (socketContainer == active)
                {
                    active = newSockets.length == 0 ? null : newSockets[0];
                }
            }
            else
            {
                logger.severe("Cannot find socket to remove.");
            }
        }

        if (logger.isLoggable(Level.FINE))
        {
            logger.fine("Removed: " + socketContainer);
        }
        if (socketContainer != null)
        {
            // Stop the reading thread.
            // TODO: do we want to interrupt the thread here? This will not
            // help unless we set a soTimeout > 0
            socketContainer.closed = true;
        }
    }

    /**
     * Returns the index in {@link #socketContainers} of the
     * {@link SocketContainer} with socket equal to {@code socket}, or -1 if
     * such a {@link SocketContainer} doesn't exist.
     *
     * @param socket the {@link DatagramSocket} to get the index of.
     * @return the index in {@link #socketContainers} of the
     * {@link SocketContainer} with socket equal to {@code socket}, or -1 if
     * such a {@link SocketContainer} doesn't exist.
     */
    private int indexOf(SocketContainer[] socketContainers, Object socket)
    {
        for (int i = 0; i < socketContainers.length; i++)
        {
            if (socketContainers[i].datagramSocket == socket ||
                socketContainers[i].delegatingSocket == socket)
            {
                return i;
            }
        }
        return -1;
    }

    /**
     * TODO
     */
    private SocketContainer getActiveSocket()
    {
        //TODO switch dynamically.
        SocketContainer[] socketContainers = this.socketContainers;
        if (socketContainers != null && socketContainers.length > 0)
        {
            return socketContainers[0];
        }
        return null;
    }

    /**
     * {@inheritDoc}
     * </p>
     * Delegates to the "active" socket, if one exists. Else returns
     * {@code null}.
     */
    @Override
    public InetAddress getLocalAddress()
    {
        SocketContainer activeSocket = getActiveSocket();
        return activeSocket == null ? null : activeSocket.getLocalAddress();
    }

    /**
     * {@inheritDoc}
     * </p>
     * Delegates to the "active" socket, if one exists. Else returns
     * {@code 0}.
     * TODO: should we return 0 (unbound) or -1 (closed) if there are no
     * sockets?
     */
    @Override
    public int getLocalPort()
    {
        SocketContainer activeSocket = getActiveSocket();
        return activeSocket == null ? 0 : activeSocket.getLocalPort();
    }

    /**
     * {@inheritDoc}
     * </p>
     * Delegates to the "active" socket, if one exists. Else returns
     * {@code null}.
     */
    @Override
    public SocketAddress getLocalSocketAddress()
    {
        SocketContainer activeSocket = getActiveSocket();
        return
            activeSocket == null ? null : activeSocket.getLocalSocketAddress();
    }

    /**
     * {@inheritDoc}
     * </p>
     * Copies into {@code p} a packet already received from one of the
     * underlying sockets. The socket is chosen on the base of the timestamp
     * of the reception of the first packet in its queue (so that earlier
     * packets are received first).
     */
    @Override
    public void receive(DatagramPacket p)
            throws SocketTimeoutException
    {
        long start = System.currentTimeMillis();
        int soTimeout = this.soTimeout;

        // We need to hold the lock while checking for an available packet,
        // otherwise we might end up wait()-ing if a packet becomes available
        // after our check.
        // We keep the loop inside the lock, because this prevents us from
        // having to re-obtain the lock after wait() returns. All operations
        // inside the block are non-blocking, except for wait(), so we run no
        // risk of causing a deadlock by doing so.
        synchronized (receiveLock)
        {
            do
            {
                // Find the input socket with the oldest packet
                SocketContainer[] socketContainers = this.socketContainers;
                SocketContainer socketToReceiveFrom = null;
                long firstTime = -1;
                for (SocketContainer socketContainer : socketContainers)
                {
                    long f = socketContainer.getFirstReceivedTime();
                    if (f > 0)
                    {
                        if (firstTime == -1 || firstTime > f)
                        {
                            firstTime = f;
                            socketToReceiveFrom = socketContainer;
                        }
                    }
                }

                // If a packet is available read it
                if (socketToReceiveFrom != null)
                {
                    socketToReceiveFrom.receive(p);
                    return;
                }
                // Otherwise wait on receiveLock.
                else
                {
                    try
                    {
                        if (soTimeout > 0)
                        {
                            long remaining
                                = start + soTimeout
                                        - System.currentTimeMillis();
                            if (remaining <= 0)
                                throw new SocketTimeoutException();

                            receiveLock.wait(remaining);
                        }
                        else
                        {
                            receiveLock.wait();
                        }
                    }
                    catch (InterruptedException ie)
                    {
                        Thread.currentThread().interrupt();
                        // We haven't received a packet, but what else can we
                        // do?
                        return;
                    }
                }
            }
            while (true);
        }
    }

    /**
     * Contains one of the sockets which this {@link MergingDatagramSocket}
     * merges, and objects associated with the socket, including a thread
     * which loops reading from it.
     *
     * The socket is either a {@link DatagramSocket} or a
     * {@link DelegatingSocket} instance, stored in {@link #datagramSocket} or
     * {@link #delegatingSocket} respectively. Exactly one of these fields must
     * be null.
     */
    private class SocketContainer
    {
        /**
         * Either the socket represented by this instance, if it is a {@link
         * DatagramSocket} instance, or {@code null} if it is not.
         */
        private final DatagramSocket datagramSocket;

        /**
         * Either the socket represented by this instance, if it is a {@link
         * DelegatingSocket} instance, or {@code null}if it is not.
         */
        private final DelegatingSocket delegatingSocket;

        /**
         * The queue to which packets received from this instance's socket are
         * added.
         */
        private final ArrayBlockingQueue<Buffer> queue
            = new ArrayBlockingQueue<>(100);

        /**
         * A pool of unused {@link Buffer} instances.
         */
        private final ArrayBlockingQueue<Buffer> pool
            = new ArrayBlockingQueue<>(10);

        /**
         * A flag used to signal to {@link #thread} to finish.
         */
        private boolean closed = false;

        /**
         * The remote address of the last received packet.
         */
        private SocketAddress remoteAddress = null;

        /**
         * The thread which reads packets from this instance's socket and adds
         * them to {@link #queue}. If the queue is filled up, it will stop
         * receiving packets and will block waiting for the queue accept.
         */
        private Thread thread;

        /**
         * Initializes a {@link SocketContainer} instance using a {@link
         * DatagramSocket} as its socket.
         *
         * @param socket the socket.
         */
        SocketContainer(DelegatingSocket socket)
        {
            this.datagramSocket = null;
            this.delegatingSocket = Objects.requireNonNull(socket, "socket");
            init();
        }

        /**
         * Initializes a {@link SocketContainer} instance using a {@link
         * DatagramSocket} as its socket.
         *
         * @param socket the socket.
         */
        SocketContainer(DatagramSocket socket)
        {
            this.datagramSocket = Objects.requireNonNull(socket, "socket");
            this.delegatingSocket = null;
            init();
        }

        /**
         * Initializes and starts the thread of this instance.
         */
        private void init()
        {
            thread = new Thread()
            {
                @Override
                public void run()
                {
                    runInReaderThread();
                }
            };
            thread.setDaemon(true);
            thread.setName("MergingDatagramSocket reader thread for: "
                               + getLocalSocketAddress() + " -> "
                               + getRemoteSocketAddress());

            if (logger.isLoggable(Level.FINE))
            {
                logger.fine("Starting the thread for socket "
                                + getLocalSocketAddress() + " -> "
                                + getRemoteSocketAddress());
            }
            thread.start();
        }

        /**
         * @return an unused {@link Buffer} instance.
         */
        private Buffer getFreeBuffer()
        {
            Buffer buffer = pool.poll();
            if (buffer == null)
                buffer = new Buffer();
            buffer.reset();
            return buffer;
        }

        /**
         * Reads from the underlying socket and adds the read packets to {@link
         * #queue}. Blocks if {@link #queue} is full.
         */
        private void runInReaderThread()
        {
            while (true)
            {
                if (closed || Thread.currentThread().isInterrupted())
                    break;

                // Read from the underlying socket
                Buffer buffer = getFreeBuffer();
                try
                {
                    if (!doReceive(buffer))
                    {
                        continue;
                    }
                }
                catch (IOException ioe)
                {
                    logger.severe("Failed to receive: " + ioe);
                    break;
                }

                if (closed || Thread.currentThread().isInterrupted())
                    break;

                try
                {
                    queue.put(buffer);
                    synchronized (receiveLock)
                    {
                        receiveLock.notifyAll();
                    }
                }
                catch (InterruptedException ie)
                {
                    Thread.currentThread().interrupt();
                }
            }

            if (logger.isLoggable(Level.FINE))
            {
                logger.fine("Finished: " + toString());
            }
        }

        /**
         * Tries to receive a packet from the underlying socket into {@code
         * buffer}.
         *
         * @param buffer the buffer into which to receive.
         * @return {@code true} if the method succeeded, or {@code false} if the
         * thread was interrupted or this {@link SocketContainer} was closed.
         * @throws IOException if receiving failed due to an I/O error from the
         * underlying socket.
         */
        private boolean doReceive(Buffer buffer)
            throws IOException
        {
            while (true)
            {
                if (closed || Thread.currentThread().isInterrupted())
                    break;
                try
                {
                    if (datagramSocket != null)
                    {
                        datagramSocket.receive(buffer.pkt);
                    }
                    else
                    {
                        delegatingSocket.receive(buffer.pkt);
                    }

                    buffer.receivedTime = System.currentTimeMillis();
                    remoteAddress = buffer.pkt.getSocketAddress();

                    maybeUpdateActive();
                    return true;
                }
                catch (SocketTimeoutException ste)
                {
                    // Ignore timeouts and loop.
                }
            }

            return false;
        }

        /**
         * Makes this {@link SocketContainer} the active socket container for
         * this {@link MergingDatagramSocket}, if it isn't already the active
         * socket.
         */
        private void maybeUpdateActive()
        {
            SocketContainer active = MergingDatagramSocket.this.active;
            // Avoid obtaining the lock on every packet from the active socket.
            // There is no harm if the value is overwritten before we obtain
            // the lock.
            if (active != this)
            {
                synchronized (socketContainersSyncRoot)
                {
                    MergingDatagramSocket.this.active = this;
                    if (logger.isLoggable(Level.FINE))
                    {
                        logger.warning("Switching to new active socket: "
                                           + this);
                    }
                }
            }
        }

        /**
         * Copies a packet from this {@link SocketContainer}'s queue into
         * {@code p}. Does not block.
         *
         * @param p the {@link DatagramPacket} to receive into.
         */
        private void receive(DatagramPacket p)
        {
            Buffer buffer = queue.poll();
            if (buffer == null)
            {
                throw new IllegalStateException("Queue empty.");
            }

            byte[] dest = p.getData();
            int destOffset = p.getOffset();
            int len
                = Math.min(
                        dest.length - destOffset,
                        buffer.pkt.getLength());

            System.arraycopy(buffer.pkt.getData(), buffer.pkt.getOffset(),
                             dest, destOffset,
                             len);
            p.setLength(len);
            p.setSocketAddress(buffer.pkt.getSocketAddress());

            pool.offer(buffer);
        }

        /**
         * @return the time of reception of the first packet in the queue, or
         * {@code -1} if the queue is empty.
         */
        private long getFirstReceivedTime()
        {
            Buffer nextBuffer = queue.peek();
            if (nextBuffer != null)
            {
                return nextBuffer.receivedTime;
            }
            return -1;
        }

        /**
         * {@inheritDoc}
         * <p>
         * Delegates to the underlying socket (either {@link #datagramSocket} or
         * {@link #delegatingSocket}).
         */
        private InetAddress getLocalAddress()
        {
            return datagramSocket != null
                ? datagramSocket.getLocalAddress()
                : delegatingSocket.getLocalAddress();
        }

        /**
         * {@inheritDoc}
         * <p>
         * Delegates to the underlying socket (either {@link #datagramSocket} or
         * {@link #delegatingSocket}).
         */
        private int getLocalPort()
        {
            return datagramSocket != null
                ? datagramSocket.getLocalPort()
                : delegatingSocket.getLocalPort();
        }

        /**
         * {@inheritDoc}
         * <p>
         * Delegates to the underlying socket (either {@link #datagramSocket} or
         * {@link #delegatingSocket}).
         */
        public SocketAddress getLocalSocketAddress()
        {
            return datagramSocket != null
                ? datagramSocket.getLocalSocketAddress()
                : delegatingSocket.getLocalSocketAddress();

        }

        /**
         * Returns a {@link String} representation of this {@link
         * SocketContainer}.
         */
        public String toString()
        {
            if (datagramSocket != null)
            {
                return datagramSocket.getLocalSocketAddress()
                    + " -> " + remoteAddress;
            }
            else
            {
                return delegatingSocket.getLocalSocketAddress()
                    + " -> " + remoteAddress;
            }
        }

        /**
         * Sends a {@link DatagramPacket} through the underlying socket (either
         * {@link #datagramSocket} or {@link #delegatingSocket}).
         *
         * @param pkt the packet to send.
         */
        private void send(DatagramPacket pkt)
            throws IOException
        {
            if (datagramSocket != null)
            {
                datagramSocket.send(pkt);
            }
            else
            {
                delegatingSocket.send(pkt);
            }
        }

        /**
         * Represents a {@link DatagramPacket} for the purposes of {@link
         * SocketContainer}.
         */
        private class Buffer
        {
            /**
             * The size of the buffer to allocate.
             */
            private static final int MAX_PACKET_SIZE = 1500;

            /**
             * The time at which this buffer was filled.
             */
            long receivedTime = -1;

            /**
             * The {@link DatagramPacket} wrapped by this {@link Buffer}.
             */
            DatagramPacket pkt
                = new DatagramPacket(
                new byte[MAX_PACKET_SIZE],
                0,
                MAX_PACKET_SIZE);

            /**
             * Prepares this {@link Buffer} for reuse.
             */
            private void reset()
            {
                receivedTime = -1;

                // We are going to receive from a socket into this packet. If
                // the length is insufficient it is going to truncate the data.
                // So reset it to what we know is the underlying byte[]'s
                // length.
                pkt.setLength(MAX_PACKET_SIZE);
            }
        }
    }
}
