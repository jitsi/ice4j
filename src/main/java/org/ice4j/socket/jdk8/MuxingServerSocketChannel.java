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
package org.ice4j.socket.jdk8;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.*;
import org.ice4j.ice.harvest.*;
import org.ice4j.socket.*;

/**
 * Shares a listening endpoint (i.e. an open and bound
 * {@link ServerSocketChannel}) among multiple {@code MuxServerSocketChannel}s.
 * Accepted {@link SocketChannel}s are demultiplexed based on
 * {@link DatagramPacketFilter}s and dispatched for acceptance through matching
 * {@code MuxServerSocketChannel}s.
 *
 * @author Lyubomir Marinov
 */
class MuxingServerSocketChannel
    extends DelegatingServerSocketChannel<ServerSocketChannel>
{
    /**
     * Reference to 0.0.0.0 IPv4 or 0::0 IPv6 address for "wildcard" matching
     * purposes.
     */
    private static final InetAddress ANY_LOCAL_ADDRESS;

    /**
     * The {@code Selector} which waits for incoming network connections on all
     * {@link #muxingServerSocketChannels}.
     */
    private static Selector acceptSelector;

    /**
     * The {@code Thread} which waits for and accepts incoming network
     * connections on all {@link #muxingServerSocketChannels}.
     */
    private static Thread acceptThread;

    /**
     * The (global) list of existing <tt>MixingServerSocketChannel</tt>s.
     */
    private static final List<MuxingServerSocketChannel>
        muxingServerSocketChannels
            = new LinkedList<>();

    /**
     * The maximum number of milliseconds to wait for an accepted
     * {@code SocketChannel} to provide incoming/readable data before it is
     * considered abandoned by the client.
     */
    private static final int SOCKET_CHANNEL_READ_TIMEOUT
        = MuxServerSocketChannelFactory.SOCKET_CHANNEL_READ_TIMEOUT;

    /**
     * The maximum number of {@code byte}s to be read from
     * {@link SocketChannel}s accepted by {@link MuxingServerSocketChannel}s in
     * order to demultiplex (i.e. filter) them into
     * {@code MuxServerSocketChannel}s.
     */
    private static final int SOCKET_CHANNEL_READ_CAPACITY
        = Math.max(
                GoogleTurnSSLCandidateHarvester.SSL_CLIENT_HANDSHAKE.length,
                Math.max(
                        HttpDemuxFilter.REQUEST_METHOD_MAX_LENGTH + 1 /* SP */,
                        HttpDemuxFilter.TLS_MIN_LENGTH));

    static
    {
        try
        {
            ANY_LOCAL_ADDRESS = InetAddress.getByName("::");
        }
        catch (UnknownHostException e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * Adds a specific {@code MuxingServerSocketChannel} to the (global) list of
     * existing {@code MuxingServerSocketChannel}s and schedules acceptance of
     * incoming network connections on it.
     *
     * @param channel the {@code MuxingServerSocketChannel} to add to the
     * (global) list of existing {@code MuxingServerSocketChannel}s and to
     * schedule for acceptance of incoming network connections
     * @throws IOException if an I/O error occurs
     */
    private static void addMuxingServerSocketChannel(
            MuxingServerSocketChannel channel)
        throws IOException
    {
        synchronized (muxingServerSocketChannels)
        {
            muxingServerSocketChannels.add(channel);
            muxingServerSocketChannels.notifyAll();

            scheduleAccept(channel);
        }
    }

    /**
     * Closes a {@code Channel} and swallows any {@link IOException}.
     *
     * @param channel the {@code Channel} to close
     */
    public static void closeNoExceptions(Channel channel)
    {
        MuxServerSocketChannelFactory.closeNoExceptions(channel);
    }

    /**
     * Finds the first open {@code MuxingServerSocketChannel} in the (global)
     * list of existing {@code MuxingServerSocketChannel}s which is bound to a
     * specific local {@link SocketAddress}.
     *
     * @param localAddr the local {@code SocketAddress} on which the bound
     * {@code MuxingServerSocketChannel} is to be found
     * @return the first open {@code MuxingServerSocketChannel} in the (global)
     * list of existing {@code MuxingServerSocketChannel}s which is bound to the
     * specified {@code localAddr} or {@code null}
     */
    private static MuxingServerSocketChannel findMuxingServerSocketChannel(
            SocketAddress localAddr)
    {
        MuxingServerSocketChannel channel = null;

        synchronized (muxingServerSocketChannels)
        {
            Iterator<MuxingServerSocketChannel> i
                = muxingServerSocketChannels.iterator();

            while (i.hasNext())
            {
                MuxingServerSocketChannel aChannel = i.next();

                if (aChannel.isOpen())
                {
                    SocketAddress aLocalAddr;

                    try
                    {
                        aLocalAddr = aChannel.getLocalAddress();
                    }
                    catch (ClosedChannelException cce)
                    {
                        i.remove();
                        aLocalAddr = null;
                    }
                    catch (IOException ioe)
                    {
                        aLocalAddr = null;
                    }

                    boolean matches
                        = aLocalAddr != null && aLocalAddr.equals(localAddr);

                    // If not the same address, let's see if the cached one is
                    // an "anyLocalAddress" and if so let's consider it a match.
                    if (!matches
                            && aLocalAddr instanceof InetSocketAddress
                            && localAddr instanceof InetSocketAddress)
                    {
                        InetSocketAddress aLocalInetAddr
                            = (InetSocketAddress) aLocalAddr;
                        InetSocketAddress localInetAddr
                            = (InetSocketAddress) localAddr;

                        matches
                            = aLocalInetAddr.getAddress()
                                    .equals(ANY_LOCAL_ADDRESS)
                                && aLocalInetAddr.getPort()
                                    == localInetAddr.getPort();
                    }

                    if (matches)
                    {
                        channel = aChannel;
                        // The whole idea of using (1) a List for
                        // muxingServerSocketChannels instead of a Map and (2)
                        // an Iterator to loop over muxingServerSocketChannels
                        // is to aggressively clean up. Anyway, break as soon as
                        // possible in order to improve the execution speed and
                        // because there is an attempt to clean
                        // muxingServerSocketChannels up upon closing.
                        break;
                    }
                }
                else
                {
                    i.remove();
                }
            }
        }
        return channel;
    }

    /**
     * If {@link #acceptSelector} exists and is open, try to close it and do not
     * throw an <tt>IOException</tt>.
     */
    private static void maybeCloseAcceptSelector()
    {
        if (acceptSelector != null)
        {
            if (acceptSelector.isOpen())
            {
                try
                {
                    acceptSelector.close();
                }
                catch (IOException ioe)
                {
                    // I don't know what to do about any IOException during
                    // Selector#close() even if I log it.
                }
            }
            acceptSelector = null;
        }
    }

    /**
     * Opens and binds a new {@code MuxServerSocketChannel} instance. If there
     * are other (existing) {@code MuxServerSocketChannel} open and bound on the
     * specified listening {@code endpoint}, the new instance will share it with
     * them.
     *
     * @param properties a {@code Map} of the values to be assigned to
     * properties of the underlying {@link ServerSocketChannel} which is to
     * actually listen on the specified {@code endpoint}. If the new instance is
     * not the first to open and bind the specified {@code endpoint}, the
     * {@code properties} and their respective values may not be used.
     * @param endpoint the IP and port the new instance is to bind to
     * @param backlog the requested maximum number of pending incoming
     * connections to be queued. If the new instance is not the first to open
     * and bind the specified {@code endpoint}, the value may not be used.
     * @param filter the {@code DatagramPacketFilter} to demultiplex (i.e.
     * recognize) the content meant for the new instance
     * @return a new {@code MuxServerSocketChannel} instance open and bound on
     * the specified listening {@code endpoint}
     * @throws IOException if an I/O error occurs
     */
    public static MuxServerSocketChannel openAndBind(
            Map<String,Object> properties,
            SocketAddress endpoint,
            int backlog,
            DatagramPacketFilter filter)
        throws IOException
    {
        // The restriction(s) on filter are imposed by MuxingServerSocketChannel
        // and MuxServerSocketChannel. Assert that they are satisfied as early
        // as possible though because it does not make sense to bind a
        // ServerSocketChannel and initialize a new MuxingServerSocketChannel
        // instance otherwise.
        MuxServerSocketChannel.assertIsNotNull(filter, "filter");

        MuxingServerSocketChannel muxingChannel;

        synchronized (muxingServerSocketChannels)
        {
            muxingChannel = findMuxingServerSocketChannel(endpoint);
            if (muxingChannel == null)
            {
                ServerSocketChannel channel
                    = MuxServerSocketChannelFactory
                        .openAndBindServerSocketChannel(
                                properties,
                                endpoint,
                                backlog);

                muxingChannel = new MuxingServerSocketChannel(channel);
                addMuxingServerSocketChannel(muxingChannel);
            }
        }

        return muxingChannel.createMuxServerSocketChannel(filter);
    }

    /**
     * Runs in {@link #acceptThread} and waits for and accepts incoming network
     * connections on all {@link #muxingServerSocketChannels}.
     */
    private static void runInAcceptThread()
    {
        do
        {
            Selector sel;
            boolean select = false;

            synchronized (muxingServerSocketChannels)
            {
                if (!Thread.currentThread().equals(acceptThread))
                    break;

                sel = MuxingServerSocketChannel.acceptSelector;
                if (!sel.isOpen())
                    break;

                // Accept from all muxingServerSocketChannels.
                for (Iterator<MuxingServerSocketChannel> i
                        = muxingServerSocketChannels.iterator();
                     i.hasNext();)
                {
                    MuxingServerSocketChannel ch = i.next();

                    if (ch.isOpen())
                    {
                        try
                        {
                            ch.accept();
                        }
                        catch (IOException ioe)
                        {
                            // If ioe is a ClosedChannelException signalling
                            // that ch is closed, it will be handled at the end
                            // of the loop by removing ch from
                            // muxingServerSocketChannels.
                        }

                        // Make sure all muxingServerSocketChannels are
                        // registered with acceptSelector.
                        if (ch.isOpen() && ch.keyFor(sel) == null)
                        {
                            try
                            {
                                ch.register(sel, SelectionKey.OP_ACCEPT);
                            }
                            catch (ClosedChannelException cce)
                            {
                                // The cce will be handled at the end of the
                                // loop by removing ch from
                                // muxingServerSocketChannels.
                            }
                        }
                    }

                    if (ch.isOpen())
                        select = true;
                    else
                        i.remove();
                }
                // We've accepted from all muxingServerSocketChannels.
                sel.selectedKeys().clear();

                // If there are no muxingServerSocketChannels, we will wait
                // until there are.
                if (!select)
                {
                    try
                    {
                        muxingServerSocketChannels.wait();
                    }
                    catch (InterruptedException ie)
                    {
                        // I don't know that we care about the interrupted state
                        // of the current thread because that the method
                        // runInAcceptThread() is pretty much the whole
                        // execution of the current thread that could
                        // potentially care about the interrupted state and it
                        // doesn't.
                    }
                    continue;
                }
            }

            // Wait for a new iteration of acceptance. (The value of the local
            // variable select is guaranteed to be true.)
            try
            {
                sel.select();
            }
            catch (ClosedSelectorException cse)
            {
                break;
            }
            catch (IOException ioe)
            {
                // Well, we're selecting from multiple SelectableChannels so
                // we're not sure what the IOException signals here.
            }
        }
        while (true);
    }

    /**
     * Schedules a specific {@code MuxingServerSocketChannel} for acceptance of
     * incoming network connections in {@link #acceptThread}.
     *
     * @param channel the {@code MuxingServerSocketChannel} to schedule for
     * acceptance of incoming network connections in {@code acceptThread}
     * @throws IOException if an I/O error occurs
     */
    private static void scheduleAccept(MuxingServerSocketChannel channel)
        throws IOException
    {
        synchronized (muxingServerSocketChannels)
        {
            if (acceptThread == null)
            {
                // acceptSelector
                maybeCloseAcceptSelector();
                try
                {
                    acceptSelector = channel.provider().openSelector();
                }
                catch (IOException ioe)
                {
                    acceptSelector = Selector.open();
                }

                // acceptThread
                acceptThread
                    = new Thread()
                    {
                        @Override
                        public void run()
                        {
                            try
                            {
                                runInAcceptThread();
                            }
                            finally
                            {
                                synchronized (muxingServerSocketChannels)
                                {
                                    if (Thread.currentThread().equals(
                                            acceptThread))
                                    {
                                        // acceptThread
                                        acceptThread = null;
                                        // acceptSelector
                                        maybeCloseAcceptSelector();
                                    }
                                }
                            }
                        }
                    };
                acceptThread.setDaemon(true);
                acceptThread.setName(
                        MuxingServerSocketChannel.class.getName()
                            + ".acceptThread");
                acceptThread.start();
            }
            else
            {
                // Notify acceptThread that a new MuxingServerSocketChannel
                // (e.g. channel) may have been added.
                Selector sel = MuxingServerSocketChannel.acceptSelector;

                if (sel != null)
                    sel.wakeup();
            }
        }

        // We might as well expedite the acceptance from
        // muxingServerSocketChannel i.e. not wait for acceptThread and
        // explicitly cause an accept iteration.
        channel.accept();
    }

    /**
     * The list of <tt>MuxServerSocketChannel</tt>s created by and delegating to
     * this instance.
     */
    private final List<MuxServerSocketChannel> muxServerSocketChannels
        = new ArrayList<>();

    /**
     * The list of {@code SocketChannel}s which have been accepted by this
     * {@code MuxingServerSocketChannel}, are being read from, and have not been
     * accepted by the {@link DatagramPacketFilter} of any
     * {@link MuxServerSocketChannel} yet.
     */
    private final Queue<SocketChannel> readQ = new LinkedList<>();

    /**
     * The {@code Selector} which waits for incoming packets on all
     * {@code SocketChannel}s in {@link #readQ}.
     */
    private final Selector readSelector;

    /**
     * The {@code Thread} which waits for incoming packets on and reads them
     * from all {@code SocketChannel}s in {@link #readQ}.
     */
    private Thread readThread;

    /**
     * The <tt>Object</tt> which synchronizes the access to the state of this
     * <tt>MuxingServerSocketChannel</tt> such as
     * {@link #muxServerSocketChannels} and {@link #readQ}.
     */
    private final Object syncRoot = new Object();

    /**
     * Initializes a new {@code MuxingServerSocketChannel} instance which is to
     * share the listening endpoint of a specific {@link ServerSocketChannel}
     * among multiple {@code MuxServerSocketChannel}s.
     *
     * @param delegate the {@code ServerSocketChannel} for which the new
     * instance is to provide listening endpoint sharing
     * @throws IOException if an I/O error occurs
     */
    public MuxingServerSocketChannel(ServerSocketChannel delegate)
        throws IOException
    {
        super(MuxServerSocketChannel.assertIsNotNull(delegate, "delegate"));

        // If at least one MuxServerSocketChannel is configured as non-blocking,
        // then MuxingServerSocketChannel (i.e. delegate) has to be configured
        // as non-blocking as well.
        configureBlocking(false);

        readSelector = provider().openSelector();
    }

    /**
     * Adds a specific {@code MuxServerSocketChannel} to the list of
     * {@code MuxServerSocketChannel}s created by and delegating to this
     * instance.
     *
     * @param channel the {@code MuxServerSocketChannel} to add
     */
    protected void addMuxServerSocketChannel(MuxServerSocketChannel channel)
    {
        synchronized (syncRoot)
        {
            muxServerSocketChannels.add(channel);
            syncRoot.notifyAll();

            // Wake readThread up in case a SocketChannel from readQ is accepted
            // by the filter of the newly-added MuxServerSocketChannel.
            scheduleRead(/* channel */ null);
        }
    }

    /**
     * Initializes a new {@code MuxServerSocketChannel} instance which is to
     * delegate to this instance and is to demultiplex incoming network
     * connections and packets using a specific {@link DatagramPacketFilter}.
     *
     * @param filter the {@code DatagramPacketFilter} to be used by the new
     * {@code MuxServerSocketChannel} instance to demultiplex incoming network
     * connections and packets
     * @return a new {@code MuxServerSocketChannel} instance which delegates to
     * this instance and demultiplexes incoming network connections and packets
     * using the specified {@code filter}
     */
    protected MuxServerSocketChannel createMuxServerSocketChannel(
            DatagramPacketFilter filter)
    {
        // A MuxServerSocketChannel with no filter does not make sense. It
        // cannot be a fallback because DatagramPacketFilters (i.e.
        // MuxServerSocketChannels) have no priorities. It cannot be a catch all
        // because a SocketChannel (i.e. Socket) may be accepted by a single
        // MuxServerSocketChannel only.
        MuxServerSocketChannel.assertIsNotNull(filter, "filter");

        MuxServerSocketChannel channel;

        synchronized (syncRoot)
        {
            Iterator<MuxServerSocketChannel> i
                = muxServerSocketChannels.iterator();

            while (i.hasNext())
            {
                MuxServerSocketChannel aChannel = i.next();

                if (aChannel.isOpen())
                {
                    DatagramPacketFilter aFilter = aChannel.filter;

                    // The implementations of Object#equals(Object) should be
                    // symmetric but they are written by humans so there is room
                    // for errors.
                    if (filter.equals(aFilter) || aFilter.equals(filter))
                    {
                        // A SocketChannel (i.e. Socket) may be accepted by a
                        // single MuxServerSocketChannel only.
                        throw new IllegalArgumentException("filter");
                    }
                }
                else
                {
                    i.remove();
                }
            }

            channel = new MuxServerSocketChannel(this, filter);
            addMuxServerSocketChannel(channel);
        }

        muxServerSocketChannelAdded(channel);

        return channel;
    }

    /**
     * Determines whether any of the {@code MuxServerSocketChannel}s created by
     * and delegating to this instance demultiplexes (i.e. recognizes) a
     * specific {@link SocketChannel} based on a specific {@link DatagramPacket}
     * read from it and will make it available for acceptance.
     *
     * @param p the {@code DatagramPacket} read from {@code channel} which is to
     * be analyzed by the {@code MuxServerSocketChannel}s created by and
     * delegating to this instance
     * @param channel the {@code SocketChannel} from which {@code p} was read
     * and which is to possibly be demultiplexed into a
     * {@code MuxServerSocketChannel}
     * @return {@code true} if one of the {@code MuxServerSocketChannel}s
     * created by and delegating to this instance demultiplexed the specified
     * {@code channel}; otherwise, {@code false}
     */
    private boolean filterAccept(DatagramPacket p, SocketChannel channel)
    {
        boolean b = false;

        for (Iterator<MuxServerSocketChannel> i
                = muxServerSocketChannels.iterator();
             i.hasNext();)
        {
            MuxServerSocketChannel muxChannel = i.next();

            if (muxChannel.isOpen())
            {
                try
                {
                    b = muxChannel.filterAccept(p, channel);
                    if (b)
                        break;
                }
                catch (Throwable t)
                {
                    // The implementation of DatagramPacketFilter is external to
                    // MuxingServerSocketChannel and we do not want the failure
                    // of one DatagramPacketFilter to kill the whole
                    // MuxingServerSocketChannel.
                    if (t instanceof InterruptedException)
                        Thread.currentThread().interrupt();
                    else if (t instanceof ThreadDeath)
                        throw (ThreadDeath) t;
                }
            }
            else
            {
                i.remove();
            }
        }
        return b;
    }

    /**
     * {@inheritDoc}
     *
     * Queues a {@link SocketChannel} accepted by this instance for reading so
     * that it may later on be demultiplexed into a
     * {@code MuxServerSocketChannel}.
     */
    @Override
    protected SocketChannel implAccept(SocketChannel accepted)
        throws IOException
    {
        synchronized (syncRoot)
        {
            if (accepted != null && accepted.isOpen())
            {
                accepted.configureBlocking(false);

                readQ.add(accepted);
                syncRoot.notifyAll();

                scheduleRead(accepted);
            }
        }

        return accepted;
    }

    /**
     * {@inheritDoc}
     *
     * Associates a {@link MuxingServerSocket} with this
     * {@code MuxingServerSocketChannel}.
     */
    @Override
    protected MuxingServerSocket implSocket(ServerSocket socket)
        throws IOException
    {
        return new MuxingServerSocket(socket, this);
    }

    /**
     * Attempts to read from a specific {@link SocketChannel} into a specific
     * {@link ByteBuffer} without throwing an {@link IOException} if the reading
     * from the {@code channel} fails or there is insufficient room in
     * {@code buf} to write into.
     *
     * @param channel the {@code SocketChannel} to read from
     * @param buf the {@code ByteBuffer} to write into
     * @return the number of {@code byte}s read from {@code channel} and written
     * into {@code buf} or {@code -1} if {@code channel} has reached the end of
     * its stream
     */
    protected int maybeRead(SocketChannel channel, ByteBuffer buf)
    {
        int read;

        if (buf.remaining() > 0)
        {
            try
            {
                read = channel.read(buf);
            }
            catch (IOException ioe)
            {
                // If ioe is a ClosedChannelException signalling that the
                // specified channel is closed, it will be handled by the method
                // caller (by removing channel from readQ).
                read = 0;
            }
        }
        else
        {
            read = 0;
        }
        return read;
    }

    /**
     * Notifies this <tt>MixingServerSocketChannel</tt> that a specific
     * <tt>MuxServerSocketChannel</tt> was added to
     * {@link #muxServerSocketChannels}.
     *
     * @param channel the added <tt>MuxServerSocketChannel</tt>
     */
    protected void muxServerSocketChannelAdded(
            MuxServerSocketChannel channel)
    {
    }

    /**
     * Runs in {@link #readThread} and reads from all {@link SocketChannel}s in
     * {@link #readQ} and serves them for demultiplexing to
     * {@link #muxServerSocketChannels}.
     */
    protected void runInReadThread()
    {
        do
        {
            Selector sel;
            boolean select = false;

            synchronized (syncRoot)
            {
                if (!Thread.currentThread().equals(readThread))
                    break;

                sel = this.readSelector;
                if (!sel.isOpen())
                    break;

                for (Iterator<SocketChannel> i = readQ.iterator();
                     i.hasNext();)
                {
                    SocketChannel ch = i.next();
                    boolean remove = false;

                    if (ch.isOpen())
                    {
                        SelectionKey sk = ch.keyFor(sel);

                        if (sk == null)
                        {
                            // Make sure that all SocketChannels in readQ are
                            // registered with readSelector.
                            try
                            {
                                sk = ch.register(sel, SelectionKey.OP_READ);
                            }
                            catch (ClosedChannelException cce)
                            {
                                // The cce will be handled at the end of the
                                // loop by removing ch from readQ.
                            }
                        }
                        if (sk != null && sk.isValid())
                        {
                            // Try to read from ch.
                            DatagramBuffer db
                                = (DatagramBuffer) sk.attachment();

                            if (db == null)
                            {
                                db
                                    = new DatagramBuffer(
                                            SOCKET_CHANNEL_READ_CAPACITY);
                                sk.attach(db);
                            }

                            int read = maybeRead(ch, db.getByteBuffer());

                            // Try to filter ch (into a MuxServerSocketChannel).
                            if (ch.isOpen())
                            {
                                // Maintain a record of when the SocketChannel
                                // last provided readable data in order to weed
                                // out abandoned ones.
                                long now = System.currentTimeMillis();

                                if (read > 0 || db.timestamp == -1)
                                    db.timestamp = now;

                                DatagramPacket pkt = db.getDatagramPacket();

                                if (pkt.getLength() > 0
                                        && filterAccept(pkt, ch))
                                {
                                    sk.cancel();
                                    remove = true;
                                }
                                else if (read <= 0
                                        && now - db.timestamp
                                            > SOCKET_CHANNEL_READ_TIMEOUT)
                                {
                                    // The SocketChannel appears to have been
                                    // abandoned by the client.
                                    closeNoExceptions(ch);
                                }
                            }
                        }
                    }

                    if (remove || !ch.isOpen())
                        i.remove();
                    else
                        select = true;
                }
                // We've read from all SocketChannels in readQ.
                sel.selectedKeys().clear();

                // If there are no SocketChannels in readQ, we will wait until
                // there are.
                if (!select)
                {
                    try
                    {
                        syncRoot.wait();
                    }
                    catch (InterruptedException ie)
                    {
                        // I don't know that we care about the interrupted state
                        // of the current thread because that the method
                        // runInReadThread() is pretty much the whole execution
                        // of the current thread that could potentially care
                        // about the interrupted state and it doesn't.
                    }
                    continue;
                }
            }

            // Wait for a new iteration of acceptance. (The value of the local
            // variable select is guaranteed to be true.)
            try
            {
                sel.select();
            }
            catch (ClosedSelectorException cse)
            {
                break;
            }
            catch (IOException ioe)
            {
                // Well, we're selecting from multiple SelectableChannels so
                // we're not sure what the IOException signals here.
            }
        }
        while (true);
    }

    /**
     * Queues a specific {@link SocketChannel} to be read and demultiplexed into
     * a {@code MuxServerSocketChannel}.
     *
     * @param channel the {@code SocketChannel} to queue for reading and
     * demultiplexing
     */
    protected void scheduleRead(SocketChannel channel)
    {
        synchronized (syncRoot)
        {
            if (readThread == null)
            {
                // readThread
                readThread
                    = new Thread()
                    {
                        @Override
                        public void run()
                        {
                            try
                            {
                                runInReadThread();
                            }
                            finally
                            {
                                synchronized (syncRoot)
                                {
                                    if (Thread.currentThread().equals(
                                            readThread))
                                    {
                                        readThread = null;
                                    }
                                }
                            }
                        }
                    };
                readThread.setDaemon(true);
                readThread.setName(
                        MuxingServerSocketChannel.class.getName()
                            + ".readThread");
                readThread.start();
            }
            else
            {
                // Notify readThread that a new SocketChannel (e.g. channel) may
                // have been added.
                Selector sel = this.readSelector;

                if (sel != null)
                    sel.wakeup();
            }
        }
    }
}
