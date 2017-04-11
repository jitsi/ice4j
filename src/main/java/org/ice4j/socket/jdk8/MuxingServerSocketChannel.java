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
import java.util.function.*;
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
     * The maximum number of milliseconds to wait in a
     * {@link Selector#select(long)}. The timeout should be a precaution though
     * i.e. (1) it should better not be necessary and (2) it should be long
     * enough to not unnecessarily hurt the performance of the application.
     */
    private static final int SELECTOR_SELECT_TIMEOUT
        = MuxServerSocketChannelFactory.SOCKET_CHANNEL_READ_TIMEOUT;

    /**
     * The maximum number of milliseconds to wait for an accepted
     * {@code SocketChannel} to provide incoming/readable data before it is
     * considered abandoned by the client.
     */
    static final int SOCKET_CHANNEL_READ_TIMEOUT
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
        Objects.requireNonNull(filter, "filter");

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
        runInSelectorThread(
                /* syncRoot */ muxingServerSocketChannels,
                /* threadSupplier */ new Supplier<Thread>()
                {
                    @Override
                    public Thread get()
                    {
                        return MuxingServerSocketChannel.acceptThread;
                    }
                },
                /* selectorSupplier */ new Supplier<Selector>()
                {
                    @Override
                    public Selector get()
                    {
                        return MuxingServerSocketChannel.acceptSelector;
                    }
                },
                /* selectionKeyOps */ SelectionKey.OP_ACCEPT,
                /* channels */ muxingServerSocketChannels,
                /* predicate */ new BiPredicate<MuxingServerSocketChannel, SelectionKey>()
                {
                    @Override
                    public boolean test(
                            MuxingServerSocketChannel ch,
                            SelectionKey sk)
                    {
                        try
                        {
                            // The idea is that all muxingServerSocketChannels
                            // are non-blocking.
                            ch.accept();
                        }
                        catch (IOException ioe)
                        {
                            // If ioe is a ClosedChannelException signalling
                            // that ch is closed, it will be handled at the end
                            // of the loop by removing ch from
                            // muxingServerSocketChannels.
                        }

                        return false;
                    }
                });
    }

    /**
     * Continually tests a {@link Predicate} on a set of
     * {@link SelectableChannel}s.
     *
     * @param syncRoot the {@code Object} to synchronize the access to
     * {@code threadSupplier}, {@code selectorSupplier}, {@code channels}, and
     * {@code predicate}. It should be notified whenever the values supplied by
     * {@code threadSupplier}, {@code selectorSupplier}, and {@code channels}
     * change.
     * @param threadSupplier the {@link Supplier} which is to supply the
     * {@code Thread} in which the method is supposed to be running. If the
     * returned value differs from the {@code Thread} in which the method is
     * actually running (i.e. {@link Thread#currentThread()}, the method
     * returns. In other words, {@code threadSupplier} is one of the ways to
     * break out of the loop implemented by the method. The
     * {@code threadSupplier} is called on while {@code syncRoot} is acquired.
     * @param selectorSupplier the {@code Supplier} which is to supply the
     * {@code Selector} on which the method is to await changes in the states of
     * {@code channels} in order to begin a subsequent loop iteration. If the
     * returned {@code Selector} is not open, the method returns. In other
     * words, {@code selectorSupplier} is another way to break out of the loop
     * implemented by the method. The {@code selectorSupplier} is called on
     * while {@code syncRoot} is acquired.
     * @param selectionKeyOps the {@link SelectionKey} operation-set bits which
     * identify the states of {@code channels} whose changes trigger new loop
     * iterations
     * @param channels the (set of) {@code SelectableChannel}s on each of which
     * {@code predicate} is to be continually tested. A loop iteration is
     * triggered when at least one of {@code channels} has a state identified by
     * {@code selectionKeyOps} changes.
     * @param predicate the {@code Predicate} which is to be continually tested
     * on {@code channels}. A loop iteration is triggered when at least one of
     * {@code channels} has a state identified by {@code selectionKeyOps}
     * changes. {@link BiPredicate#test(Object, Object)} is supplied with an
     * element of {@code channels} and its (automatically) associated
     * {@code SelectionKey} in the {@code Selector} returned by
     * {@code selectorSupplier}. The {@code SelectionKey} is provided in case,
     * for example, the implementation of {@code predicate} chooses to associate
     * additional state with the {@code SelectableChannel} (through
     * {@link SelectionKey#attach(Object)}) available throughout the whole loop.
     * @param <T> the element type of {@code channels}
     */
    private static <T extends SelectableChannel> void runInSelectorThread(
            Object syncRoot,
            Supplier<Thread> threadSupplier,
            Supplier<Selector> selectorSupplier,
            int selectionKeyOps,
            Iterable<T> channels,
            BiPredicate<T, SelectionKey> predicate)
    {
        // The timeout to use when invoking Selector#select(long) on sel (i.e.
        // the Selector supplied by selectorSupplier). It purpose is twofold:
        // (1) to not wait too long in Selector#select() (hence
        // SELECTOR_SELECT_TIMEOUT) and (2) to weed out abandoned channels
        // (hence SOCKET_CHANNEL_READ_TIMEOUT).
        final int selSelectTimeout
            = Math.min(SELECTOR_SELECT_TIMEOUT, SOCKET_CHANNEL_READ_TIMEOUT);

        do
        {
            Selector sel;
            boolean select = false;

            synchronized (syncRoot)
            {
                if (!Thread.currentThread().equals(threadSupplier.get()))
                    break;

                sel = selectorSupplier.get();
                if (sel == null || !sel.isOpen())
                    break;

                for (Iterator<T> i = channels.iterator(); i.hasNext();)
                {
                    T ch = i.next();
                    boolean remove = false;

                    if (ch.isOpen())
                    {
                        SelectionKey sk = ch.keyFor(sel);

                        if (sk == null)
                        {
                            // Make sure that all (SelectableChannels in)
                            // channels are registered with (the Selector) sel.
                            try
                            {
                                sk = ch.register(sel, selectionKeyOps);
                            }
                            catch (ClosedChannelException cce)
                            {
                                // The cce will be handled at the end of the
                                // loop by removing ch from channels.
                            }
                        }
                        if (sk != null && sk.isValid())
                        {
                            remove = predicate.test(ch, sk);
                            if (remove)
                                sk.cancel();
                        }
                    }

                    if (remove || !ch.isOpen())
                        i.remove();
                    else
                        select = true;
                }

                // We've invoked the predicate on all (SelectableChannels in)
                // channels.
                sel.selectedKeys().clear();

                // If there are no SelectableChannels in channels, we will wait
                // until there are.
                if (!select)
                {
                    // We're going to wait bellow and continue with the next
                    // iteration of the loop afterwards. Don't hold onto sel
                    // while waiting (because it's unnecessary).
                    sel = null;

                    try
                    {
                        syncRoot.wait();
                    }
                    catch (InterruptedException ie)
                    {
                        // I don't know that we care about the interrupted state
                        // of the current thread because the method
                        // runInSelectorThread() is (or at least should be)
                        // pretty much the whole execution of the current thread
                        // that could potentially care about the interrupted
                        // state and it doesn't (or at least shouldn't).
                    }
                    continue;
                }
            }

            // Wait for a new change in the state(s) of at least one element of
            // channels. (The value of the local variable select is guaranteed
            // to be true here.)
            try
            {
                // Even if no element of channels has its state(s) changed, do
                // wake up after selSelectTimeout milliseconds in order to weed
                // out abandoned channels.
                sel.select(selSelectTimeout);
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
        super(Objects.requireNonNull(delegate, "delegate"));

        // If at least one MuxServerSocketChannel is configured as non-blocking,
        // then MuxingServerSocketChannel (i.e. delegate) has to be configured
        // as non-blocking as well.
        configureBlocking(false);

        readSelector = provider().openSelector();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SocketChannel accept()
        throws IOException
    {
        SocketChannel ch = super.accept();

        // Weeds out abandoned SocketChannels which were classified/filtered
        // into MuxServerSocketChannel but were not accepted (out of it) for a
        // long time. The accept() method of MuxingServerSocketChannel is a
        // suitable place to do that because it is periodically invoked (by the
        // runInAcceptThread() method) on a clock (in addition to network
        // activity, of course).
        closeAbandonedSocketChannels();

        return ch;
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
     * Weed out {@code SocketChannel}s which were classified/filtered into
     * {@code MuxServerSocketChannel} but were not accepted (out of it) for a
     * long time.
     */
    private void closeAbandonedSocketChannels()
    {
        synchronized (syncRoot)
        {
            Collection<MuxServerSocketChannel> chs = muxServerSocketChannels;

            if (!chs.isEmpty())
            {
                long now = System.currentTimeMillis();

                for (MuxServerSocketChannel ch : chs)
                    ch.closeAbandonedSocketChannels(now);
            }
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
        Objects.requireNonNull(filter, "filter");

        MuxServerSocketChannel channel;

        synchronized (syncRoot)
        {
            for (Iterator<MuxServerSocketChannel> i
                        = muxServerSocketChannels.iterator();
                    i.hasNext();)
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

                // If there is only one (open) MuxServerSocketChannel, it is
                // inefficient to read from it in a separate thread and then
                // either deliver the accepted to the MuxServerSocketChannel or
                // close the accepted. The situation is pretty much like no
                // functionality enabled by MuxServerSocketChannel is needed:
                // whoever has invoked accept() on this ServerSocketChannel is
                // going to read from the accepted and either figure out that it
                // is in an expected format or close it.
                MuxServerSocketChannel oneAndOnly = null;

                for (MuxServerSocketChannel ch : muxServerSocketChannels)
                {
                    if (ch.isOpen())
                    {
                        if (oneAndOnly == null)
                        {
                            oneAndOnly = ch;
                        }
                        else
                        {
                            oneAndOnly = null;
                            break;
                        }
                    }
                }
                if (oneAndOnly != null && oneAndOnly.qAccept(accepted))
                {
                    // It shouldn't matter much whether null or accepted is
                    // returned. It sounds reasonable to return null from the
                    // standpoint that accepted was classified/filtered into a
                    // MuxServerSocketChannel and, consequently, this
                    // MuxingServerSocketChannel no longer possesses it.
                    return null;
                }

                // There are multiple (open) MuxServerSocketChannels (or none
                // but then the situation is weird and it's more easily handled
                // as the situation with multiple) and this instance is to read
                // from accepted in orde to determine where it's to be
                // classified/filtered.
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
    protected void muxServerSocketChannelAdded(MuxServerSocketChannel channel)
    {
    }

    /**
     * Runs in {@link #readThread} and reads from all {@link SocketChannel}s in
     * {@link #readQ} and serves them for demultiplexing to
     * {@link #muxServerSocketChannels}.
     */
    protected void runInReadThread()
    {
        runInSelectorThread(
                /* syncRoot */ syncRoot,
                /* threadSupplier */ new Supplier<Thread>()
                {
                    @Override
                    public Thread get()
                    {
                        return readThread;
                    }
                },
                /* selectorSupplier */ new Supplier<Selector>()
                {
                    @Override
                    public Selector get()
                    {
                        return readSelector;
                    }
                },
                /* selectionKeyOps */ SelectionKey.OP_READ,
                /* channels */ readQ,
                /* predicate */ new BiPredicate<SocketChannel, SelectionKey>()
                {
                    @Override
                    public boolean test(SocketChannel ch, SelectionKey sk)
                    {
                        return testRunInReadThreadPredicate(ch, sk);
                    }
                });
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

    /**
     * Implements {@link BiPredicate#test(Object, Object)} of the
     * {@code BiPredicate} utilized by {@link #runInReadThread()}. The method is
     * defined explicitly for the purposes of reducing excessive indentation and
     * bettering readability. Reads from {@code ch} and attempts to
     * classify/filter it into a {@link MuxServerSocketChannel} for acceptance.
     * If {@code ch} has not provided readable data within
     * {@link #SOCKET_CHANNEL_READ_TIMEOUT}, it is forcibly closed.
     *
     * @param ch the {@code SocketChannel} to read from and to classify/filter
     * into a {@code MuxServerSocketChannel} for acceptance
     * @param sk the {@code SelectionKey} associated with {@code ch} in the
     * {@code Selector} which awaits changes in the state(s) of {@code ch}
     * @return {@code true} if {@code ch} is to no longer be tested; otherwise,
     * {@code false}
     */
    private boolean testRunInReadThreadPredicate(
            SocketChannel ch,
            SelectionKey sk)
    {
        // Try to read from ch.
        DatagramBuffer db = (DatagramBuffer) sk.attachment();

        if (db == null)
        {
            db = new DatagramBuffer(SOCKET_CHANNEL_READ_CAPACITY);
            sk.attach(db);
        }

        int read = maybeRead(ch, db.getByteBuffer());

        // Try to filter ch (into a MuxServerSocketChannel).
        if (ch.isOpen())
        {
            // Maintain a record of when the SocketChannel last provided
            // readable data in order to weed out abandoned ones.
            long now = System.currentTimeMillis();

            if (read > 0 || db.timestamp == -1)
                db.timestamp = now;

            DatagramPacket p = db.getDatagramPacket();
            int len = p.getLength();

            if (len > 0)
            {
                if (filterAccept(p, ch))
                {
                    // A MuxServerSocketChannel has accepted ch so this
                    // MuxingServerSocketChannel is no longer responsible for
                    // ch.
                    return true;
                }
                else if (len >= SOCKET_CHANNEL_READ_CAPACITY)
                {
                    // This MuxingServerSocketChannel has read from ch as much
                    // as it will ever read and no existing
                    // MuxServerSocketChannel has accepted ch. There is no point
                    // in waiting anymore.
                    closeNoExceptions(ch);
                    // Allow this MuxingServerSocketChannel to clean ch up.
                    return false;
                }
            }

            if (read <= 0 && now - db.timestamp >= SOCKET_CHANNEL_READ_TIMEOUT)
            {
                // It appears ch has been abandoned by the client.
                closeNoExceptions(ch);
                return false;
            }
        }

        return false;
    }
}
