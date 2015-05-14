/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
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
 * Implements a {@link ServerSocketChannel} which is capable of sharing its
 * listening endpoint with multiple others like it.
 *
 * @author Lyubomir Marinov
 */
public class MuxServerSocketChannel
    extends DelegatingServerSocketChannel<MuxServerSocketChannel.MuxingServerSocketChannel>
{
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

    /**
     * The maximum number of milliseconds to wait for an accepted
     * {@code SocketChannel} to provide incoming/readable data before it is
     * considered abandoned by the client.
     */
    private static final int SOCKET_CHANNEL_READ_TIMEOUT
        = MuxServerSocketChannelFactory.SOCKET_CHANNEL_READ_TIMEOUT;

    /**
     * Asserts that <tt>t</tt> is not <tt>null</tt> by throwing a
     * <tt>NullPointerException</tt> if it is.
     *
     * @param t the <tt>Object</tt> to assert that it is not <tt>null</tt>
     * @param message the (detail) message of the <tt>NullPointerException</tt>
     * to be thrown if <tt>t</tt> is <tt>null</tt>
     * @param <T> the type of <tt>t</tt>
     * @return <tt>t</tt>
     * @throws NullPointerException if <tt>t</tt> is <tt>null</tt>. The (detail)
     * message of the <tt>NullPointerException</tt> is <tt>message</tt>
     */
    public static <T> T assertIsNotNull(T t, String message)
        throws NullPointerException
    {
        if (t == null)
            throw new NullPointerException(message);
        else
            return t;
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
        return
            MuxingServerSocketChannel.openAndBind(
                    properties,
                    endpoint,
                    backlog,
                    filter);
    }

    /**
     * The (ordered) list (i.e. queue) of <tt>SocketChannel</tt>s to be returned
     * by {@link #accept()}.
     */
    private final Queue<SocketChannel> acceptQ
        = new LinkedList<SocketChannel>();

    /**
     * The {@code DatagramPacketFilter} which demultiplexes
     * {@code SocketChannel}s accepted by the associated
     * {@code MuxingServerSocketChannel}.
     */
    protected final DatagramPacketFilter filter;

    /**
     * The <tt>Object</tt> which synchronizes the access to the state of this
     * <tt>MuxServerSocketChannel</tt> such as {@link #acceptQ}.
     */
    private final Object syncRoot = new Object();

    /**
     * Initializes a new {@code MuxServerSocketChannel} instance which is to
     * demultiplex {@link SocketChannel}s accepted by a specific
     * {@link MuxingServerSocketChannel} using a specific
     * {@link DatagramPacketFilter}. The new instance shares the listening
     * endpoint of {@code delegate} with any other associated
     * {@code MuxServerSocketChannel}s.
     *
     * @param delegate the {@code MuxingServerSocketChannel} which is actually
     * open and bound to a listening endpoint and accepts {@code SocketChannel}s
     * to be filtered by associated
     * {@code MuxServerSocketChannel}s
     * @param filter the {@code DatagramPacketFilter} which is to demultiplex
     * {@code SocketChannel}s accepted by {@code delegate}
     */
    protected MuxServerSocketChannel(
            MuxingServerSocketChannel delegate,
            DatagramPacketFilter filter)
    {
        super(assertIsNotNull(delegate, "delegate"));

        this.filter = assertIsNotNull(filter, "filter");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SocketChannel accept()
        throws IOException
    {
        SocketChannel accepted;

        // Pop a SocketChannel from acceptQ.
        do
        {
            if (!isOpen())
            {
                throw new ClosedChannelException();
            }
            else if (!isBound())
            {
                throw new NotYetBoundException();
            }
            else
            {
                synchronized (syncRoot)
                {
                    accepted = acceptQ.poll();
                    if (accepted == null)
                    {
                        if (isBlocking())
                        {
                            try
                            {
                                syncRoot.wait();
                            }
                            catch (InterruptedException ie)
                            {
                            }
                        }
                        else
                        {
                            break;
                        }
                    }
                    else if (accepted.isOpen())
                    {
                        // Allow the MuxServerSocketChannel class and/or its
                        // super(s) to have a final say on the accepted
                        // SocketChannel such as wrapping it into a suitable
                        // specialization of DelegatingSocketChannel.
                        accepted = implAccept(accepted);
                        if (accepted != null)
                            break;
                    }
                }
            }
        }
        while (true);
        return accepted;
    }

    /**
     * Determines whether the {@link #filter} of this instance accepts a
     * specific {@code SocketChannel} from which a specific
     * {@code DatagramPacket} has been read and, if it does, queues the
     * {@code channel} to be accepted through this instance.
     *
     * @param p the {@code DatagramPacket} which has been read from
     * {@code channel} and which is to be analyzed by the {@code filter} of this
     * instance
     * @param channel the {@code SocketChannel} from which {@code p} has been
     * read and which is to be queued for acceptance through this instance if
     * the {@code filter} accepts {@code p} 
     * @return {@code true} if the {@code filter} of this instance accepts
     * {@code p} and {@code channel} was queued for acceptance through this
     * instance; otherwise, {@code false}
     */
    protected boolean filterAccept(DatagramPacket p, SocketChannel channel)
    {
        boolean b;

        if (filter.accept(p))
            b = qAccept(new PreReadSocketChannel(p, channel));
        else
            b = false;
        return b;
    }

    /**
     * {@inheritDoc}
     *
     * Adjusts the blocking mode of {@link #delegate}.
     */
    @Override
    protected void implConfigureBlocking(boolean block)
        throws IOException
    {
        // If at least one MuxServerSocketChannel is configured as non-blocking,
        // then MuxingServerSocketChannel has to be configured as non-blocking
        // as well.
        if (!block)
            delegate.configureBlocking(block);
    }

    /**
     * {@inheritDoc}
     *
     * Associates a {@link MuxServerSocket} with this
     * {@code MuxServerSocketChannel}.
     */
    @Override
    protected MuxServerSocket implSocket(ServerSocket socket)
        throws IOException
    {
        return new MuxServerSocket((MuxingServerSocket) socket, this);
    }

    /**
     * Queues a {@link SocketChannel} for acceptance through this instance.
     *
     * @param channel the {@code SocketChannel} to queue for acceptance through
     * this instance
     * @return {@code true} if {@code channel} was queued for acceptance through
     * this instance; otherwise, {@code false}
     */
    private boolean qAccept(SocketChannel channel)
    {
        boolean b;

        synchronized (syncRoot)
        {
            if (acceptQ.offer(channel))
            {
                syncRoot.notifyAll();
                b = true;
            }
            else
            {
                b = false;
            }
        }
        return b;
    }

    /**
     * Associates a {@link ByteBuffer} with a {@link DatagramPacket} so that the
     * {@code ByteBuffer} may be used for writing into a {@code byte} array and
     * the {@code DatagramPacket} may be used for reader from the same
     * {@code byte} array.
     */
    private static class DatagramBuffer
    {
        /**
         * The {@code ByteBuffer} which is associated with
         * {@link #datagramPacket} and shares its backing {@code array} with.
         */
        private final ByteBuffer byteBuffer;

        /**
         * The {@code DatagramPacket} which is associated with
         * {@link #byteBuffer} and shares its {@code data} with.
         */
        private final DatagramPacket datagramPacket;

        /**
         * The latest/last time in milliseconds at which {@code byte}s were
         * written into this {@code DatagramBuffer}.
         */
        long timestamp = -1;

        /**
         * Initializes a new {@code DatagramBuffer} instance with a specific
         * capacity of {@code byte}s shared between a {@code ByteBuffer} and a
         * {@code DatagramPacket}.
         *
         * @param capacity the maximum number of {@code byte}s to be written
         * into and read from the new instance
         */
        public DatagramBuffer(int capacity)
        {
            byteBuffer = ByteBuffer.allocate(capacity);
            datagramPacket
                = new DatagramPacket(
                        byteBuffer.array(),
                        /* offset */ 0,
                        /* length */ 0);
        }

        /**
         * Gets the {@code ByteBuffer} (view) of this instance.
         *
         * @return the {@code ByteBuffer} (view) of this instance
         */
        public ByteBuffer getByteBuffer()
        {
            return byteBuffer;
        }

        /**
         * Gets the {@code DatagramPacket} (view) of this instance. The
         * {@code length} of the {@code DatagramPacket} equals the
         * {@code position} of the {@code ByteBuffer} so that the {@code byte}s
         * written into the {@code ByteBuffer} may be read from the
         * {@code DatagramPacket}.
         *
         * @return the {@code DatagramPacket} (view) of this instance
         */
        public DatagramPacket getDatagramPacket()
        {
            datagramPacket.setLength(byteBuffer.position());
            return datagramPacket;
        }
    }

    /**
     * Represents a {@link ServerSocket} associated with a
     * {@code MuxingServerSocketChannel}.
     */
    protected static class MuxingServerSocket
        extends DelegatingServerSocket
    {
        /**
         * Initializes a new {@code MuxingServerSocket} instance which delegates
         * (its method calls) to a specific {@code ServerSocket} and is
         * associated with a specific {@code MuxingServerSocketChannel}.
         *
         * @param delegate the {@code ServerSocket} the new instance is to
         * delegate (its method calls) to. Technically, it is the {@code socket}
         * of the {@code delegate} of {@code channel}.
         * @param channel the {@code MuxingServerSocketChannel} associated with
         * the new instance
         * @throws IOException if an I/O error occurs
         */
        public MuxingServerSocket(
                ServerSocket delegate,
                MuxingServerSocketChannel channel)
            throws IOException
        {
            super(
                    assertIsNotNull(delegate, "delegate"),
                    assertIsNotNull(channel, "channel"));
        }
    }

    /**
     * Shares a listening endpoint (i.e. an open and bound
     * {@link ServerSocketChannel}) among multiple
     * {@code MuxServerSocketChannel}s. Accepted {@link SocketChannel}s are
     * demultiplexed based on {@link DatagramPacketFilter}s and dispatched for
     * acceptance through matching {@code MuxServerSocketChannel}s.
     */
    protected static class MuxingServerSocketChannel
        extends DelegatingServerSocketChannel<ServerSocketChannel>
    {
        /**
         * The {@code Selector} which waits for incoming network connections on
         * all {@link #muxingServerSocketChannels}.
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
                = new LinkedList<MuxingServerSocketChannel>();

        /**
         * Adds a specific {@code MuxingServerSocketChannel} to the (global)
         * list of existing {@code MuxingServerSocketChannel}s and schedules
         * acceptance of incoming network connections on it.
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
         * Finds the first open {@code MuxingServerSocketChannel} in the
         * (global) list of existing {@code MuxingServerSocketChannel}s which is
         * bound to a specific local {@link SocketAddress}.
         *
         * @param localAddr the local {@code SocketAddress} on which the bound
         * {@code MuxingServerSocketChannel} is to be found
         * @return the first open {@code MuxingServerSocketChannel} in the
         * (global) list of existing {@code MuxingServerSocketChannel}s which is
         * bound to the specified {@code localAddr} or {@code null} 
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
                        if (aLocalAddr != null && aLocalAddr.equals(localAddr))
                        {
                            channel = aChannel;
                            // The whole idea of using (1) a List for
                            // muxingServerSocketChannels instead of a Map and
                            // (2) an Iterator to loop over
                            // muxingServerSocketChannels is to aggressively
                            // clean up. Anyway, break as soon as possible in
                            // order to improve the execution speed and because
                            // there is an attempt to clean
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
         * If {@link #acceptSelector} exists and is open, try to close it and do
         * not throw an <tt>IOException</tt>.
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
                    }
                }
                acceptSelector = null;
            }
        }

        /**
         * Opens and binds a new {@code MuxServerSocketChannel} instance. If
         * there are other (existing) {@code MuxServerSocketChannel} open and
         * bound on the specified listening {@code endpoint}, the new instance
         * will share it with them.
         *
         * @param properties a {@code Map} of the values to be assigned to
         * properties of the underlying {@link ServerSocketChannel} which is to
         * actually listen on the specified {@code endpoint}. If the new
         * instance is not the first to open and bind the specified
         * {@code endpoint}, the {@code properties} and their respective values
         * may not be used.
         * @param endpoint the IP and port the new instance is to bind to
         * @param backlog the requested maximum number of pending incoming
         * connections to be queued. If the new instance is not the first to
         * open and bind the specified {@code endpoint}, the value may not be
         * used.
         * @param filter the {@code DatagramPacketFilter} to demultiplex (i.e.
         * recognize) the content meant for the new instance
         * @return a new {@code MuxServerSocketChannel} instance open and bound
         * on the specified listening {@code endpoint}
         * @throws IOException if an I/O error occurs
         */
        public static MuxServerSocketChannel openAndBind(
                Map<String,Object> properties,
                SocketAddress endpoint,
                int backlog,
                DatagramPacketFilter filter)
            throws IOException
        {
            // The restriction(s) on filter are imposed by
            // MuxingServerSocketChannel and MuxServerSocketChannel. Assert that
            // they are satisfied as early as possible though because it does
            // not make sense to bind a ServerSocketChannel and initialize a new
            // MuxingServerSocketChannel instance otherwise.
            assertIsNotNull(filter, "filter");

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
         * Runs in {@link #acceptThread} and waits for and accepts incoming
         * network connections on all {@link #muxingServerSocketChannels}.
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
                                // that ch is closed, it will be handled at the
                                // end of the loop by removing ch from
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
                        }
                        continue;
                    }
                }

                // Wait for a new iteration of acceptance.
                if (select)
                {
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
                        // Well, we're selecting from multiple
                        // SelectableChannels so we're not sure what the
                        // IOException signals here.
                    }
                }
            }
            while (true);
        }

        /**
         * Schedules a specific {@code MuxingServerSocketChannel} for acceptance
         * of incoming network connections in {@link #acceptThread}.
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
         * The list of <tt>MuxServerSocketChannel</tt>s created by and
         * delegating to this instance.
         */
        private final List<MuxServerSocketChannel> muxServerSocketChannels
            = new ArrayList<MuxServerSocketChannel>();

        /**
         * The list of {@code SocketChannel}s which have been accepted by this
         * {@code MuxingServerSocketChannel}, are being read from, and have not
         * been accepted by the {@link DatagramPacketFilter} of any
         * {@link MuxServerSocketChannel} yet.
         */
        private final Queue<SocketChannel> readQ
            = new LinkedList<SocketChannel>();

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
         * The <tt>Object</tt> which synchronizes the access to the state of
         * this <tt>MuxingServerSocketChannel</tt> such as
         * {@link #muxServerSocketChannels} and {@link #readQ}.
         */
        private final Object syncRoot = new Object();

        /**
         * Initializes a new {@code MuxingServerSocketChannel} instance which is
         * to share the listening endpoint of a specific
         * {@link ServerSocketChannel} among multiple
         * {@code MuxServerSocketChannel}s.
         *
         * @param delegate the {@code ServerSocketChannel} for which the new
         * instance is to provide listening endpoint sharing
         * @throws IOException if an I/O error occurs
         */
        public MuxingServerSocketChannel(ServerSocketChannel delegate)
            throws IOException
        {
            super(assertIsNotNull(delegate, "delegate"));

            // If at least one MuxServerSocketChannel is configured as
            // non-blocking, then MuxingServerSocketChannel (i.e. delegate) has
            // to be configured as non-blocking as well.
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

                // Wake readThread up in case a SocketChannel from readQ is
                // accepted by the filter of the newly-added
                // MuxServerSocketChannel.
                scheduleRead(/* channel */ null);
            }
        }

        /**
         * Initializes a new {@code MuxServerSocketChannel} instance which is to
         * delegate to this instance and is to demultiplex incoming network
         * connections and packets using a specific
         * {@link DatagramPacketFilter}.
         *
         * @param filter the {@code DatagramPacketFilter} to be used by the new
         * {@code MuxServerSocketChannel} instance to demultiplex incoming
         * network connections and packets
         * @return a new {@code MuxServerSocketChannel} instance which delegates
         * to this instance and demultiplexes incoming network connections and
         * packets using the specified {@code filter}
         */
        protected MuxServerSocketChannel createMuxServerSocketChannel(
                DatagramPacketFilter filter)
        {
            // A MuxServerSocketChannel with no filter does not make sense. It
            // cannot be a fallback because DatagramPacketFilters (i.e.
            // MuxServerSocketChannels) have no priorities. It cannot be a catch
            // all because a SocketChannel (i.e. Socket) may be accepted by a
            // single MuxServerSocketChannel only.
            assertIsNotNull(filter, "filter");

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

                        // The implementations of Object#equals(Object) should
                        // be symmetric but they are written by humans so there
                        // is room for errors.
                        if (filter.equals(aFilter) || aFilter.equals(filter))
                        {
                            // A SocketChannel (i.e. Socket) may be accepted by
                            // a single MuxServerSocketChannel only.
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
         * Determines whether any of the {@code MuxServerSocketChannel}s created
         * by and delegating to this instance demultiplexes (i.e. recognizes) a
         * specific {@link SocketChannel} based on a specific
         * {@link DatagramPacket} read from it and will make it available for
         * acceptance.
         *
         * @param p the {@code DatagramPacket} read from {@code channel} which
         * is to be analyzed by the {@code MuxServerSocketChannel}s created by
         * and delegating to this instance
         * @param channel the {@code SocketChannel} from which {@code p} was
         * read and which is to possibly be demultiplexed into a
         * {@code MuxServerSocketChannel}
         * @return {@code true} if one of the {@code MuxServerSocketChannel}s
         * created by and delegating to this instance demultiplexed the
         * specified {@code channel}; otherwise, {@code false}
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
                        // The implementation of DatagramPacketFilter is
                        // external to MuxingServerSocketChannel and we do not
                        // want the failure of one DatagramPacketFilter to kill
                        // the whole MuxingServerSocketChannel.
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
         * Queues a {@link SocketChannel} accepted by this instance for reading
         * so that it may later on be demultiplexed into a
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
         * Attempts to read from a specific {@link SocketChannel} into a
         * specific {@link ByteBuffer} without throwing an {@link IOException}
         * if the reading from the {@code channel} fails or there is
         * insufficient room in {@code buf} to write into.
         *
         * @param channel the {@code SocketChannel} to read from
         * @param buf the {@code ByteBuffer} to write into
         * @return the number of {@code byte}s read from {@code channel} and
         * written into {@code buf} or {@code -1} if {@code channel} has reached
         * the end of its stream
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
                    // specified channel is closed, it will be handled by the
                    // method caller (by removing channel from readQ).
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
         * Runs in {@link #readThread} and reads from all {@link SocketChannel}s
         * in {@link #readQ} and serves them for demultiplexing to
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
                                // Make sure that all SocketChannels in readQ
                                // are registered with readSelector.
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

                                // Try to filter ch (into a
                                // MuxServerSocketChannel).
                                if (ch.isOpen())
                                {
                                    // Maintain a record of when the
                                    // SocketChannel last provided readable data
                                    // in order to weed out abandoned ones.
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
                                        // The SocketChannel appears to have
                                        // been abandoned by the client.
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

                    // If there are no SocketChannels in readQ, we will wait
                    // until there are.
                    if (!select)
                    {
                        try
                        {
                            syncRoot.wait();
                        }
                        catch (InterruptedException ie)
                        {
                        }
                        continue;
                    }
                }

                // Wait for a new iteration of acceptance.
                if (select)
                {
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
                        // Well, we're selecting from multiple
                        // SelectableChannels so we're not sure what the
                        // IOException signals here.
                    }
                }
            }
            while (true);
        }

        /**
         * Queues a specific {@link SocketChannel} to be read and demultiplexed
         * into a {@code MuxServerSocketChannel}.
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
                    // Notify readThread that a new SocketChannel (e.g. channel)
                    // may have been added.
                    Selector sel = this.readSelector;

                    if (sel != null)
                        sel.wakeup();
                }
            }
        }
    }

    /**
     * Represents a {@link ServerSocket} associated with a
     * {@code MuxServerSocketChannel}.
     */
    public static class MuxServerSocket
        extends DelegatingServerSocket
    {
        /**
         * Initializes a new {@code MuxServerSocket} instance which delegates
         * (its method calls) to a specific {@code MuxingServerSocket} and is
         * associated with a specific {@code MuxServerSocketChannel}.
         *
         * @param delegate the {@code MuxingServerSocket} the new instance is to
         * delegate (its method calls) to. Technically, it is the {@code socket}
         * of the {@code delegate} of {@code channel}.
         * @param channel the {@code MuxServerSocketChannel} associated with the
         * new instance
         * @throws IOException if an I/O error occurs
         */
        public MuxServerSocket(
                MuxingServerSocket delegate,
                MuxServerSocketChannel channel)
            throws IOException
        {
            super(
                    assertIsNotNull(delegate, "delegate"),
                    assertIsNotNull(channel, "channel"));
        }
    }
}
