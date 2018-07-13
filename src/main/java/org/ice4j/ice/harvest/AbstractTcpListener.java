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
package org.ice4j.ice.harvest;

import org.ice4j.*;
import org.ice4j.ice.*;
import org.ice4j.message.*;
import org.ice4j.socket.*;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.*;
import java.util.logging.*;

/**
 * An abstract class that binds on a set of sockets and accepts sessions that
 * start with a STUN Binding Request (preceded by an optional fake SSL
 * handshake). The handling of the accepted sessions (e.g. handling in ICE) is
 * left to the implementations.
 *
 * This instance runs two threads: {@link #acceptThread} and
 * {@link #readThread}. The 'accept' thread just accepts new <tt>Socket</tt>s
 * and passes them over to the 'read' thread. The 'read' thread reads a STUN
 * message from an accepted socket and, based on the STUN username, passes it
 * to the appropriate session.
 *
 * @author Boris Grozev
 * @author Lyubomir Marinov
 */
public abstract class AbstractTcpListener
{
    /**
     * Our class logger.
     */
    private static final Logger logger
        = Logger.getLogger(AbstractTcpListener.class.getName());

    /**
     * Closes a {@code Channel} and swallows any {@link IOException}.
     *
     * @param channel the {@code Channel} to close
     */
    static void closeNoExceptions(Channel channel)
    {
        MuxServerSocketChannelFactory.closeNoExceptions(channel);
    }

    /**
     * Returns a list of all addresses on the interfaces in <tt>interfaces</tt>
     * which are found suitable for candidate allocations (are not loopback, are
     * up, and are allowed by the configuration).
     *
     * @param port the port to use.
     * @param interfaces the list of interfaces to use.
     */
    private static List<TransportAddress> getLocalAddresses(
            int port,
            List<NetworkInterface> interfaces)
        throws IOException
    {
        List<TransportAddress> addresses = new LinkedList<>();

        for (NetworkInterface iface : interfaces)
        {
            if (NetworkUtils.isInterfaceLoopback(iface)
                    || !NetworkUtils.isInterfaceUp(iface)
                    || !HostCandidateHarvester.isInterfaceAllowed(iface))
            {
                //this one is obviously not going to do
                continue;
            }

            Enumeration<InetAddress> ifaceAddresses = iface.getInetAddresses();

            while(ifaceAddresses.hasMoreElements())
            {
                InetAddress addr = ifaceAddresses.nextElement();

                addresses.add(new TransportAddress(addr, port, Transport.TCP));
            }
        }
        return addresses;
    }

    /**
     * Determines whether a specific {@link DatagramPacket} is the first
     * expected (i.e. supported) to be received from an accepted
     * {@link SocketChannel} by this {@link AbstractTcpListener}. This is true
     * if it is contains the hard-coded SSL client handshake (
     * {@link GoogleTurnSSLCandidateHarvester#SSL_CLIENT_HANDSHAKE}), or
     * a STUN Binding Request.
     *
     * @param p the {@code DatagramPacket} to examine
     * @return {@code true} if {@code p} looks like the first
     * {@code DatagramPacket} expected to be received from an accepted
     * {@code SocketChannel} by this {@code TcpHarvester};
     * otherwise, {@code false}
     */
    private static boolean isFirstDatagramPacket(DatagramPacket p)
    {
        int len = p.getLength();
        boolean b = false;

        if (len > 0)
        {
            byte[] buf = p.getData();
            int off = p.getOffset();

            // Check for Google TURN SSLTCP
            final byte[] googleTurnSslTcp
                = GoogleTurnSSLCandidateHarvester.SSL_CLIENT_HANDSHAKE;

            if (len >= googleTurnSslTcp.length)
            {
                b = true;
                for (int i = 0, iEnd = googleTurnSslTcp.length, j = off;
                     i < iEnd;
                     i++, j++)
                {
                    if (googleTurnSslTcp[i] != buf[j])
                    {
                        b = false;
                        break;
                    }
                }
            }

            // nothing found, lets check for stun binding requests
            if (!b)
            {
                // 2 bytes    uint16 length
                // STUN Binding request:
                //   2 bits   00
                //   14 bits  STUN Messsage Type
                //   2 bytes  Message Length
                //   4 bytes  Magic Cookie

                // RFC 5389: For example, a Binding request has class=0b00
                // (request) and method=0b000000000001 (Binding) and is encoded
                // into the first 16 bits as 0x0001.
                if (len >= 10 && buf[off + 2] == 0 && buf[off + 3] == 1)
                {
                    final byte[] magicCookie = Message.MAGIC_COOKIE;

                    b = true;
                    for (int i = 0, iEnd = magicCookie.length, j = off + 6;
                         i < iEnd;
                         i++, j++)
                    {
                        if (magicCookie[i] != buf[j])
                        {
                            b = false;
                            break;
                        }
                    }
                }
            }
        }
        return b;
    }

    /**
     * The thread which <tt>accept</tt>s TCP connections from the sockets in
     * {@link #serverSocketChannels}.
     */
    private AcceptThread acceptThread;

    /**
     * Triggers the termination of the threads of this instance.
     */
    private boolean close = false;

    /**
     * The list of transport addresses which we have found to be listening on,
     * and which may be, for example, advertises as ICE candidates.
     */
    protected final List<TransportAddress> localAddresses = new LinkedList<>();

    /**
     * Channels pending to be added to the list that {@link #readThread} reads
     * from.
     */
    private final List<SocketChannel> newChannels = new LinkedList<>();

    /**
     * The <tt>Selector</tt> used by {@link #readThread}.
     */
    private final Selector readSelector = Selector.open();

    /**
     * The thread which reads from the already <tt>accept</tt>ed sockets.
     */
    private ReadThread readThread;

    /**
     * The list of <tt>ServerSocketChannel</tt>s that we will <tt>accept</tt>
     * on.
     */
    private final List<ServerSocketChannel> serverSocketChannels
        = new LinkedList<>();

    /**
     * The object used to synchronize access to the collection of sessions that
     * the implementation of this class uses.
     */
    protected final Object sessionsSyncRoot = new Object();

    /**
     * Initializes a new <tt>TcpHarvester</tt>, which is to
     * listen on port number <tt>port</tt> on all IP addresses on all available
     * interfaces.
     *
     * @param port the port to listen on.
     * @throws IOException when {@link StackProperties#ALLOWED_ADDRESSES} or
     * {@link StackProperties#BLOCKED_ADDRESSES} contains invalid values, or
     * if an I/O error occurs.
     */
    public AbstractTcpListener(int port)
            throws IOException
    {
        this(port, Collections.list(NetworkInterface.getNetworkInterfaces()));
    }

    /**
     * Initializes a new <tt>TcpHarvester</tt>, which is to listen on port
     * number <tt>port</tt> on all the IP addresses on the specified
     * <tt>NetworkInterface</tt>s.
     *
     * @param port the port to listen on.
     * @param interfaces the interfaces to listen on.
     * @throws IOException when {@link StackProperties#ALLOWED_ADDRESSES} or
     * {@link StackProperties#BLOCKED_ADDRESSES} contains invalid values, or
     * if an I/O error occurs.
     */
    public AbstractTcpListener(int port, List<NetworkInterface> interfaces)
        throws IOException
    {
        this(getLocalAddresses(port, interfaces));
    }

    /**
     * Initializes a new <tt>TcpHarvester</tt>, which is to listen on the
     * specified list of <tt>TransportAddress</tt>es.
     *
     * @param transportAddresses the transport addresses to listen on.
     * @throws IOException when {@link StackProperties#ALLOWED_ADDRESSES} or
     * {@link StackProperties#BLOCKED_ADDRESSES} contains invalid values, or
     * if an I/O error occurs.
     */
    public AbstractTcpListener(List<TransportAddress> transportAddresses)
        throws IOException
    {
        addLocalAddresses(transportAddresses);
        init();
    }

    /**
     * Adds to {@link #localAddresses} those addresses from
     * <tt>transportAddresses</tt> which are found suitable for candidate
     * allocation.
     *
     * @param transportAddresses the list of addresses to add.
     * @throws IOException when {@link StackProperties#ALLOWED_ADDRESSES} or
     * {@link StackProperties#BLOCKED_ADDRESSES} contains invalid values.
     */
    protected void addLocalAddresses(List<TransportAddress> transportAddresses)
        throws IOException
    {
        boolean useIPv6 = !StackProperties.getBoolean(
                StackProperties.DISABLE_IPv6,
                false);
        boolean useIPv6LinkLocal = !StackProperties.getBoolean(
                StackProperties.DISABLE_LINK_LOCAL_ADDRESSES,
                false);

        // White list from the configuration
        String[] allowedAddressesStr
            = StackProperties.getStringArray(StackProperties.ALLOWED_ADDRESSES,
                                             ";");
        InetAddress[] allowedAddresses = null;

        if (allowedAddressesStr != null)
        {
            allowedAddresses = new InetAddress[allowedAddressesStr.length];
            for (int i = 0; i < allowedAddressesStr.length; i++)
            {
                allowedAddresses[i]
                    = InetAddress.getByName(allowedAddressesStr[i]);
            }
        }

        // Black list from the configuration
        String[] blockedAddressesStr
            = StackProperties.getStringArray(StackProperties.BLOCKED_ADDRESSES,
                                             ";");
        InetAddress[] blockedAddresses = null;

        if (blockedAddressesStr != null)
        {
            blockedAddresses = new InetAddress[blockedAddressesStr.length];
            for (int i = 0; i < blockedAddressesStr.length; i++)
            {
                blockedAddresses[i]
                    = InetAddress.getByName(blockedAddressesStr[i]);
            }
        }

        for (TransportAddress transportAddress : transportAddresses)
        {
            InetAddress address = transportAddress.getAddress();

            if (address.isLoopbackAddress())
            {
                //loopback again
                continue;
            }

            if (!useIPv6 && (address instanceof Inet6Address))
                continue;

            if (!useIPv6LinkLocal
                    && (address instanceof Inet6Address)
                    && address.isLinkLocalAddress())
            {
                logger.info("Not using link-local address " + address +" for"
                                    + " TCP candidates.");
                continue;
            }

            if (allowedAddresses != null)
            {
                boolean found = false;

                for (InetAddress allowedAddress : allowedAddresses)
                {
                    if (allowedAddress.equals(address))
                    {
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    logger.info("Not using " + address +" for TCP candidates, "
                                + "because it is not in the allowed list.");
                    continue;
                }
            }

            if (blockedAddresses != null)
            {
                boolean found = false;

                for (InetAddress blockedAddress : blockedAddresses)
                {
                    if (blockedAddress.equals(address))
                    {
                        found = true;
                        break;
                    }
                }
                if (found)
                {
                    logger.info("Not using " + address + " for TCP candidates, "
                                + "because it is in the blocked list.");
                    continue;
                }
            }

            // Passed all checks
            localAddresses.add(transportAddress);
        }
    }

    /**
     * Triggers the termination of the threads of this
     * <tt>MultiplexingTcpHarvester</tt>.
     */
    public void close()
    {
        close = true;
    }

    /**
     * Initializes {@link #serverSocketChannels}, creates and starts the threads
     * used by this instance.
     * @throws IOException if an I/O error occurs
     */
    protected void init()
        throws IOException
    {
        boolean bindWildcard = StackProperties.getBoolean(
                StackProperties.BIND_WILDCARD,
                false);

        // Use a set to filter out any duplicates.
        Set<InetSocketAddress> addressesToBind = new HashSet<>();

        for (TransportAddress transportAddress : localAddresses)
        {
            addressesToBind.add( new InetSocketAddress(
                bindWildcard ? null : transportAddress.getAddress(),
                transportAddress.getPort()
            ) );
        }

        for (InetSocketAddress addressToBind : addressesToBind )
        {
            addSocketChannel( addressToBind );
        }

        acceptThread = new AcceptThread();
        acceptThread.start();

        readThread = new ReadThread();
        readThread.start();
    }

    /**
     * Initializes one of the channels in {@link #serverSocketChannels},
     * @throws IOException if an I/O error occurs
     */
    private void addSocketChannel(InetSocketAddress address)
        throws IOException
    {
        ServerSocketChannel channel = MuxServerSocketChannelFactory
            .openAndBindMuxServerSocketChannel(
                            /* properties */ null,
                            address,
                            /* backlog */ 0,
                            new DatagramPacketFilter()
                            {
                                /**
                                 * {@inheritDoc}
                                 */
                                @Override
                                public boolean accept(DatagramPacket p)
                                {
                                    return isFirstDatagramPacket(p);
                                }
                            });

        serverSocketChannels.add(channel);
    }

    /**
     * Accepts a session.
     * @param socket the {@link Socket} for the session.
     * @param ufrag the local username fragment for the session.
     * @param pushback the first "datagram" (RFC4571-framed), already read from
     * the socket's stream.
     * @throws IllegalStateException
     * @throws IOException
     */
    protected abstract void acceptSession(
            Socket socket, String ufrag, DatagramPacket pushback)
        throws IOException, IllegalStateException;

    /**
     * A <tt>Thread</tt> which will accept new <tt>SocketChannel</tt>s from all
     * <tt>ServerSocketChannel</tt>s in {@link #serverSocketChannels}.
     */
    private class AcceptThread
        extends Thread
    {
        /**
         * The <tt>Selector</tt> used to select a specific
         * <tt>ServerSocketChannel</tt> which is ready to <tt>accept</tt>.
         */
        private final Selector selector;

        /**
         * Initializes a new <tt>AcceptThread</tt>.
         */
        public AcceptThread()
            throws IOException
        {
            setName("TcpHarvester AcceptThread");
            setDaemon(true);

            selector = Selector.open();
            for (ServerSocketChannel channel : serverSocketChannels)
            {
                channel.configureBlocking(false);
                channel.register(selector, SelectionKey.OP_ACCEPT);
            }
        }

        /**
         * Notifies {@link #readThread} that new channels have been added.
         */
        private void notifyReadThread()
        {
            readSelector.wakeup();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void run()
        {
            do
            {
                if (close)
                {
                    break;
                }

                IOException exception = null;
                List<SocketChannel> channelsToAdd = new LinkedList<>();
                // Allow to go on, so we can quit if closed.
                long selectTimeout = 3000;

                for (SelectionKey key : selector.keys())
                {
                    if (key.isValid())
                    {
                        SocketChannel channel;
                        boolean acceptable = key.isAcceptable();

                        try
                        {
                            channel
                                = ((ServerSocketChannel) key.channel())
                                    .accept();
                        }
                        catch (IOException ioe)
                        {
                            exception = ioe;
                            break;
                        }

                        // Add the accepted channel to newChannels to allow the
                        // 'read' thread to it up.
                        if (channel != null)
                        {
                            channelsToAdd.add(channel);
                        }
                        else if (acceptable)
                        {
                            // The SelectionKey reported the channel as
                            // acceptable but channel#accept() did not accept a
                            // non-null SocketChannel. Give the channel a little
                            // time to get its act together.
                            selectTimeout = 100;
                        }
                    }
                }
                // We accepted from all serverSocketChannels.
                selector.selectedKeys().clear();

                if (!channelsToAdd.isEmpty())
                {
                    synchronized (newChannels)
                    {
                        newChannels.addAll(channelsToAdd);
                    }
                    notifyReadThread();
                }

                if (exception != null)
                {
                    logger.info(
                            "Failed to accept a socket, which should have been"
                                + " ready to accept: " + exception);
                    break;
                }

                try
                {
                    // Allow to go on, so we can quit if closed.
                    selector.select(selectTimeout);
                }
                catch (IOException ioe)
                {
                    logger.info(
                            "Failed to select an accept-ready socket: " + ioe);
                    break;
                }
            }
            while (true);

            //now clean up and exit
            for (ServerSocketChannel serverSocketChannel : serverSocketChannels)
                closeNoExceptions(serverSocketChannel);

            try
            {
                selector.close();
            }
            catch (IOException ioe)
            {}
        }
    }

    /**
     * Contains a <tt>SocketChannel</tt> that <tt>ReadThread</tt> is reading
     * from.
     */
    private static class ChannelDesc
    {
        /**
         * The actual <tt>SocketChannel</tt>.
         */
        public final SocketChannel channel;

        /**
         * The time the channel was last found to be active.
         */
        long lastActive = System.currentTimeMillis();

        /**
         * The buffer which stores the data so far read from the channel.
         */
        ByteBuffer buffer = null;

        /**
         * Whether we had checked for initial "pseudo" SSL handshake.
         */
        boolean checkedForSSLHandshake = false;

        /**
         * Buffer to use if we had read some data in advance and want to process
         * it after next read, used when we are checking for "pseudo" SSL and
         * we haven't found some, but had read data to check for it.
         */
        byte[] preBuffered = null;

        /**
         * The value of the RFC4571 "length" field read from the channel, or
         * -1 if it hasn't been read (yet).
         */
        int length = -1;

        /**
         * Initializes a new <tt>ChannelDesc</tt> with the given channel.
         * @param channel the channel.
         */
        public ChannelDesc(SocketChannel channel)
        {
            this.channel = channel;
        }
    }

    /**
     * An <tt>IceSocketWrapper</tt> implementation which allows a
     * <tt>DatagramPacket</tt> to be pushed back and received on the first call
     * to {@link #receive(DatagramPacket)}.
     */
    protected static class PushBackIceSocketWrapper
        extends IceSocketWrapper
    {
        /**
         * The <tt>DatagramPacket</tt> which will be used on the first call to
         * {@link #receive(DatagramPacket)}.
         */
        private DatagramPacket datagramPacket;

        /**
         * The <tt>IceSocketWrapper</tt> that this instance wraps around.
         */
        private final IceSocketWrapper wrapped;

        /**
         * Initializes a new <tt>PushBackIceSocketWrapper</tt> instance that
         * wraps around <tt>wrappedWrapper</tt> and reads from
         * <tt>datagramSocket</tt> on the first call to
         * {@link #receive(DatagramPacket)}
         *
         * @param wrappedWrapper the <tt>IceSocketWrapper</tt> instance that we
         * wrap around.
         * @param datagramPacket the <tt>DatagramPacket</tt> which will be used
         * on the first call to {@link #receive(DatagramPacket)}
         */
        public PushBackIceSocketWrapper(IceSocketWrapper wrappedWrapper,
                                        DatagramPacket datagramPacket)
        {
            this.wrapped = wrappedWrapper;
            this.datagramPacket = datagramPacket;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void close()
        {
            wrapped.close();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public InetAddress getLocalAddress()
        {
            return wrapped.getLocalAddress();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int getLocalPort()
        {
            return wrapped.getLocalPort();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public SocketAddress getLocalSocketAddress()
        {
            return wrapped.getLocalSocketAddress();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public Socket getTCPSocket()
        {
            return wrapped.getTCPSocket();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public DatagramSocket getUDPSocket()
        {
            return wrapped.getUDPSocket();
        }

        /**
         * {@inheritDoc}
         *
         * On the first call to this instance reads from
         * {@link #datagramPacket}, on subsequent calls delegates to
         * {@link #wrapped}.
         */
        @Override
        public void receive(DatagramPacket p) throws IOException
        {
            if (datagramPacket != null)
            {
                int len = Math.min(p.getLength(), datagramPacket.getLength());
                System.arraycopy(datagramPacket.getData(), 0,
                                 p.getData(), 0,
                                 len);
                p.setAddress(datagramPacket.getAddress());
                p.setPort(datagramPacket.getPort());
                datagramPacket = null;
            }
            else
            {
                wrapped.receive(p);
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void send(DatagramPacket p) throws IOException
        {
            wrapped.send(p);
        }
    }

    private class ReadThread
        extends Thread
    {
        /**
         * Initializes a new <tt>ReadThread</tt>.
         *
         * @throws IOException if the selector to be used fails to open.
         */
        public ReadThread()
            throws IOException
        {
            setName("TcpHarvester ReadThread");
            setDaemon(true);
        }

        /**
         * Registers the channels from {@link #newChannels} in
         * {@link #readSelector}.
         */
        private void checkForNewChannels()
        {
            synchronized (newChannels)
            {
                for (SocketChannel channel : newChannels)
                {
                    try
                    {
                        channel.configureBlocking(false);
                        channel.register(
                                readSelector,
                                SelectionKey.OP_READ,
                                new ChannelDesc(channel));
                    }
                    catch (IOException ioe)
                    {
                        logger.info("Failed to register channel: " + ioe);
                        closeNoExceptions(channel);
                    }
                }
                newChannels.clear();
            }
        }

        /**
         * Closes any inactive channels registered with {@link #readSelector}.
         * A channel is considered inactive if it hasn't been available for
         * reading for
         * {@link MuxServerSocketChannelFactory#SOCKET_CHANNEL_READ_TIMEOUT}
         * milliseconds.
         */
        private void cleanup()
        {
            long now = System.currentTimeMillis();

            for (SelectionKey key : readSelector.keys())
            {
                // An invalid key specifies that either the channel was closed
                // (in which case we do not have to do anything else to it) or
                // that we no longer control the channel (i.e. we do not want to
                // do anything else to it). 
                if (!key.isValid())
                    continue;

                ChannelDesc channelDesc = (ChannelDesc) key.attachment();

                if (channelDesc == null)
                    continue;

                long lastActive = channelDesc.lastActive;

                if (lastActive != -1
                        && now - lastActive
                            > MuxServerSocketChannelFactory
                                .SOCKET_CHANNEL_READ_TIMEOUT)
                {
                    // De-register from the Selector.
                    key.cancel();

                    SocketChannel channel = channelDesc.channel;

                    logger.info("Read timeout for socket: " + channel.socket());

                    closeNoExceptions(channel);
                }
            }
        }

        /**
         * Tries to read, without blocking, from <tt>channel</tt> to its
         * buffer. If after reading the buffer is filled, handles the data in
         * the buffer.
         *
         * This works in three stages:
         * 1 (optional): Read a fixed-size message. If it matches the
         * hard-coded pseudo SSL ClientHello, sends the hard-coded ServerHello.
         * 2: Read two bytes as an unsigned int and interpret it as the length
         * to read in the next stage.
         * 3: Read number of bytes indicated in stage2 and try to interpret
         * them as a STUN message.
         *
         * If a datagram is successfully read it is passed on to
         * {@link #processFirstDatagram(byte[], ChannelDesc, SelectionKey)}
         *
         * @param channel the <tt>SocketChannel</tt> to read from.
         * @param key the <tt>SelectionKey</tt> associated with
         * <tt>channel</tt>, which is to be canceled in case no further
         * reading is required from the channel.
         */
        private void readFromChannel(ChannelDesc channel, SelectionKey key)
        {
            if (channel.buffer == null)
            {
                // Set up a buffer with a pre-determined size

                if (!channel.checkedForSSLHandshake && channel.length == -1)
                {
                    channel.buffer
                        = ByteBuffer.allocate(
                                GoogleTurnSSLCandidateHarvester
                                    .SSL_CLIENT_HANDSHAKE.length);
                }
                else if (channel.length == -1)
                {
                    channel.buffer = ByteBuffer.allocate(2);
                }
                else
                {
                    channel.buffer = ByteBuffer.allocate(channel.length);
                }
            }

            try
            {
                int read = channel.channel.read(channel.buffer);

                if (read == -1)
                    throw new IOException("End of stream!");
                else if (read > 0)
                    channel.lastActive = System.currentTimeMillis();

                if (!channel.buffer.hasRemaining())
                {
                    // We've filled in the buffer.
                    if (!channel.checkedForSSLHandshake)
                    {
                        byte[] bytesRead
                            = new byte[GoogleTurnSSLCandidateHarvester
                                .SSL_CLIENT_HANDSHAKE.length];

                        channel.buffer.flip();
                        channel.buffer.get(bytesRead);

                        // Set to null, so that we re-allocate it for the next
                        // stage
                        channel.buffer = null;
                        channel.checkedForSSLHandshake = true;

                        if (Arrays.equals(bytesRead,
                                          GoogleTurnSSLCandidateHarvester
                                                  .SSL_CLIENT_HANDSHAKE))
                        {
                            ByteBuffer byteBuffer = ByteBuffer.wrap(
                                    GoogleTurnSSLCandidateHarvester
                                            .SSL_SERVER_HANDSHAKE);
                            channel.channel.write(byteBuffer);
                        }
                        else
                        {
                            int fb = bytesRead[0];
                            int sb = bytesRead[1];

                            channel.length = (((fb & 0xff) << 8) | (sb & 0xff));

                            byte[] preBuffered
                                = Arrays.copyOfRange(
                                    bytesRead, 2, bytesRead.length);

                            // if we had read enough data
                            if(channel.length <= bytesRead.length - 2)
                            {
                                processFirstDatagram(
                                    preBuffered, channel, key);
                            }
                            else
                            {
                                // not enough data, store what was read
                                // and continue
                                channel.preBuffered = preBuffered;

                                channel.length -= channel.preBuffered.length;
                            }
                        }
                    }
                    else if (channel.length == -1)
                    {
                        channel.buffer.flip();

                        int fb = channel.buffer.get();
                        int sb = channel.buffer.get();

                        channel.length = (((fb & 0xff) << 8) | (sb & 0xff));

                        // Set to null, so that we re-allocate it for the next
                        // stage
                        channel.buffer = null;
                    }
                    else
                    {
                        byte[] bytesRead = new byte[channel.length];

                        channel.buffer.flip();
                        channel.buffer.get(bytesRead);

                        if(channel.preBuffered != null)
                        {
                            // will store preBuffered and currently read data
                            byte[] newBytesRead = new byte[
                                channel.preBuffered.length + bytesRead.length];

                            // copy old data
                            System.arraycopy(
                                channel.preBuffered, 0,
                                newBytesRead, 0,
                                channel.preBuffered.length);
                            // and new data
                            System.arraycopy(
                                bytesRead, 0,
                                newBytesRead, channel.preBuffered.length,
                                bytesRead.length);

                            // use that data for processing
                            bytesRead = newBytesRead;

                            channel.preBuffered = null;
                        }

                        processFirstDatagram(bytesRead, channel, key);
                    }
                }
            }
            catch (Exception e)
            {
                // The ReadThread should continue running no matter what
                // exceptions occur in the code above (we've observed exceptions
                // due to failures to allocate resources) because otherwise
                // the #newChannels list is never pruned leading to a leak of
                // sockets.
                logger.info(
                        "Failed to handle TCP socket "
                            + channel.channel.socket() + ": " + e.getMessage());
                key.cancel();
                closeNoExceptions(channel.channel);
            }
        }

        /**
         * Process the first RFC4571-framed datagram read from a socket.
         *
         * If the datagram contains a STUN Binding Request, and it has a
         * USERNAME attribute, the local &quot;ufrag&quot; is extracted from the
         * attribute value, and the socket is passed to
         * {@link #acceptSession(Socket, String, DatagramPacket)}.
         *
         * @param bytesRead bytes to be processed
         * @param channel the <tt>SocketChannel</tt> to read from.
         * @param key the <tt>SelectionKey</tt> associated with
         * <tt>channel</tt>, which is to be canceled in case no further
         * reading is required from the channel.
         * @throws IOException if the datagram does not contain s STUN Binding
         * Request with a USERNAME attribute.
         * @throws IllegalStateException if the session for the extracted
         * username fragment cannot be accepted for implementation reasons
         * (e.g. no ICE Agent with the given local ufrag is found).
         */
        private void processFirstDatagram(
            byte[] bytesRead,
            ChannelDesc channel, SelectionKey key)
            throws IOException, IllegalStateException
        {
            // Does this look like a STUN binding request?
            // What's the username?
            String ufrag
                = AbstractUdpListener.getUfrag(bytesRead,
                                               (char) 0,
                                               (char) bytesRead.length);

            if (ufrag == null)
            {
                throw new IOException("Cannot extract ufrag");
            }

            // The rest of the stack will read from the socket's
            // InputStream. We cannot change the blocking mode
            // before the channel is removed from the selector (by
            // cancelling the key)
            key.cancel();
            channel.channel.configureBlocking(true);

            // Construct a DatagramPacket from the just-read packet
            // which is to be pushed back
            DatagramPacket p
                = new DatagramPacket(bytesRead, bytesRead.length);
            Socket socket = channel.channel.socket();

            p.setAddress(socket.getInetAddress());
            p.setPort(socket.getPort());

            acceptSession(socket, ufrag, p);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void run()
        {
            do
            {
                synchronized (AbstractTcpListener.this)
                {
                    if (close)
                        break;
                }

                // clean up stale channels
                cleanup();

                checkForNewChannels();

                for (SelectionKey key : readSelector.keys())
                {
                    if (key.isValid())
                    {
                        ChannelDesc channelDesc
                            = (ChannelDesc) key.attachment();

                        readFromChannel(channelDesc, key);
                    }
                }
                // We read from all SocketChannels.
                readSelector.selectedKeys().clear();

                try
                {
                    readSelector.select(
                            MuxServerSocketChannelFactory
                                    .SOCKET_CHANNEL_READ_TIMEOUT
                                / 2);
                }
                catch (IOException ioe)
                {
                    logger.info("Failed to select a read-ready channel.");
                }
            }
            while (true);

            //we are all done, clean up.
            synchronized (newChannels)
            {
                for (SocketChannel channel : newChannels)
                {
                    closeNoExceptions(channel);
                }
                newChannels.clear();
            }

            for (SelectionKey key : readSelector.keys())
            {
                // An invalid key specifies that either the channel was closed
                // (in which case we do not have to do anything else to it) or
                // that we no longer control the channel (i.e. we do not want to
                // do anything else to it).
                if (key.isValid())
                {
                    Channel channel = key.channel();

                    if (channel.isOpen())
                        closeNoExceptions(channel);
                }
            }

            try
            {
                readSelector.close();
            }
            catch (IOException ioe)
            {}
        }
    }
}
