/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice.harvest;

import java.io.*;
import java.lang.ref.*;
import java.net.*;
import java.nio.channels.*;
import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.ice.*;
import org.ice4j.message.*;
import org.ice4j.socket.*;

/**
 * A <tt>CandidateHarvester</tt> implementation, which listens on a specified
 * list of TCP server sockets. On {@link #harvest(org.ice4j.ice.Component)}, a
 * TCP candidate with type "passive" is added for each of the server sockets.
 *
 * This instance runs two threads: {@link #acceptThread} and
 * {@link #readThread}. The 'accept' thread just accepts new <tt>Socket</tt>s
 * and passes them over to the 'read' thread. The 'read' thread reads a STUN
 * message from an accepted socket and, based on the STUN username, passes it
 * to the appropriate <tt>Component</tt>.
 *
 * @author Boris Grozev
 */
public class MultiplexingTcpHostHarvester
    extends CandidateHarvester
{
    /**
     * Our class logger.
     */
    private static final Logger logger
            = Logger.getLogger(MultiplexingTcpHostHarvester.class.getName());

    /**
     * Channels which we have failed to read from after at least
     * <tt>READ_TIMEOUT</tt> milliseconds will be considered failed and will
     * be closed.
     */
    private static final int READ_TIMEOUT = 10000;

    /**
     * The constant which specifies how often to perform purging on
     * {@link #components}.
     */
    private static final int PURGE_INTERVAL = 20;

    /**
     * The list of <tt>ServerSocketChannel</tt>s that we will <tt>accept</tt> on.
     */
    private final List<ServerSocketChannel> serverSocketChannels
            = new LinkedList<ServerSocketChannel>();

    /**
     * The list of transport addresses which we have found to be listening on,
     * and which we will advertise as candidates in
     * {@link #harvest(org.ice4j.ice.Component)}
     */
    private final List<TransportAddress> localAddresses
            = new LinkedList<TransportAddress>();

    /**
     * The thread which <tt>accept</tt>s TCP connections from the sockets in
     * {@link #serverSocketChannels}.
     */
    private AcceptThread acceptThread;

    /**
     * The thread which reads from the already <tt>accept</tt>ed sockets.
     */
    private ReadThread readThread;

    /**
     * The <tt>Selector</tt> used by {@link #readThread}.
     */
    private Selector readSelector = Selector.open();

    /**
     * Triggers the termination of the threads of this instance.
     */
    private boolean close = false;

    /**
     * Whether or not to use ssltcp.
     */
    private boolean ssltcp = false;

    /**
     * Channels pending to be added to the list that {@link #readThread} reads
     * from.
     */
    private final List<SocketChannel> newChannels
            = new LinkedList<SocketChannel>();

    /**
     * Maps a local "ufrag" to the single <tt>Component</tt> instance with that
     * "ufrag".
     *
     * We only keep weak references, because we do not want to prevent
     * <tt>Component</tt>s from being freed.
     */
    private final Map<String, WeakReference<Component>> components
            = new HashMap<String, WeakReference<Component>>();

    /**
     * A counter used to decide when to purge {@link #components}.
     */
    private int purgeCounter = 0;

    /**
     * Maps a public address to a local address.
     */
    private final Map<InetAddress, InetAddress> mappedAddresses
            = new HashMap<InetAddress, InetAddress>();

    /**
     * Sets of additional ports, for which server reflexive candidates will be
     * added.
     */
    private Set<Integer> mappedPorts = new HashSet<Integer>();

    /**
     * Initializes a new <tt>MultiplexingTcpHostHarvester</tt>, which is to
     * listen on port number <tt>port</tt> on all IP addresses on all
     * available interfaces.
     *
     * @param port the port to listen on.
     */
    public MultiplexingTcpHostHarvester(int port)
        throws IOException
    {
        this(port,
             Collections.list(NetworkInterface.getNetworkInterfaces()),
             false);
    }

    /**
     * Initializes a new <tt>MultiplexingTcpHostHarvester</tt>, which is to
     * listen on port number <tt>port</tt> on all IP addresses on all
     * available interfaces.
     *
     * @param port the port to listen on.
     * @param ssltcp whether to use ssltcp or not.
     */
    public MultiplexingTcpHostHarvester(int port, boolean ssltcp)
            throws IOException
    {
        this(port,
             Collections.list(NetworkInterface.getNetworkInterfaces()),
             ssltcp);
    }

    /**
     * Initializes a new <tt>MultiplexingTcpHostHarvester</tt>, which is to
     * listen on the specified list of <tt>TransportAddress</tt>es.
     *
     * @param transportAddresses the transport addresses to listen on.
     * @param ssltcp whether to use ssltcp or not.
     */
    public MultiplexingTcpHostHarvester(
            List<TransportAddress> transportAddresses,
            boolean ssltcp)
        throws IOException
    {
        this.ssltcp = ssltcp;
        addLocalAddresses(transportAddresses);
        init();
    }

    /**
     * Initializes a new <tt>MultiplexingTcpHostHarvester</tt>, which is to
     * listen on the specified list of <tt>TransportAddress</tt>es.
     *
     * @param transportAddresses the transport addresses to listen on.
     */
    public MultiplexingTcpHostHarvester(
            List<TransportAddress> transportAddresses)
            throws IOException
    {
        this(transportAddresses, false);
    }

    /**
     * Initializes a new <tt>MultiplexingTcpHostHarvester</tt>, which is to
     * listen on port number <tt>port</tt> on all the IP addresses on the
     * specified <tt>NetworkInterface</tt>s.
     *
     * @param port the port to listen on.
     * @param interfaces the interfaces to listen on.
     */
    public MultiplexingTcpHostHarvester(int port,
                                        List<NetworkInterface> interfaces,
                                        boolean ssltcp)
        throws IOException
    {
        this.ssltcp = ssltcp;
        addLocalAddresses(getLocalAddresses(port, interfaces));
        init();
    }

    /**
     * Initializes {@link #serverSocketChannels}, creates and starts the threads
     * used by this instance.
     */
    private void init()
            throws IOException
    {
        for (TransportAddress transportAddress : localAddresses)
        {
            ServerSocketChannel channel = ServerSocketChannel.open();
            ServerSocket socket = channel.socket();
            socket.bind(
                    new InetSocketAddress(transportAddress.getAddress(),
                                          transportAddress.getPort()));
            serverSocketChannels.add(channel);
        }

        acceptThread = new AcceptThread();
        acceptThread.start();

        readThread = new ReadThread();
        readThread.start();
    }

    /**
     * Returns a list of all addresses on the interfaces in <tt>interfaces</tt>
     * which are found suitable for candidate allocations (are not loopback,
     * are up, and are allowed by the configuration.
     *
     * @param port the port to use.
     * @param interfaces the list of interfaces to use.
     */
    private List<TransportAddress> getLocalAddresses(
            int port,
            List<NetworkInterface> interfaces)
        throws IOException

    {
        List<TransportAddress> addresses
                = new LinkedList<TransportAddress>();

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

                TransportAddress transportAddress
                    = new TransportAddress(addr,
                                           port,
                                           Transport.TCP);
                addresses.add(transportAddress);
            }
        }

        return addresses;
    }

    /**
     * Adds to {@link #localAddresses} those addresses from
     * <tt>transportAddresses</tt> which are found suitable for candidate
     * allocation.
     *
     * @param transportAddresses the list of addresses to add.
     */
    private void addLocalAddresses(List<TransportAddress> transportAddresses)
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
     * Returns the <tt>Component</tt> instance, if any, for a given local
     * "ufrag".
     * @param localUfrag the local "ufrag"
     * @return the <tt>Component</tt> instance, if any, for a given local
     * "ufrag".
     */
    private Component getComponent(String localUfrag)
    {
        synchronized (components)
        {
            WeakReference<Component> wr = components.get(localUfrag);

            if (wr != null)
            {
                Component component = wr.get();
                if (component == null)
                {
                    components.remove(localUfrag);
                }

                return component;
            }
            return null;
        }
    }

    /**
     * {@inheritDoc}
     *
     * Saves a (weak) reference to <tt>Component</tt>, so that it can be
     * notified if/when a socket for one of it <tt>LocalCandidate</tt>s is
     * accepted.
     *
     * This method does not perform any network operations and should return
     * quickly.
     */
    @Override
    public Collection<LocalCandidate> harvest(Component component)
    {
        IceMediaStream stream = component.getParentStream();
        Agent agent = stream.getParentAgent();
        if (stream.getComponentCount() != 1 || agent.getStreamCount() != 1)
        {
            /*
             * MultiplexingTcpHostHarvester only works with streams with a
             * single component, and agents with a single stream. This is
             * because we use the local "ufrag" to de-multiplex the accept()-ed
             * sockets between the known components.
             */
            throw new IllegalStateException("More than one Component for an "
                                            + "Agent, cannot harvest.");
        }

        List<LocalCandidate> candidates = createLocalCandidates(component);
        for (LocalCandidate candidate : candidates)
            component.addLocalCandidate(candidate);


        synchronized (components)
        {
            components.put(agent.getLocalUfrag(),
                           new WeakReference<Component>(component));
            purgeComponents();
        }

        return candidates;
    }

    /**
     * Removes entries from {@link #components} for which the
     * <tt>WeakReference</tt> has been cleared.
     */
    private void purgeComponents()
    {
        purgeCounter += 1;
        if (purgeCounter % PURGE_INTERVAL == 0)
        {
            List<String> toRemove = new LinkedList<String>();
            synchronized (components)
            {
                for (Map.Entry<String, WeakReference<Component>> entry
                        : components.entrySet())
                {
                    WeakReference<Component> wr = entry.getValue();
                    if (wr == null || wr.get() == null)
                        toRemove.add(entry.getKey());
                }

                for (String key : toRemove)
                    components.remove(key);
            }
        }
    }

    /**
     * Creates and returns the list of <tt>LocalCandidate</tt>s which are to be added
     * by this <tt>MultiplexingTcpHostHarvester</tt>to a specific
     * <tt>Component</tt>.
     *
     * @param component the <tt>Component</tt> for which to create candidates.
     * @return the list of <tt>LocalCandidate</tt>s which are to be added
     * by this <tt>MultiplexingTcpHostHarvester</tt>to a specific
     * <tt>Component</tt>.
     */
    private List<LocalCandidate> createLocalCandidates(Component component)
    {
        List<TcpHostCandidate> hostCandidates
                = new LinkedList<TcpHostCandidate>();
        // Add the host candidates for the addresses we really listen on
        for (TransportAddress transportAddress : localAddresses)
        {
            TcpHostCandidate candidate
                    = new TcpHostCandidate(transportAddress, component);
            candidate.setTcpType(CandidateTcpType.PASSIVE);
            if (ssltcp)
                candidate.setSSL(true);

            hostCandidates.add(candidate);
        }

        // Add srflx candidates for any mapped addresses
        List<LocalCandidate> mappedCandidates
                = new LinkedList<LocalCandidate>();
        for (Map.Entry<InetAddress, InetAddress> mapping
                : mappedAddresses.entrySet())
        {
            InetAddress localAddress = mapping.getValue();
            for (TcpHostCandidate base : hostCandidates)
            {
                if (localAddress
                        .equals(base.getTransportAddress().getAddress()))
                {
                    InetAddress publicAddress = mapping.getKey();
                    ServerReflexiveCandidate mappedCandidate
                        = new ServerReflexiveCandidate(
                            new TransportAddress(publicAddress,
                                                 base.getTransportAddress()
                                                     .getPort(),
                                                 Transport.TCP),
                            base,
                            base.getStunServerAddress(),
                            CandidateExtendedType.STATICALLY_MAPPED_CANDIDATE);
                    if (base.isSSL())
                        mappedCandidate.setSSL(true);

                    mappedCandidates.add(mappedCandidate);
                }
            }
        }

        // Add srflx candidates for mapped ports
        List<LocalCandidate> portMappedCandidates
                = new LinkedList<LocalCandidate>();
        for (TcpHostCandidate base : hostCandidates)
        {
            for (Integer port : mappedPorts)
            {
                ServerReflexiveCandidate portMappedCandidate
                    = new ServerReflexiveCandidate(
                        new TransportAddress(
                            base.getTransportAddress().getAddress(),
                            port,
                            Transport.TCP),
                        base,
                        base.getStunServerAddress(),
                        CandidateExtendedType.STATICALLY_MAPPED_CANDIDATE);
                if (base.isSSL())
                    portMappedCandidate.setSSL(true);

                portMappedCandidates.add(portMappedCandidate);
            }
        }
        // Mapped ports for mapped addresses
        for (LocalCandidate mappedCandidate : mappedCandidates)
        {
            TcpHostCandidate base = (TcpHostCandidate) mappedCandidate.getBase();
            for (Integer port : mappedPorts)
            {
                ServerReflexiveCandidate portMappedCandidate
                        = new ServerReflexiveCandidate(
                        new TransportAddress(
                                mappedCandidate.getTransportAddress()
                                        .getAddress(),
                                port,
                                Transport.TCP),
                        base,
                        base.getStunServerAddress(),
                        CandidateExtendedType.STATICALLY_MAPPED_CANDIDATE);
                if (base.isSSL())
                    portMappedCandidate.setSSL(true);

                portMappedCandidates.add(portMappedCandidate);
            }
        }

        LinkedList<LocalCandidate> allCandidates
                = new LinkedList<LocalCandidate>();
        allCandidates.addAll(hostCandidates);
        allCandidates.addAll(mappedCandidates);
        allCandidates.addAll(portMappedCandidates);
        return allCandidates;
    }

    /**
     * Adds port as an additional port. When harvesting, additional server
     * reflexive candidates will be added with this port.
     * @param port the port to add.
     */
    public void addMappedPort(int port)
    {
        mappedPorts.add(port);
    }

    /**
     * Adds a mapping between <tt>publicAddress</tt> and <tt>localAddress</tt>.
     * This means that on harvest, along with any host candidates that have
     * <tt>publicAddress</tt>, a server reflexive candidate will be added
     * (with the same port as the host candidate).
     *
     * @param publicAddress the public address.
     * @param localAddress the local address.
     */
    public void addMappedAddress(InetAddress publicAddress,
                                 InetAddress localAddress)
    {
        mappedAddresses.put(publicAddress, localAddress);
    }

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
         * The channel to which this <tt>AcceptThread</tt> will write when a
         * new socket has been <tt>accept</tt>ed in order to notify
         * {@link #readThread}.
         */

        /**
         * Initializes a new <tt>AcceptThread</tt>.
         */
        private AcceptThread()
            throws IOException
        {
            setName("MultiplexingTcpHostHarvester AcceptThread");

            selector = Selector.open();
            for (ServerSocketChannel channel : serverSocketChannels)
            {
                channel.configureBlocking(false);
                channel.register(selector, SelectionKey.OP_ACCEPT);
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void run()
        {
            while (true)
            {
                int readyChannels;
                if (close)
                {
                    break;
                }

                try
                {
                    // Allow to go on, so we can quit if closed
                    readyChannels = selector.select(3000);
                }
                catch (IOException ioe)
                {
                    logger.info("Failed to select an accept-ready socket: "
                                    + ioe);
                    break;
                }

                if (readyChannels > 0)
                {
                    synchronized (newChannels)
                    {
                    }
                    IOException exception = null;
                    List<SocketChannel> channelsToAdd
                            = new LinkedList<SocketChannel>();

                    for (SelectionKey key : selector.selectedKeys())
                    {
                        SocketChannel channel;
                        if (key.isAcceptable())
                        {
                            try
                            {
                                channel = ((ServerSocketChannel)
                                    key.channel()).accept();
                            }
                            catch (IOException ioe)
                            {
                                exception = ioe;
                                break;
                            }

                            // Add the accepted socket to newChannels, so
                            // the 'read' thread can pick it up.
                            channelsToAdd.add(channel);
                        }
                    }
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
                        logger.info("Failed to accept a socket, which"
                                        + "should have been ready to accept: "
                                        + exception);
                        break;
                    }
                }
            } // while(true)

            //now clean up and exit
            for (ServerSocketChannel serverSocketChannel : serverSocketChannels)
            {
                try
                {
                    serverSocketChannel.close();
                }
                catch (IOException ioe)
                {
                }
            }

            try
            {
                selector.close();
            }
            catch (IOException ioe)
            {}

        }

        /**
         * Notifies {@link #readThread} that new channels have been added to
         */
        private void notifyReadThread()
        {
            readSelector.wakeup();
        }
    }

    private class ReadThread
        extends Thread
    {
        /**
         * Contains the <tt>SocketChanel</tt>s that we are currently reading
         * from, mapped to the time they were initially added.
         */
        private final Map<SocketChannel, Long> channels
                = new HashMap<SocketChannel, Long>();

        /**
         * <tt>Selector</tt> used to detect when one of {@link #channels} is
         * ready to be read from.
         */
        private final Selector selector;

        /**
         * The channel on which we will be notified when new channels are
         * available in {@link #newChannels}.
         */

        /**
         * Used in {@link #cleanup()}, defined here to avoid allocating on
         * every invocation.
         */
        private final List<SocketChannel> toRemove
                = new LinkedList<SocketChannel>();

        /**
         * Initializes a new <tt>ReadThread</tt>.
         * @throws IOException if the selector to be used fails to open.
         */
        private ReadThread()
                throws IOException
        {
            setName("MultiplexingTcpHostHarvester ReadThread");
            selector = MultiplexingTcpHostHarvester.this.readSelector;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void run()
        {
            Set<SelectionKey> selectedKeys;
            int readyChannels = 0;
            SelectableChannel selectedChannel;

            while (true)
            {
                synchronized (MultiplexingTcpHostHarvester.this)
                {
                    if (close)
                        break;
                }

                // clean up stale channels
                cleanup();

                checkForNewChannels();

                try
                {
                    readyChannels = selector.select(READ_TIMEOUT / 2);
                }
                catch (IOException ioe)
                {
                    logger.info("Failed to select a read-ready channel.");
                }

                if (readyChannels > 0)
                {
                    selectedKeys = selector.selectedKeys();
                    for (SelectionKey key : selectedKeys)
                    {
                        if (key.isReadable())
                        {
                            selectedChannel = key.channel();
                            key.cancel();

                            readFromChannel((SocketChannel) selectedChannel);
                            channels.remove(selectedChannel);
                        }
                    }
                    selectedKeys.clear();
                }
            } //while(true)

            //we are all done, clean up.
            synchronized (newChannels)
            {
                for (SocketChannel channel : newChannels)
                {
                    try
                    {
                        channel.close();
                    }
                    catch (IOException ioe)
                    {}
                }
                newChannels.clear();
            }

            for (SocketChannel channel : channels.keySet())
            {
                try
                {
                    channel.close();
                }
                catch (IOException ioe)
                {}
            }

            try
            {
                selector.close();
            }
            catch (IOException ioe)
            {}
        }

        /**
         * Checks {@link #channels} for channels which have been added over
         * {@link #READ_TIMEOUT} milliseconds ago and closes them.
         */
        private void cleanup()
        {
            long now = System.currentTimeMillis();
            toRemove.clear();

            for (Map.Entry<SocketChannel, Long> entry : channels.entrySet())
            {
                if (now - entry.getValue() > READ_TIMEOUT)
                {
                    SocketChannel channel = entry.getKey();

                    toRemove.add(channel);
                    logger.info("Read timeout for socket: " + channel);

                    try
                    {
                        channel.close();
                    }
                    catch (IOException ioe)
                    {
                        logger.info("Failed to close channel: " + ioe);
                    }

                }
            }

            for (SocketChannel channel : toRemove)
            {
                channels.remove(channel);
            }
        }

        /**
         * Tries to read a STUN message from a specific <tt>SocketChannel</tt>
         * and handles the channel accordingly.
         *
         * If a STUN message is successfully read, and it contains a USERNAME
         * attribute, the local "ufrag" is extracted from the attribute value
         * and the socket is passed on to the <tt>Component</tt> that
         * this <tt>MultiplexingTcpHostHarvester</tt> has associated with that
         * "ufrag".
         * @param channel the <tt>SocketChannel</tt> to read from.
         */
        private void readFromChannel(SocketChannel channel)
        {
            try
            {
                // re-enable blocking mode, so that we can read from the
                // socket's input stream
                channel.configureBlocking(true);

                Socket socket = channel.socket();
                InputStream inputStream = socket.getInputStream();

                // If we use ssltcp we wait for a pseudo-ssl handshake from the
                // client.
                if (ssltcp)
                {
                    byte[] buf
                            = new byte[GoogleTurnSSLCandidateHarvester
                                            .SSL_CLIENT_HANDSHAKE.length];

                    inputStream.read(buf);
                    if (Arrays.equals(buf,
                                      GoogleTurnSSLCandidateHarvester
                                          .SSL_CLIENT_HANDSHAKE))
                    {
                        socket.getOutputStream().write(
                            GoogleTurnSSLCandidateHarvester
                                .SSL_SERVER_HANDSHAKE);
                    }
                    else
                    {
                        throw new ReadThreadException(
                            "Expected a pseudo ssl handshake, didn't get one.");
                    }
                }

                // read an RFC4571 frame into datagramPacket

                // TODO refactor so that:
                // 1. We don't block
                // 2. We know the length of the buffer to allocate
                DatagramPacket datagramPacket
                        = new DatagramPacket(new byte[1500],1500);
                DelegatingSocket.receiveFromNetwork(
                        datagramPacket,
                        inputStream,
                        socket.getInetAddress(),
                        socket.getPort());

                // Does this look like a STUN binding request?
                // What's the username?
                Message stunMessage
                        = Message.decode(datagramPacket.getData(),
                                         (char) datagramPacket.getOffset(),
                                         (char) datagramPacket.getLength());

                if (stunMessage.getMessageType() != Message.BINDING_REQUEST)
                    throw new ReadThreadException("Not a binding request");

                UsernameAttribute usernameAttribute
                        = (UsernameAttribute)
                        stunMessage.getAttribute(Attribute.USERNAME);
                if (usernameAttribute == null)
                    throw new ReadThreadException(
                            "No USERNAME attribute present.");

                String usernameString
                        = new String(usernameAttribute.getUsername());
                String localUfrag = usernameString.split(":")[0];
                Component component = getComponent(localUfrag);
                if (component == null)
                    throw new ReadThreadException("No component found.");


                //phew, finally
                handSocketToComponent(socket, component, datagramPacket);
            }
            catch (IOException e)
            {
                logger.info("Failed to read from socket: " + e);
            }
            catch (StunException e)
            {
                logger.info("Failed to read from socket: " + e);
            }
            catch (ReadThreadException e)
            {
                logger.info("Failed to read from socket: " + e);
            }
            finally
            {
                channels.remove(channel);
            }
        }

        /**
         * Makes <tt>socket</tt> available to <tt>component</tt> and pushes
         * back <tt>datagramPacket</tt> into the STUN socket.
         * @param socket the <tt>Socket</tt>.
         * @param component the <tt>Component</tt>.
         * @param datagramPacket the <tt>DatagramPacket</tt> to push back.
         */
        private void handSocketToComponent(Socket socket,
                                           Component component,
                                           DatagramPacket datagramPacket)
        {
            IceProcessingState state
                    = component.getParentStream().getParentAgent().getState();
            if (!IceProcessingState.WAITING.equals(state)
                    && !IceProcessingState.RUNNING.equals(state))
            {
                logger.info("Not adding a socket to an ICE agent with state "
                                + state);
                return;
            }

            // Socket to add to the candidate
            IceSocketWrapper candidateSocket = null;

            // STUN-only filtered socket to add to the StunStack
            IceSocketWrapper stunSocket = null;

            try
            {
                MultiplexingSocket multiplexing = new MultiplexingSocket(socket);
                candidateSocket = new IceTcpSocketWrapper(multiplexing);

                stunSocket
                    = new IceTcpSocketWrapper(
                        multiplexing.getSocket(new StunDatagramPacketFilter()));
                stunSocket
                    = new PushBackIceSocketWrapper(stunSocket, datagramPacket);
            }
            catch (IOException ioe)
            {
                logger.info("Failed to create sockets: " + ioe);
            }

            TcpHostCandidate candidate = findCandidate(component, socket);
            if (candidate != null)
            {
                component.getParentStream().getParentAgent()
                        .getStunStack().addSocket(stunSocket);
                candidate.addSocket(candidateSocket);

                // the socket is not our responsibility anymore. It is up to
                // the candidate/component to close/free it.
            }
            else
            {
                logger.info("Failed to find the local candidate for socket: "
                                    + socket);
                try
                {
                    socket.close();
                }
                catch (IOException ioe)
                {}
            }

        }

        /**
         * Searches among the local candidates of <tt>Component</tt> for a
         * <tt>TcpHostCandidate</tt> with the same transport address as the
         * local transport address of <tt>socket</tt>.
         *
         * We expect to find such a candidate, which has been added by this
         * <tt>MultiplexingTcpHostHarvester</tt> while harvesting.
         *
         * @param component the <tt>Component</tt> to search.
         * @param socket the <tt>Socket</tt> to match the local transport
         * address of.
         * @return a <tt>TcpHostCandidate</tt> among the local candidates of
         * <tt>Component</tt> with the same transport address as the local
         * address of <tt>Socket</tt>, or <tt>null</tt> if no such candidate
         * exists.
         */
        private TcpHostCandidate findCandidate(Component component, Socket socket)
        {
            InetAddress localAddress = socket.getLocalAddress();
            int localPort = socket.getLocalPort();

            for (LocalCandidate candidate : component.getLocalCandidates())
            {
                TransportAddress transportAddress
                        = candidate.getTransportAddress();
                if (candidate instanceof TcpHostCandidate
                        && Transport.TCP.equals(transportAddress.getTransport())
                        && localPort == transportAddress.getPort()
                        && localAddress.equals(transportAddress.getAddress()))
                {
                    return (TcpHostCandidate) candidate;
                }
            }
            return null;
        }

        /**
         * Adds the channels from {@link #newChannels} to {@link #channels}
         * and registers them in {@link #selector}.
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
                        channel.register(selector, SelectionKey.OP_READ);
                    }
                    catch (IOException ioe)
                    {
                        logger.info("Failed to register channel: " + ioe);
                        try
                        {
                            channel.close();
                        }
                        catch (IOException ioe2)
                        {}
                    }

                    channels.put(channel, System.currentTimeMillis());
                }
                newChannels.clear();
            }
        }
    }

    /**
     * An exception used internally by
     * {@link org.ice4j.ice.harvest.MultiplexingTcpHostHarvester.ReadThread}.
     */
    @SuppressWarnings("serial")
    private class ReadThreadException
        extends Exception
    {
        private ReadThreadException(String s)
        {
            super(s);
        }
    }

    /**
     * An <tt>IceSocketWrapper</tt> implementation which allows a
     * <tt>DatagramPacket</tt> to be pushed back and received on the first
     * call to {@link #receive(java.net.DatagramPacket)}
     */
    private static class PushBackIceSocketWrapper
        extends IceSocketWrapper
    {
        /**
         * The <tt>IceSocketWrapper</tt> that this instance wraps around.
         */
        private IceSocketWrapper wrapped;

        /**
         * The <tt>DatagramPacket</tt> which will be used on the first call
         * to {@link #receive(java.net.DatagramPacket)}.
         */
        private DatagramPacket datagramPacket;

        /**
         * Initializes a new <tt>PushBackIceSocketWrapper</tt> instance that
         * wraps around <tt>wrappedWrapper</tt> and reads from
         * <tt>datagramSocket</tt> on the first call to
         * {@link #receive(java.net.DatagramPacket)}
         *
         * @param wrappedWrapper the <tt>IceSocketWrapper</tt> instance that we
         * wrap around.
         * @param datagramPacket the <tt>DatagramPacket</tt> which will be used
         * on the first call to {@link #receive(java.net.DatagramPacket)}
         */
        private PushBackIceSocketWrapper(IceSocketWrapper wrappedWrapper,
                                         DatagramPacket datagramPacket)
        {
            this.wrapped = wrappedWrapper;
            this.datagramPacket = datagramPacket;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void send(DatagramPacket p) throws IOException
        {
            wrapped.send(p);
        }

        /**
         * {@inheritDoc}
         *
         * On the first call to this instance reads from {@link #datagramPacket},
         * on subsequent calls delegates to {@link #wrapped}.
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
    }

}
