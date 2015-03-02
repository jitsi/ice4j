/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice.harvest;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.ice.*;
import org.ice4j.message.*;
import org.ice4j.socket.*;
import org.ice4j.stack.*;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

/**
 * A harvester implementation which binds to a single <tt>DatagramSocket</tt>
 * and provides local candidates of type "host". It runs a thread
 * ({@link #thread}) which perpetually reads from the socket.
 *
 * When {@link #harvest(org.ice4j.ice.Component)} is called, this harvester
 * creates and adds to the component a
 * {@link org.ice4j.ice.harvest.SinglePortUdpHarvester.MyCandidate} instance,
 * and associates the component's local username fragment (ufrag) with this
 * candidate.
 *
 * When a datagram from an unknown source is received, it is parsed as a STUN
 * Binding Request, and if it has a USERNAME attribute, its ufrag is extracted.
 * If this ufrag is associated with a candidate of this harvester, a new socket
 * is created and added to the candidate, and the remote address of the datagram
 * is associated with this socket. This mapping is then used to de-multiplex
 * received datagrams based on their remote address.
 *
 * @author Boris Grozev
 */
public class SinglePortUdpHarvester
        extends CandidateHarvester
{
    /**
     * Our class logger.
     */
    private static final Logger logger
            = Logger.getLogger(SinglePortUdpHarvester.class.getName());

    /**
     * The size for newly allocated <tt>Buffer</tt> instances. This limits the
     * maximum size of datagrams we can receive.
     *
     * XXX should we increase this in case of other MTUs, or set it dynamically
     * according to the available network interfaces?
     */
    private static final int BUFFER_SIZE
        = /* assumed MTU */ 1500 - /* IPv4 header */ 20 - /* UDP header */ 8;

    /**
     * The number of <tt>Buffer</tt> instances to keep in {@link #pool}.
     */
    private static final int POOL_SIZE = 256;

    /**
     * Creates a new <tt>SinglePortUdpHarvester</tt> instance for each allowed
     * IP address found on each allowed network interface, with the given port.
     *
     * @param port the UDP port number to use.
     * @return the list of created <tt>SinglePortUdpHarvester</tt>s.
     */
    public static List<SinglePortUdpHarvester>
        createHarvesters(int port)
    {
        List<SinglePortUdpHarvester> harvesters
           = new LinkedList<SinglePortUdpHarvester>();

        List<TransportAddress> addresses = new LinkedList<TransportAddress>();

        try
        {
            for (NetworkInterface iface
                    : Collections.list(NetworkInterface.getNetworkInterfaces()))
            {
                if (NetworkUtils.isInterfaceLoopback(iface)
                        || !NetworkUtils.isInterfaceUp(iface)
                        || !HostCandidateHarvester.isInterfaceAllowed(iface))
                {
                    continue;
                }

                Enumeration<InetAddress> ifaceAddresses
                        = iface.getInetAddresses();
                while (ifaceAddresses.hasMoreElements())
                {
                    InetAddress address = ifaceAddresses.nextElement();

                    addresses.add(
                        new TransportAddress(address, port, Transport.UDP));
                }
            }
        }
        catch (SocketException se)
        {
            logger.info("Failed to get network interfaces: " + se);
        }

        for (TransportAddress address : addresses)
        {
            try
            {
                harvesters.add(new SinglePortUdpHarvester(address));
            }
            catch (IOException ioe)
            {
                logger.info("Failed to create SinglePortUdpHarvester for "
                                + "address " + address + ": " + ioe);
            }
        }

        return harvesters;
    }

    /**
     * The map which keeps the known remote addresses and their associated
     * candidateSockets.
     * {@link #thread} is the only thread which adds new entries, while
     * other threads remove entries when candidates are freed.
     */
    private final Map<SocketAddress, MySocket> sockets
            = new ConcurrentHashMap<SocketAddress, MySocket>();

    /**
     * The map which keeps all currently active <tt>Candidate</tt>s created by
     * this harvester. The keys are the local username fragments (ufrags) of
     * the components for which the candidates are harvested.
     */
    private final Map<String, MyCandidate> candidates
            = new ConcurrentHashMap<String, MyCandidate>();

    /**
     * A pool of <tt>Buffer</tt> instances used to avoid creating of new java
     * objects.
     */
    private final ArrayBlockingQueue<Buffer> pool
        = new ArrayBlockingQueue<Buffer>(POOL_SIZE);

    /**
     * The local address that this harvester is bound to.
     */
    private final TransportAddress localAddress;

    /**
     * The "main" socket that this harvester reads from.
     */
    private final DatagramSocket socket;

    /**
     * The thread reading from {@link #socket}.
     */
    private final Thread thread;

    /**
     * Initializes a new <tt>SinglePortUdpHarvester</tt> instance which is to
     * bind on the specified local address.
     * @param localAddress the address to bind to.
     * @throws IOException if initialization fails.
     */
    public SinglePortUdpHarvester(TransportAddress localAddress)
        throws IOException
    {
        this.localAddress = localAddress;
        this.socket = new DatagramSocket(localAddress);
        logger.info("Initialized SinglePortUdpHarvester with address "
                            + localAddress);

        thread = new Thread()
        {
            @Override
            public void run()
            {
                SinglePortUdpHarvester.this.runInHarvesterThread();
            }
        };

        thread.setName(SinglePortUdpHarvester.class.getName() + " thread");
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Perpetually reads datagrams from {@link #socket} and handles them
     * accordingly.
     *
     * It is important that this blocks are little as possible (except on
     * socket.receive(), of course),  because it could potentially delay the
     * reception of both ICE and media packets for the whole application.
     */
    private void runInHarvesterThread()
    {
        Buffer buf;
        DatagramPacket pkt = null;
        Component component;
        MyCandidate candidate;
        MySocket destinationSocket;
        InetSocketAddress remoteAddress;

        while (true)
        {
            // TODO: implement stopping the thread with a switch?

            buf = getFreeBuffer();

            if (pkt == null)
                pkt = new DatagramPacket(buf.buffer, 0, buf.buffer.length);
            else
                pkt.setData(buf.buffer, 0, buf.buffer.length);

            try
            {
                socket.receive(pkt);
            }
            catch (IOException ioe)
            {
                logger.severe("Failed to receive from socket: " + ioe);
                break;
            }
            buf.len = pkt.getLength();


            remoteAddress = (InetSocketAddress) pkt.getSocketAddress();
            destinationSocket = sockets.get(remoteAddress);
            if (destinationSocket != null)
            {
                //make 'pkt' available for reading through destinationSocket
                destinationSocket.addBuffer(buf);
            }
            else
            {
                // Packet from an unknown source. Is it a STUN Binding Request?
                String ufrag = getUfrag(buf.buffer, 0, buf.len);
                if (ufrag == null)
                {
                    // Not a STUN Binding Request or doesn't have a valid
                    // USERNAME attribute. Drop it.
                    continue;
                }

                candidate = candidates.get(ufrag);
                component
                    = candidate == null ? null : candidate.getParentComponent();
                if (component != null)
                {
                    // This is a STUN Binding Request destined for this
                    // specific Candidate/Component/Agent.

                    try
                    {
                        // 1. Create a socket for this remote address
                        MySocket newSocket = new MySocket(remoteAddress);

                        // 2. Set-up de-multiplexing for future datagrams
                        // with this address to this socket.
                        sockets.put(remoteAddress, newSocket);

                        // 3. Let the candidate and its STUN stack no about the
                        // new socket.
                        candidate.addSocket(newSocket, remoteAddress);

                        // 4. Add the original datagram to the new socket.
                        newSocket.addBuffer(buf);
                    }
                    catch (SocketException se)
                    {
                        logger.info("Could not create a socket: " + se);
                        continue;
                    }
                    catch (IOException ioe)
                    {
                        logger.info("Failed to handle new socket: " + ioe);
                        continue;
                    }
                }
                else
                {
                    // A STUN Binding Request with an unknown USERNAME. Drop it.
                    continue;
                }
            }
        }

        // TODO we are all done, clean up.
    }

    /**
     * Gets an unused <tt>Buffer</tt> instance, creating it if necessary.
     * @return  an unused <tt>Buffer</tt> instance, creating it if necessary.
     */
    private Buffer getFreeBuffer()
    {
        Buffer buf = pool.poll();
        if (buf == null)
        {
            buf = new Buffer(new byte[BUFFER_SIZE], 0);
        }

        return buf;
    }

    /**
     * Tries to parse the bytes in <tt>buf</tt> at offset <tt>off</tt> (and
     * length <tt>len</tt>) and a STUN Binding Request message. If successful,
     * looks for a USERNAME attribute and returns the local username fragment
     * part (see RFC5245 Section 7.1.2.3).
     * In case of any failure returns <tt>null</tt>.
     *
     * @param buf the bytes.
     * @param off the offset.
     * @param len the length.
     * @return the local ufrag from the USERNAME attribute of the STUN message
     * contained in <tt>buf</tt>, or <tt>null</tt>.
     */
    private String getUfrag(byte[] buf, int off, int len)
    {
        try
        {
            Message stunMessage
                    = Message.decode(buf,
                                     (char) off,
                                     (char) len);

            if (stunMessage.getMessageType()
                    != Message.BINDING_REQUEST)
            {
                return null;
            }

            UsernameAttribute usernameAttribute
                    = (UsernameAttribute)
                    stunMessage.getAttribute(Attribute.USERNAME);
            if (usernameAttribute == null)
                return null;

            String usernameString
                    = new String(usernameAttribute.getUsername());
            return usernameString.split(":")[0];
        }
        catch (Exception e)
        {
            // Catch everything. We are going to log, and then drop the packet
            // anyway.
            logger.info("Failed to extract local ufrag: " + e);
        }

        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<LocalCandidate> harvest(Component component)
    {
        IceMediaStream stream = component.getParentStream();
        Agent agent = stream.getParentAgent();
        String ufrag = agent.getLocalUfrag();

        if (stream.getComponentCount() != 1 || agent.getStreamCount() != 1)
        {
            /*
             * SinglePortUdpHarvester only works with streams with a
             * single component, and agents with a single stream. This is
             * because we use the local "ufrag" from an incoming STUN packet
             * to setup de-multiplexing based on remote transport address.
             */
            throw new IllegalStateException(
                    "More than one Component for an Agent, cannot harvest.");
        }

        MyCandidate candidate = new MyCandidate(component, ufrag);

        candidates.put(ufrag, candidate);
        component.addLocalCandidate(candidate);

        return new ArrayList<LocalCandidate>(Arrays.asList(candidate));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isHostHarvester()
    {
        return true;
    }

    /**
     * Implements a <tt>DatagramSocket</tt> for the purposes of a specific
     * <tt>MyCandidate</tt>.
     *
     * It is not bound to a specific port, but shares the same local address
     * as the bound socket held by the harvester.
     */
    private class MySocket
            extends DatagramSocket
    {
        /**
         * The size of {@link #queue}.
         */
        private static final int QUEUE_SIZE = 64;

        /**
         * The FIFO which acts as a buffer for this socket.
         */
        private final ArrayBlockingQueue<Buffer> queue
            = new ArrayBlockingQueue<Buffer>(QUEUE_SIZE);

        /**
         * The remote address that is associated with this socket.
         */
        private SocketAddress remoteAddress;

        /**
         * Initializes a new <tt>MySocket</tt> instance with the given
         * remote address.
         * @param remoteAddress the remote address to be associated with the
         * new instance.
         * @throws SocketException
         */
        public MySocket(SocketAddress remoteAddress)
            throws SocketException
        {
            // unbound
            super((SocketAddress)null);

            this.remoteAddress = remoteAddress;
        }

        /**
         * Adds pkt to this socket. If the queue is full, drops a packet. Does
         * not block.
         */
        private void addBuffer(Buffer buf)
        {
            // XXX Should we drop the first packet from the queue instead?
            if (!queue.offer(buf))
                logger.info("Dropping a packet because the queue is full.");
        }

        /**
         * {@inheritDoc}
         *
         * Delegates to the actual socket of the harvester.
         */
        @Override
        public InetAddress getLocalAddress()
        {
            return localAddress.getAddress();
        }

        /**
         * {@inheritDoc}
         *
         * Delegates to the actual socket of the harvester.
         */
        @Override
        public int getLocalPort()
        {
            return localAddress.getPort();
        }

        /**
         * {@inheritDoc}
         *
         * Delegates to the actual socket of the harvester.
         */
        @Override
        public SocketAddress getLocalSocketAddress()
        {
            return localAddress;
        }

        /**
         * {@inheritDoc}
         *
         * Removes the association of the remote address with this socket from
         * the harvester's map.
         */
        @Override
        public void close()
        {
            // We could be called by the super-class constructor, in which
            // case this.removeAddress is not initialized yet.
            if (remoteAddress != null)
                SinglePortUdpHarvester.this.sockets.remove(remoteAddress);

            super.close();
        }

        /**
         * Reads the data from the first element of {@link #queue} into
         * <tt>p</tt>. Blocks until {@link #queue} has an element.
         * @param p
         * @throws IOException
         */
        @Override
        public void receive(DatagramPacket p)
           throws IOException
        {
            Buffer buf = null;

            while (buf == null)
            {
                try
                {
                    buf = queue.take();
                }
                catch (InterruptedException ie)
                {
                    // XXX How should we handle this?
                }
            }

            byte[] pData = p.getData();

            // XXX Should we use p.setData() here with a buffer of our own?
            if (pData == null || pData.length < buf.len)
                throw new IOException("packet buffer not available");

            System.arraycopy(buf.buffer, 0, pData, 0, buf.len);
            p.setLength(buf.len);
            p.setSocketAddress(remoteAddress);

            pool.offer(buf);
        }

        /**
         * {@inheritDoc}
         *
         * Delegates to the actual socket of the harvester.
         */
        @Override
        public void send(DatagramPacket p)
            throws IOException
        {
            socket.send(p);
        }
    }

    /**
     * Represents a buffer for the purposes of <tt>SinglePortUdpHarvester</tt>.
     * Wraps a byte[] and adds a length field specifying the number of elements
     * actually used.
     */
    private class Buffer
    {
        /**
         * The actual data.
         */
        byte[] buffer;

        /**
         * The number of elements of {@link #buffer} actually used.
         */
        int len;

        /**
         * Initializes a new <tt>Buffer</tt> instance.
         * @param buffer the data.
         * @param len the length.
         */
        private Buffer(byte[] buffer, int len)
        {
            this.buffer = buffer;
            this.len = len;
        }
    }

    /**
     * Implements a <tt>Candidate</tt> for the purposes of this
     * <tt>SinglePortUdpHarvester</tt>.
     */
    private class MyCandidate
        extends HostCandidate
    {
        /**
         * The local username fragment associated with this candidate.
         */
        private final String ufrag;

        /**
         * The collection of <tt>IceSocketWrapper</tt>s that can potentially
         * be used by the ice4j user to read/write from/to this candidate.
         * The keys are the remote addresses for each socket.
         *
         * There are wrappers over <tt>MultiplexedDatagramSocket</tt>s over
         * a corresponding socket in {@link #sockets}.
         */
        private final Map<SocketAddress, IceSocketWrapper> candidateSockets
                = new HashMap<SocketAddress, IceSocketWrapper>();

        /**
         * The collection of <tt>DatagramSocket</tt>s added to this candidate.
         * The keys are the remote addresses for each socket.
         *
         * These are the "raw" sockets, before any wrappers are added for
         * the STUN stack or the user of ice4j.
         */
        private final Map<SocketAddress, DatagramSocket> sockets
                = new HashMap<SocketAddress, DatagramSocket>();

        /**
         * Initializes a new <tt>MyCandidate</tt> instance with the given
         * <tt>Component</tt> and the given local username fragment.
         * @param component the <tt>Component</tt> for which this candidate will
         * serve.
         * @param ufrag the local ICE username fragment for this candidate (and
         * its <tt>Component</tt> and <tt>Agent</tt>).
         */
        private MyCandidate(Component component, String ufrag)
        {
            super(localAddress, component);
            this.ufrag = ufrag;
        }

        /**
         * {@inheritDoc}
         *
         * Closes all sockets in use by this <tt>LocalCandidate</tt>.
         */
        @Override
        public void free()
        {
            candidates.remove(ufrag);

            synchronized (candidateSockets)
            {
                for (IceSocketWrapper s : candidateSockets.values())
                {
                    s.close();
                }
                candidateSockets.clear();
            }

            StunStack stunStack = getStunStack();
            synchronized (sockets)
            {
                for (Map.Entry<SocketAddress, DatagramSocket> e
                        : sockets.entrySet())
                {
                    DatagramSocket socket = e.getValue();

                    if (stunStack != null)
                    {
                        TransportAddress localAddress
                            = new TransportAddress(socket.getLocalAddress(),
                                                   socket.getLocalPort(),
                                                   Transport.UDP);
                        TransportAddress remoteAddress
                            = new TransportAddress((InetSocketAddress)e.getKey(),
                                                   Transport.UDP);

                        stunStack.removeSocket(localAddress, remoteAddress);
                    }

                    socket.close();
                }
                sockets.clear();
            }

            super.free();
        }

        /**
         * Adds a new <tt>Socket</tt> to this candidate, which is associated
         * with a particular remote address.
         * @param socket the socket to add.
         * @param remoteAddress the remote address for the socket.
         */
        private void addSocket(DatagramSocket socket,
                               InetSocketAddress remoteAddress)
            throws IOException
        {
            Component component = getParentComponent();
            if (component == null)
                return;
            IceProcessingState state
                    = component.getParentStream().getParentAgent().getState();
            if (!IceProcessingState.WAITING.equals(state)
                    && !IceProcessingState.RUNNING.equals(state))
            {
                throw new IOException(
                        "Agent state is " + state + ". Cannot add socket.");
            }

            MultiplexingDatagramSocket multiplexing
                    = new MultiplexingDatagramSocket(socket);

            // Socket to add to the candidate
            IceSocketWrapper candidateSocket
                = new IceUdpSocketWrapper(multiplexing);

            // STUN-only filtered socket to add to the StunStack
            IceSocketWrapper stunSocket
                = new IceUdpSocketWrapper(
                    multiplexing.getSocket(new StunDatagramPacketFilter()));

            component.getParentStream().getParentAgent().getStunStack()
                    .addSocket(
                            stunSocket,
                            new TransportAddress(remoteAddress, Transport.UDP));


            // XXX is this necessary?
            synchronized (candidateSockets)
            {
                candidateSockets.put(remoteAddress, candidateSocket);
            }

            // XXX is this necessary?
            synchronized (sockets)
            {
                sockets.put(remoteAddress, socket);
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public IceSocketWrapper getIceSocketWrapper(SocketAddress remoteAddress)
        {
            return candidateSockets.get(remoteAddress);
        }
    }
}
