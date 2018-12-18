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
import org.ice4j.attribute.*;
import org.ice4j.message.*;
import org.ice4j.util.*;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;
import java.util.logging.Logger;

/**
 * A class which holds a {@link DatagramSocket} and runs a thread
 * ({@link #thread}) which perpetually reads from it.
 *
 * When a datagram from an unknown source is received, it is parsed as a STUN
 * Binding Request, and if it has a USERNAME attribute, its ufrag is extracted.
 * At this point, an implementing class may choose to create a mapping for
 * the remote address of the datagram, which will be used for further packets
 * from this address.
 *
 * @author Boris Grozev
 */
public abstract class AbstractUdpListener
{
    /**
     * The name of the property which controls the size of the receive buffer
     * which {@link SinglePortUdpHarvester} will request for the sockets that
     * it creates.
     */
    public static final String SO_RCVBUF_PNAME
        = AbstractUdpListener.class.getName() + ".SO_RCVBUF";

    /**
     * Our class logger.
     */
    private static final Logger logger
            = Logger.getLogger(AbstractUdpListener.class.getName());

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
     * Returns the list of {@link TransportAddress}es, one for each allowed IP
     * address found on each allowed network interface, with the given port.
     *
     * @param port the UDP port number.
     * @return the list of allowed transport addresses.
     */
    public static List<TransportAddress> getAllowedAddresses(int port)
    {
        List<TransportAddress> addresses = new LinkedList<>();
        for (InetAddress address
                : HostCandidateHarvester.getAllAllowedAddresses())
        {
            addresses.add(new TransportAddress(address, port, Transport.UDP));
        }

        return addresses;
    }

    /**
     * Tries to parse the bytes in <tt>buf</tt> at offset <tt>off</tt> (and
     * length <tt>len</tt>) as a STUN Binding Request message. If successful,
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
    static String getUfrag(byte[] buf, int off, int len)
    {
        // RFC5389, Section 6:
        // All STUN messages MUST start with a 20-byte header followed by zero
        // or more Attributes.
        if (buf == null || buf.length < off + len || len < 20)
        {
            return null;
        }

        // RFC5389, Section 6:
        // The magic cookie field MUST contain the fixed value 0x2112A442 in
        // network byte order.
        if ( !( (buf[off + 4] & 0xFF) == 0x21 &&
            (buf[off + 5] & 0xFF) == 0x12 &&
            (buf[off + 6] & 0xFF) == 0xA4 &&
            (buf[off + 7] & 0xFF) == 0x42))
        {
            if (logger.isLoggable(Level.FINE))
            {
                logger.fine("Not a STUN packet, magic cookie not found.");
            }
            return null;
        }

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
            if (logger.isLoggable(Level.FINE))
            {
                logger.fine("Failed to extract local ufrag: " + e);
            }
        }

        return null;
    }

    /**
     * The map which keeps the known remote addresses and their associated
     * candidateSockets.
     * {@link #thread} is the only thread which adds new entries, while
     * other threads remove entries when candidates are freed.
     */
    private final Map<SocketAddress, MySocket> sockets
            = new ConcurrentHashMap<>();

    /**
     * A pool of <tt>Buffer</tt> instances used to avoid creating of new java
     * objects.
     */
    private final ArrayBlockingQueue<Buffer> pool
        = new ArrayBlockingQueue<>(POOL_SIZE);

    /**
     * The local address that this harvester is bound to.
     */
    protected final TransportAddress localAddress;

    /**
     * The "main" socket that this harvester reads from.
     */
    private final DatagramSocket socket;

    /**
     * The thread reading from {@link #socket}.
     */
    private final Thread thread;

    /**
     * Triggers the termination of the threads of this instance.
     */
    private boolean close = false;

    /**
     * Initializes a new <tt>SinglePortUdpHarvester</tt> instance which is to
     * bind on the specified local address.
     * @param localAddress the address to bind to.
     * @throws IOException if initialization fails.
     */
    protected AbstractUdpListener(TransportAddress localAddress)
        throws IOException
    {
        boolean bindWildcard = StackProperties.getBoolean(
                StackProperties.BIND_WILDCARD,
                false);

        if (bindWildcard)
        {
            this.localAddress = new TransportAddress(
                                        (InetAddress) null,
                                        localAddress.getPort(),
                                        localAddress.getTransport()
                                );
        }
        else
        {
            this.localAddress = localAddress;
        }

        socket = new DatagramSocket( this.localAddress );

        int receiveBufferSize = StackProperties.getInt(SO_RCVBUF_PNAME, -1);
        if (receiveBufferSize > 0)
        {
            socket.setReceiveBufferSize(receiveBufferSize);
        }

        String logMessage
            = "Initialized AbstractUdpListener with address " + this.localAddress;
        logMessage += ". Receive buffer size " + socket.getReceiveBufferSize();
        if (receiveBufferSize > 0)
        {
            logMessage += " (asked for " + receiveBufferSize + ")";
        }
        logger.info(logMessage);

        thread = new Thread()
        {
            @Override
            public void run()
            {
                AbstractUdpListener.this.runInHarvesterThread();
            }
        };

        thread.setName(AbstractUdpListener.class.getName() + " thread for "
            + this.localAddress);
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Triggers the termination of the threads of this instance.
     */
    public void close()
    {
        close = true;
        socket.close(); // causes socket#receive to stop blocking.
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
        MySocket destinationSocket;
        InetSocketAddress remoteAddress;

        do
        {
            if (close)
            {
                break;
            }

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
                if (!close)
                {
                    logger.severe("Failed to receive from socket: " + ioe);
                }
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

                maybeAcceptNewSession(buf, remoteAddress, ufrag);
                // Maybe add to #sockets here in the base class?
            }
        }
        while (true);

        // now clean up and exit
        for (MySocket candidateSocket : new ArrayList<>(sockets.values()))
        {
            candidateSocket.close();
        }
        socket.close();
    }

    /**
     * Handles the reception of a STUN Binding Request with a valid USERNAME
     * attribute, from a "new" remote address (one which is not in
     * {@link #sockets}).
     * Implementations may choose to e.g. create a socket and pass it to their
     * ICE stack.
     *
     * Note that this is meant to only be executed by
     * {@link AbstractUdpListener}'s read thread, and should not be called from
     * implementing classes.
     *
     * @param buf the UDP payload of the first datagram received on the newly
     * accepted socket.
     * @param remoteAddress the remote address from which the datagram was
     * received.
     * @param ufrag the local ICE username fragment of the received STUN Binding
     * Request.
     */
    protected abstract void maybeAcceptNewSession(
            Buffer buf,
            InetSocketAddress remoteAddress,
            String ufrag);

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
     * Creates a new {@link MySocket} instance and associates it with the given
     * remote address. Returns the created instance.
     *
     * Note that this is meant to only execute in {@link AbstractUdpListener}'s
     * read thread.
     *
     * @param remoteAddress the remote address with which to associate the new
     * socket instance.
     * @return the created socket instance.
     */
    protected MySocket addSocket(InetSocketAddress remoteAddress)
        throws SocketException
    {
        MySocket newSocket = new MySocket(remoteAddress);
        sockets.put(remoteAddress, newSocket);
        return newSocket;
    }


    /**
     * Implements a <tt>DatagramSocket</tt> for the purposes of a specific
     * <tt>MyCandidate</tt>.
     *
     * It is not bound to a specific port, but shares the same local address
     * as the bound socket held by the harvester.
     */
    protected class MySocket
            extends DatagramSocket
    {
        /**
         * The size of {@link #queue}.
         */
        private static final int QUEUE_SIZE = 128;

        /**
         * The FIFO which acts as a buffer for this socket.
         */
        private final ArrayBlockingQueue<Buffer> queue
            = new ArrayBlockingQueue<>(QUEUE_SIZE);

        /**
         * The {@link QueueStatistics} instance optionally used to collect and
         * print detailed statistics about {@link #queue}.
         */
        private final QueueStatistics queueStatistics;

        /**
         * The remote address that is associated with this socket.
         */
        private InetSocketAddress remoteAddress;

        /**
         * The flag which indicates that this <tt>DatagramSocket</tt> has been
         * closed.
         */
        private boolean closed = false;

        /**
         * Initializes a new <tt>MySocket</tt> instance with the given
         * remote address.
         * @param remoteAddress the remote address to be associated with the
         * new instance.
         * @throws SocketException
         */
        MySocket(InetSocketAddress remoteAddress)
            throws SocketException
        {
            // unbound
            super((SocketAddress)null);

            this.remoteAddress = remoteAddress;
            if (logger.isLoggable(Level.FINEST))
            {
                queueStatistics = new QueueStatistics(
                    "SinglePort" + remoteAddress.toString().replace('/', '-'));
            }
            else
            {
                queueStatistics = null;
            }
        }

        /**
         * Adds pkt to this socket. If the queue is full, drops a packet. Does
         * not block.
         */
        public void addBuffer(Buffer buf)
        {
            synchronized (queue)
            {
                // Drop the first rather than the current packet, so that
                // receivers can notice the loss earlier.
                if (queue.size() == QUEUE_SIZE)
                {
                    logger.info("Dropping a packet because the queue is full.");
                    if (queueStatistics != null)
                    {
                        queueStatistics.remove(System.currentTimeMillis());
                    }
                    queue.poll();
                }

                queue.offer(buf);
                if (queueStatistics != null)
                {
                    queueStatistics.add(System.currentTimeMillis());
                }

                queue.notify();
            }
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
         * </p>
         * This {@link DatagramSocket} will only allow packets from the
         * remote address that it has, so we consider it connected to this
         * address.
         */
        @Override
        public SocketAddress getRemoteSocketAddress()
        {
            return remoteAddress;
        }

        /**
         * {@inheritDoc}
         * </p>
         * This {@link DatagramSocket} will only allow packets from the
         * remote address that it has, so we consider it connected to this
         * address.
         */
        @Override
        public InetAddress getInetAddress()
        {
            return remoteAddress.getAddress();
        }

        /**
         * {@inheritDoc}
         * </p>
         * This {@link DatagramSocket} will only allow packets from the
         * remote address that it has, so we consider it connected to this
         * address.
         */
        @Override
        public int getPort()
        {
            return remoteAddress.getPort();
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
            synchronized (queue)
            {
                closed = true;

                // Wake up any threads still in receive()
                queue.notifyAll();
            }

            // We could be called by the super-class constructor, in which
            // case this.removeAddress is not initialized yet.
            if (remoteAddress != null)
            {
                AbstractUdpListener.this.sockets.remove(remoteAddress);
            }

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
                synchronized (queue)
                {
                    if (closed)
                    {
                        throw new SocketException("Socket closed");
                    }

                    if (queue.isEmpty())
                    {
                        try
                        {
                            queue.wait();
                        }
                        catch (InterruptedException ie)
                        {}
                    }

                    buf = queue.poll();
                    if (queueStatistics != null)
                    {
                        queueStatistics.remove(System.currentTimeMillis());
                    }
                }
            }

            byte[] pData = p.getData();

            // XXX Should we use p.setData() here with a buffer of our own?
            if (pData == null || pData.length < buf.len)
            {
                throw new IOException("packet buffer not available");
            }

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
    protected class Buffer
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
}
