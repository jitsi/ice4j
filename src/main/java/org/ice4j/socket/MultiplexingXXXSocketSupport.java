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

import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;

/**
 * Implements functionality common to TCP and UDP implementations of
 * (de)multiplexing sockets i.e. sockets which provide
 * {@code DatagramPacket}-based views of the packets they receive in the forms
 * of pseudo sockets.
 *
 * @author Lyubomir Marinov
 */
abstract class MultiplexingXXXSocketSupport
        <MultiplexedXXXSocketT extends MultiplexedXXXSocket>
{
    /**
     * The {@code Logger} used by the {@code MultiplexingXXXSocketSupport} class
     * and its instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(MultiplexingXXXSocketSupport.class.getName());

    /**
     * Initializes a new <tt>DatagramPacket</tt> instance which is a clone of a
     * specific <tt>DatagramPacket</tt> i.e. the properties of the clone
     * <tt>DatagramPacket</tt> are clones of the specified
     * <tt>DatagramPacket</tt>.
     *
     * @param p the <tt>DatagramPacket</tt> to clone
     * @return a new <tt>DatagramPacket</tt> instance which is a clone of the
     * specified <tt>DatagramPacket</tt>
     */
    public static DatagramPacket clone(DatagramPacket p)
    {
        return clone(p, /* arraycopy */ true);
    }

    /**
     * Initializes a new <tt>DatagramPacket</tt> instance which is a clone of a
     * specific <tt>DatagramPacket</tt> i.e. the properties of the clone
     * <tt>DatagramPacket</tt> are clones of the specified
     * <tt>DatagramPacket</tt>.
     *
     * @param p the <tt>DatagramPacket</tt> to clone
     * @param arraycopy <tt>true</tt> if the actual bytes of the data of
     * <tt>p</tt> are to be copied into the clone or <tt>false</tt> if only the
     * capacity of the data of <tt>p</tt> is to be cloned without copying the
     * actual bytes of the data of <tt>p</tt>
     * @return a new <tt>DatagramPacket</tt> instance which is a clone of the
     * specified <tt>DatagramPacket</tt>
     */
    private static DatagramPacket clone(DatagramPacket p, boolean arraycopy)
    {
        byte[] data;
        int off;
        int len;
        InetAddress address;
        int port;

        synchronized (p)
        {
            data = p.getData();
            off = p.getOffset();
            len = p.getLength();

            // Clone the data.
            {
                // The capacity of the specified p is preserved.
                byte[] dataClone = new byte[data.length];

                // However, only copy the range of data starting with off and
                // spanning len number of bytes. Of course, preserve off and len
                // in addition to the capacity.
                if (arraycopy && (len > 0))
                {
                    int arraycopyOff, arraycopyLen;

                    // If off and/or len are going to cause an exception though,
                    // copy the whole data.
                    if ((off >= 0)
                            && (off < data.length)
                            && (off + len <= data.length))
                    {
                        arraycopyOff = off;
                        arraycopyLen = len;
                    }
                    else
                    {
                        arraycopyOff = 0;
                        arraycopyLen = data.length;
                    }
                    System.arraycopy(
                            data, arraycopyOff,
                            dataClone, arraycopyOff,
                            arraycopyLen);
                }
                data = dataClone;
            }

            address = p.getAddress();
            port = p.getPort();
        }

        DatagramPacket c = new DatagramPacket(data, off, len);

        if (address != null)
            c.setAddress(address);
        if (port >= 0)
            c.setPort(port);

        return c;
    }

    /**
     * Copies the properties of a specific <tt>DatagramPacket</tt> to another
     * <tt>DatagramPacket</tt>. The property values are not cloned.
     *
     * @param src the <tt>DatagramPacket</tt> which is to have its properties
     * copied to <tt>dest</tt>
     * @param dest the <tt>DatagramPacket</tt> which is to have its properties
     * set to the value of the respective properties of <tt>src</tt>
     */
    public static void copy(DatagramPacket src, DatagramPacket dest)
    {
        synchronized (dest)
        {
            dest.setAddress(src.getAddress());
            dest.setPort(src.getPort());

            byte[] srcData = src.getData();

            if (srcData == null)
            {
                dest.setLength(0);
            }
            else
            {
                byte[] destData = dest.getData();

                if (destData == null)
                {
                    dest.setLength(0);
                }
                else
                {
                    int destOffset = dest.getOffset();
                    int destLength = destData.length - destOffset;
                    int srcLength = src.getLength();

                    if (destLength >= srcLength)
                    {
                        destLength = srcLength;
                    }
                    else if (logger.isLoggable(Level.WARNING))
                    {
                        logger.log(
                                Level.WARNING,
                                "Truncating received DatagramPacket data!");
                    }
                    System.arraycopy(
                            srcData, src.getOffset(),
                            destData, destOffset,
                            destLength);
                    dest.setLength(destLength);
                }
            }
        }
    }

    /**
     * The indicator which determines whether this <tt>DatagramSocket</tt> is
     * currently reading from the network using
     * {@link DatagramSocket#receive(DatagramPacket)}. When <tt>true</tt>,
     * subsequent requests to read from the network will be blocked until the
     * current read is finished.
     */
    private boolean inReceive = false;

    /**
     * The value with which {@link DatagramSocket#setReceiveBufferSize(int)} is
     * to be invoked if {@link #setReceiveBufferSize} is <tt>true</tt>. 
     */
    private int receiveBufferSize;

    /**
     * The <tt>Object</tt> which synchronizes the access to {@link #inReceive}.
     */
    private final Object receiveSyncRoot = new Object();

    /**
     * The indicator which determines whether
     * {@link DatagramSocket#setReceiveBufferSize(int)} is to be invoked with
     * the value of {@link #receiveBufferSize}.
     */
    private boolean setReceiveBufferSize = false;

    /**
     * The IP sockets filtering {@code DatagramPacket}s away from this IP
     * socket.
     */
    private final List<MultiplexedXXXSocketT> sockets = new ArrayList<>();

    /**
     * Initializes a new {@code MultiplexingXXXSocketSupport} instance.
     */
    protected MultiplexingXXXSocketSupport()
    {
    }

    /**
     * Accepts a {@code DatagramPacket} received by this socket and queues it
     * for receipt through either this multiplexing socket or its multiplexed
     * sockets whose {@code DatagramPacketFilter}s accept {@code p}.
     *
     * @param p the {@code DatagramPacket} to be accepted by either this
     * multiplexing socket or its multiplexed sockets whose
     * {@code DatagramPacketFilter}s accept {@code p}
     */
    private void acceptBySocketsOrThis(DatagramPacket p)
    {
        synchronized (sockets)
        {
            boolean accepted = false;

            for (MultiplexedXXXSocketT socket : sockets)
            {
                if (getFilter(socket).accept(p))
                {
                    List<DatagramPacket> socketReceived = getReceived(socket);

                    synchronized (socketReceived)
                    {
                        socketReceived.add(
                                accepted ? clone(p, /* arraycopy */ true) : p);
                        socketReceived.notifyAll();
                    }
                    accepted = true;

                    // Emil Ivov: Don't break because we want all
                    // filtering sockets to get the received packet.
                }
            }
            if (!accepted)
            {
                List<DatagramPacket> thisReceived = getReceived();

                synchronized (thisReceived)
                {
                    thisReceived.add(p);
                    thisReceived.notifyAll();
                }
            }
        }
    }

    /**
     * Closes a specific <tt>MultiplexedDatagramSocket</tt> which filters
     * <tt>DatagramPacket</tt>s away from this <tt>DatagramSocket</tt>.
     *
     * @param multiplexed the <tt>MultiplexedDatagramSocket</tt> to close
     * @return {@code true} if there are remaining filtered sockets.
     */
    boolean close(MultiplexedXXXSocketT multiplexed)
    {
        synchronized (sockets)
        {
            sockets.remove(multiplexed);

            return !sockets.isEmpty();
        }
    }

    /**
     * Initializes a new multiplexed socket instance which is to be associated
     * with a specific {@code DatagramPacketFilter}.
     *
     * @param filter the {@code DatagramPacketFilter} to associate with the new
     * instance
     * @return a new multiplexed socket associated with the specified
     * {@code filter}
     * @throws SocketException if there is an error in the underlying protocol,
     * such as a TCP or UDP error
     */
    protected abstract MultiplexedXXXSocketT createSocket(
            DatagramPacketFilter filter)
        throws SocketException;

    /**
     * Receives a {@code DatagramPacket} from this socket.
     *
     * @param p the {@code DatagramPacket} into which to place the incoming data
     * @throws IOException if an I/O error occurs
     */
    protected abstract void doReceive(DatagramPacket p)
        throws IOException;

    /**
     * Sets the {@code SO_RCVBUF} option to the specified value for this
     * {@code DatagramSocket}. The {@code SO_RCVBUF} option is used by the
     * network implementation as a hint to size the underlying network I/O
     * buffers. The {@code SO_RCVBUF} setting may also be used by the network
     * implementation to determine the maximum size of the packet that can be
     * received on this socket.
     *
     * @param receiveBufferSize the size to which to set the receive buffer size
     * @throws SocketException if there is an error in the underlying protocol,
     * such as a UDP error
     */
    protected abstract void doSetReceiveBufferSize(int receiveBufferSize)
        throws SocketException;

    /**
     * Gets the {@code DatagramPacketFilter} associated with a specific
     * multiplexed socket.
     *
     * @param socket the multiplexed socket whose associated
     * {@code DatagramPacketFilter} is to be retrieved
     * @return the {@code DatagramPacketFilter} associated with {@code socket}
     */
    protected DatagramPacketFilter getFilter(MultiplexedXXXSocketT socket)
    {
        return socket.getFilter();
    }

    /**
     * Gets the list of {@code DatagramPacket}s received by this socket and not
     * accepted by any (existing) {@code DatagramPacketFilter} at the time of
     * receipt.
     *
     * @return the list of {@code DatagramPacket}s received by this socket and
     * not accepted by any (existing) {@code DatagramPacketFilter} at the time of
     * receipt
     */
    protected abstract List<DatagramPacket> getReceived();

    /**
     * Gets the list of {@code DatagramPacket}s received by this multiplexing
     * socket and accepted by the {@code DatagramPacketFilter} of a specific
     * multiplexed socket at the time of receipt.
     *
     * @param socket the multiplexed socket whose list of accepted received
     * {@code DatagramPacket}s is to be returned
     * @return the list of {@code DatagramPacket}s received by this multiplexing
     * socket and accepted by the {@code DatagramPacketFilter} of the
     * multiplexed {@code socket} at the time of receipt
     */
    protected abstract List<DatagramPacket> getReceived(
            MultiplexedXXXSocketT socket);

    /**
     * Gets a <tt>MultiplexedDatagramSocket</tt> which filters
     * <tt>DatagramPacket</tt>s away from this <tt>DatagramSocket</tt> using a
     * specific <tt>DatagramPacketFilter</tt>. If such a
     * <tt>MultiplexedDatagramSocket</tt> does not exist in this instance, it is
     * created.
     *
     * @param filter the <tt>DatagramPacketFilter</tt> to get a
     * <tt>MultiplexedDatagramSocket</tt> for
     * @return a <tt>MultiplexedDatagramSocket</tt> which filters
     * <tt>DatagramPacket</tt>s away from this <tt>DatagramSocket</tt> using the
     * specified <tt>filter</tt>
     * @throws SocketException if creating the
     * <tt>MultiplexedDatagramSocket</tt> for the specified <tt>filter</tt>
     * fails
     */
    public MultiplexedXXXSocketT getSocket(DatagramPacketFilter filter)
        throws SocketException
    {
        return getSocket(filter, /* create */ true);
    }

    /**
     * Gets a <tt>MultiplexedDatagramSocket</tt> which filters
     * <tt>DatagramPacket</tt>s away from this <tt>DatagramSocket</tt> using a
     * specific <tt>DatagramPacketFilter</tt>. If <tt>create</tt> is true and
     * such a <tt>MultiplexedDatagramSocket</tt> does not exist in this
     * instance, it is created.
     *
     * @param filter the <tt>DatagramPacketFilter</tt> to get a
     * <tt>MultiplexedDatagramSocket</tt> for
     * @param create whether or not to create a
     * <tt>MultiplexedDatagramSocket</tt> if this instance does not already have
     * a socket for the given <tt>filter</tt>.
     * @return a <tt>MultiplexedDatagramSocket</tt> which filters
     * <tt>DatagramPacket</tt>s away from this <tt>DatagramSocket</tt> using the
     * specified <tt>filter</tt>
     * @throws SocketException if creating the
     * <tt>MultiplexedDatagramSocket</tt> for the specified <tt>filter</tt>
     * fails.
     */
    public MultiplexedXXXSocketT getSocket(
            DatagramPacketFilter filter,
            boolean create)
        throws SocketException
    {
        if (filter == null)
            throw new NullPointerException("filter");

        synchronized (sockets)
        {
            // If a socket for the specified filter exists already, do not
            // create a new one and return the existing.
            for (MultiplexedXXXSocketT socket : sockets)
            {
                if (filter.equals(getFilter(socket)))
                    return socket;
            }

            if (!create)
                return null;

            // Create a new socket for the specified filter.
            MultiplexedXXXSocketT socket = createSocket(filter);

            // Remember the new socket.
            if (socket != null)
            {
                sockets.add(socket);

                // A multiplexed socket may be created after packets matching
                // its filter have been received. Pull them out of the
                // multiplexing socket and into the newly-created multiplexed
                // socket.

                // XXX The fields received of both the multiplexed and the
                // multiplexing sockets are used as synchronization roots (e.g.
                // the method acceptBySocketsOrThis). In order to preserve the
                // order of acquiring synchronization roots, perform the
                // following procedure under the protection of the field
                // socketsSyncRoot even though the field sockets will not be
                // accessed.
                moveReceivedFromThisToSocket(socket);
            }

            return socket;
        }
    }

    /**
     * Moves packets which have been received from this multiplexing socket to
     * a specific multiplexed socket if they are accepted by the
     * {@code DatagramPacketFilter} of the latter.
     *
     * @param socket the multiplexed socket into which received packets are to
     * be moved from this multiplexing socket if they are accepted by the
     * {@code DatagramPacketFilter} of the former
     */
    private void moveReceivedFromThisToSocket(MultiplexedXXXSocketT socket)
    {
        // Pull the packets which have been received already and are accepted by
        // the specified multiplexed socket out of the multiplexing socket.
        List<DatagramPacket> thisReceived = getReceived();
        DatagramPacketFilter socketFilter = getFilter(socket);
        List<DatagramPacket> toMove = null;

        synchronized (thisReceived)
        {
            if (thisReceived.isEmpty())
            {
                return;
            }
            else
            {
                for (Iterator<DatagramPacket> i = thisReceived.iterator();
                        i.hasNext();)
                {
                    DatagramPacket p = i.next();

                    if (socketFilter.accept(p))
                    {
                        if (toMove == null)
                            toMove = new LinkedList<>();
                        toMove.add(p);

                        // XXX In the method receive, we allow multiple filters
                        // to accept one and the same packet.
                        i.remove();
                    }
                }
            }
        }

        // Push the packets which have been accepted already and are accepted by
        // the specified multiplexed socket into the multiplexed socket in
        // question.
        if (toMove != null)
        {
            List<DatagramPacket> socketReceived = getReceived(socket);

            synchronized (socketReceived)
            {
                socketReceived.addAll(toMove);
                // The notifyAll will practically likely be unnecessary because
                // the specified socket will likely be a newly-created one to
                // which noone else has a reference. Anyway, dp the invocation
                // for the purposes of consistency, clarity, and such.
                socketReceived.notifyAll();
            }
        }
    }

    /**
     * Receives a <tt>DatagramPacket</tt> from a specific list of
     * <tt>DatagramPacket</tt>s if it is not empty or from the network if the
     * specified list is empty. When this method returns, the
     * <tt>DatagramPacket</tt>'s buffer is filled with the data received. The
     * datagram packet also contains the sender's IP address, and the port
     * number on the sender's machine.
     *
     * @param received the list of previously received <tt>DatagramPacket</tt>
     * from which the first is to be removed and returned if available
     * @param p the <tt>DatagramPacket</tt> into which to place the incoming
     * data
     * @param timeout the maximum time in milliseconds to wait for a
     * packet. A timeout of zero is interpreted as an infinite
     * timeout
     * @throws IOException if an I/O error occurs
     * @throws SocketTimeoutException if <tt>timeout</tt> is positive and has
     * expired
     */
    void receive(List<DatagramPacket> received, DatagramPacket p, int timeout)
        throws IOException
    {
        long startTime = System.currentTimeMillis();
        DatagramPacket r = null;

        do
        {
            long now = System.currentTimeMillis();

            // If there is a packet which has been received from the network and
            // is to merely be received from the list of received
            // DatagramPackets, then let it be received and do not throw a
            // SocketTimeoutException.
            synchronized (received)
            {
                if (!received.isEmpty())
                {
                    r = received.remove(0);
                    if (r != null)
                        break;
                }
            }

            // Throw a SocketTimeoutException if the timeout is over/up.
            long remainingTimeout;

            if (timeout > 0)
            {
                remainingTimeout = timeout - (now - startTime);
                if (remainingTimeout <= 0L)
                {
                    throw new SocketTimeoutException(
                            Long.toString(remainingTimeout));
                }
            }
            else
            {
                remainingTimeout = 1000L;
            }

            // Determine whether the caller will receive from the network or
            // will wait for a previous caller to receive from the network.
            boolean wait;

            synchronized (receiveSyncRoot)
            {
                if (inReceive)
                {
                    wait = true;
                }
                else
                {
                    wait = false;
                    inReceive = true;
                }
            }
            try
            {
                if (wait)
                {
                    // The caller will wait for a previous caller to receive
                    // from the network.
                    synchronized (received)
                    {
                        if (received.isEmpty())
                        {
                            try
                            {
                                received.wait(remainingTimeout);
                            }
                            catch (InterruptedException ie)
                            {
                            }
                        }
                        else
                        {
                            received.notifyAll();
                        }
                    }
                    continue;
                }

                // The caller will receive from the network.
                DatagramPacket c = clone(p, /* arraycopy */ false);

                synchronized (receiveSyncRoot)
                {
                    if (setReceiveBufferSize)
                    {
                        setReceiveBufferSize = false;
                        try
                        {
                            doSetReceiveBufferSize(receiveBufferSize);
                        }
                        catch (Throwable t)
                        {
                            if (t instanceof ThreadDeath)
                                throw (ThreadDeath) t;
                        }
                    }
                }
                doReceive(c);

                // The caller received from the network. Copy/add the packet to
                // the receive list of the sockets which accept it.
                acceptBySocketsOrThis(c);
            }
            finally
            {
                synchronized (receiveSyncRoot)
                {
                    if (!wait)
                        inReceive = false;
                }
            }
        }
        while (true);

        copy(r, p);
    }

    /**
     * Sets the {@code SO_RCVBUF} option to the specified value for this socket.
     * The {@code SO_RCVBUF} option is used by the network implementation as a
     * hint to size the underlying network I/O buffers. The {@code SO_RCVBUF}
     * setting may also be used by the network implementation to determine the
     * maximum size of the packet that can be received on this socket.
     *
     * @param receiveBufferSize the size to which to set the receive buffer size
     * @throws SocketException if there is an error in the underlying protocol,
     * such as a TCP or UDP error
     */
    public void setReceiveBufferSize(int receiveBufferSize)
        throws SocketException
    {
        synchronized (receiveSyncRoot)
        {
            this.receiveBufferSize = receiveBufferSize;

            if (inReceive)
            {
                setReceiveBufferSize = true;
            }
            else
            {
                doSetReceiveBufferSize(receiveBufferSize);
                setReceiveBufferSize = false;
            }
        }
    }
}
