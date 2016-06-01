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
import java.net.*;
import java.util.*;
import java.util.logging.*;

/**
 * Represents a <tt>Socket</tt> which allows filtering <tt>DatagramPacket</tt>s
 * it reads from the network using <tt>DatagramPacketFilter</tt>s so that the
 * <tt>DatagramPacket</tt>s do not get received through it but through
 * associated <tt>MultiplexedSocket</tt>s.
 *
 * @author Sebastien Vincent
 * @author Lyubomir Marinov
 */
public class MultiplexingSocket
    extends DelegatingSocket
{
    /**
     * The <tt>Logger</tt> used by the <tt>MultiplexingSocket</tt> class and its
     * instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(MultiplexingSocket.class.getName());

    /**
     * Custom <tt>InputStream</tt> for this <tt>Socket</tt>.
     */
    private final InputStream inputStream = new TCPInputStream(this);

    /**
     * The {@code MultiplexingXXXSocketSupport} which implements functionality
     * common to TCP and UDP sockets in order to facilitate implementers such as
     * this instance.
     */
    private final MultiplexingXXXSocketSupport<MultiplexedSocket>
        multiplexingXXXSocketSupport
            = new MultiplexingXXXSocketSupport<MultiplexedSocket>()
            {
                /**
                 * {@inheritDoc}
                 */
                @Override
                protected MultiplexedSocket createSocket(
                        DatagramPacketFilter filter)
                    throws SocketException
                {
                    return
                        new MultiplexedSocket(MultiplexingSocket.this, filter);
                }

                /**
                 * {@inheritDoc}
                 */
                @Override
                protected void doReceive(DatagramPacket p)
                    throws IOException
                {
                    multiplexingXXXSocketSupportDoReceive(p);
                }

                /**
                 * {@inheritDoc}
                 */
                @Override
                protected void doSetReceiveBufferSize(int receiveBufferSize)
                    throws SocketException
                {
                    multiplexingXXXSocketSupportDoSetReceiveBufferSize(
                            receiveBufferSize);
                }

                /**
                 * {@inheritDoc}
                 */
                @Override
                protected List<DatagramPacket> getReceived()
                {
                    return received;
                }

                /**
                 * {@inheritDoc}
                 */
                @Override
                protected List<DatagramPacket> getReceived(
                        MultiplexedSocket socket)
                {
                    return socket.received;
                }
            };

    /**
     * Custom <tt>OutputStream</tt> for this <tt>Socket</tt>.
     */
    private TCPOutputStream outputStream = null;

    /**
     * The list of <tt>DatagramPacket</tt>s to be received through this
     * <tt>Socket</tt> i.e. not accepted by the <tt>DatagramFilter</tt>s of
     * {@link #sockets} at the time of the reading from the network.
     */
    private final List<DatagramPacket> received
        = new SocketReceiveBuffer()
        {
            private static final long serialVersionUID
                = 4097024214973676873L;

            @Override
            public int getReceiveBufferSize()
                throws SocketException
            {
                return MultiplexingSocket.this.getReceiveBufferSize();
            }
        };

    /**
     * Buffer variable for storing the SO_TIMEOUT value set by the last
     * <tt>setSoTimeout()</tt> call. Although not strictly needed, getting the
     * locally stored value as opposed to retrieving it from a parent
     * <tt>getSoTimeout()</tt> call seems to significantly improve efficiency,
     * at least on some platforms.
     */
    private int soTimeout = 0;

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @see Socket#Socket()
     */
    public MultiplexingSocket()
    {
        this((Socket) null);
    }

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @param address not used
     * @param port not used
     * @see Socket#Socket(InetAddress, int)
     */
    public MultiplexingSocket(InetAddress address, int port)
    {
        this((Socket) null);
    }

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @param address not used
     * @param port not used
     * @param localAddr not used
     * @param localPort not used
     * @see Socket#Socket(InetAddress, int, InetAddress, int)
     */
    public MultiplexingSocket(
            InetAddress address, int port,
            InetAddress localAddr, int localPort)
    {
        this((Socket) null);
    }

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @param proxy not used
     * @see Socket#Socket(Proxy)
     */
    public MultiplexingSocket(Proxy proxy)
    {
        this((Socket) null);
    }

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @param socket delegate socket
     */
    public MultiplexingSocket(Socket socket)
    {
        super(socket);

        try
        {
            setTcpNoDelay(true);
        }
        catch (SocketException ex)
        {
            logger.info("Cannot SO_TCPNODELAY");
        }
    }

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @param impl not used
     * @see Socket#Socket(SocketImpl)
     */
    protected MultiplexingSocket(SocketImpl impl)
    {
        this((Socket) null);
    }

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @param host not used
     * @param port not used
     * @see Socket#Socket(String, int)
     */
    public MultiplexingSocket(String host, int port)
    {
        this((Socket) null);
    }

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @param host not used
     * @param port not used
     * @param localAddr not used
     * @param localPort not used
     * @see Socket#Socket(String, int, InetAddress, int)
     */
    public MultiplexingSocket(
            String host, int port,
            InetAddress localAddr, int localPort)
    {
        this((Socket) null);
    }

    /**
     * Closes a specific <tt>MultiplexedSocket</tt> which filters
     * <tt>DatagramPacket</tt>s away from this <tt>Socket</tt>.
     *
     * @param multiplexed the <tt>MultiplexedSocket</tt> to close
     */
    void close(MultiplexedSocket multiplexed)
    {
        multiplexingXXXSocketSupport.close(multiplexed);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public InputStream getInputStream()
        throws IOException
    {
        return inputStream;
    }

    /**
     * Get original <tt>InputStream</tt>.
     *
     * @return original <tt>InputStream</tt>
     * @throws IOException if something goes wrong
     */
    public InputStream getOriginalInputStream()
        throws IOException
    {
        return super.getInputStream();
    }

    /**
     * Get original <tt>OutputStream</tt>.
     *
     * @return original <tt>OutputStream</tt>
     * @throws IOException if something goes wrong
     */
    public OutputStream getOriginalOutputStream()
        throws IOException
    {
        return super.getOutputStream();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OutputStream getOutputStream()
        throws IOException
    {
        if (outputStream == null)
            outputStream = new TCPOutputStream(super.getOutputStream());
        return outputStream;
    }

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
    public MultiplexedSocket getSocket(DatagramPacketFilter filter)
        throws SocketException
    {
        return multiplexingXXXSocketSupport.getSocket(filter);
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
     * Implements {@link MultiplexingXXXSocketSupport#doReceive(DatagramPacket)}
     * on behalf of {@link #multiplexingXXXSocketSupport}. Receives a
     * {@code DatagramPacket} from this socket.
     *
     * @param p the {@code DatagramPacket} into which to place the incoming data
     * @throws IOException if an I/O error occurs
     */
    private void multiplexingXXXSocketSupportDoReceive(DatagramPacket p)
        throws IOException
    {
        super.receive(p);
    }

    /**
     * Implements
     * {@link MultiplexingXXXSocketSupport#doSetReceiveBufferSize(int)} on
     * behalf of {@link #multiplexingXXXSocketSupport}. Sets the
     * {@code SO_RCVBUF} option to the specified value for this
     * {@code DatagramSocket}. The {@code SO_RCVBUF} option is used by the
     * network implementation as a hint to size the underlying network I/O
     * buffers. The {@code SO_RCVBUF} setting may also be used by the network
     * implementation to determine the maximum size of the packet that can be
     * received on this socket.
     *
     * @param receiveBufferSize the size to which to set the receive buffer size
     * @throws SocketException if there is an error in the underlying protocol,
     * such as a TCP error
     */
    private void multiplexingXXXSocketSupportDoSetReceiveBufferSize(
            int receiveBufferSize)
        throws SocketException
    {
        super.setReceiveBufferSize(receiveBufferSize);
    }

    /**
     * Receives a datagram packet from this socket. The <tt>DatagramPacket</tt>s
     * returned by this method do not match any of the
     * <tt>DatagramPacketFilter</tt>s of the <tt>MultiplexedDatagramSocket</tt>s
     * associated with this instance at the time of their receipt. When this
     * method returns, the <tt>DatagramPacket</tt>'s buffer is filled with the
     * data received. The datagram packet also contains the sender's IP address,
     * and the port number on the sender's machine.
     * <p>
     * This method blocks until a datagram is received. The <tt>length</tt>
     * field of the datagram packet object contains the length of the received
     * message. If the message is longer than the packet's length, the message
     * is truncated.
     * </p>
     *
     * @param p the <tt>DatagramPacket</tt> into which to place the incoming
     * data
     * @throws IOException if an I/O error occurs
     * @see DelegatingSocket#receive(DatagramPacket)
     */
    @Override
    public void receive(DatagramPacket p)
        throws IOException
    {
        try
        {
            setOriginalInputStream(super.getInputStream());
        }
        catch(Exception e)
        {
        }

        multiplexingXXXSocketSupport.receive(received, p, soTimeout);
    }

    /**
     * Receives a <tt>DatagramPacket</tt> from this <tt>Socket</tt> upon
     * request from a specific <tt>MultiplexedSocket</tt>.
     *
     * @param multiplexed the <tt>MultiplexedSocket</tt> which requests
     * the receipt of a <tt>DatagramPacket</tt> from the network
     * @param p the <tt>DatagramPacket</tt> to receive the data from the network
     * @throws IOException if an I/O error occurs
     */
    void receive(MultiplexedSocket multiplexed, DatagramPacket p)
        throws IOException
    {
        try
        {
            setOriginalInputStream(super.getInputStream());
        }
        catch(Exception e)
        {
        }

        multiplexingXXXSocketSupport.receive(
                multiplexed.received,
                p,
                multiplexed.getSoTimeout());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setSoTimeout(int timeout)
    	throws SocketException
    {
    	super.setSoTimeout(timeout);

    	soTimeout = timeout;
    }
}
