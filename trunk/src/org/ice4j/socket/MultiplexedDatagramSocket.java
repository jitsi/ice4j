/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.socket;

import java.io.*;
import java.net.*;
import java.nio.channels.*;
import java.util.*;

/**
 * Represents a <tt>DatagramSocket</tt> which receives <tt>DatagramPacket</tt>s
 * selected by a <tt>DatagramPacketFilter</tt> from a
 * <tt>MultiplexingDatagramSocket</tt>. The associated
 * <tt>MultiplexingDatagramSocket</tt> is the actual <tt>DatagramSocket</tt>
 * which reads the <tt>DatagramPacket</tt>s from the network. The
 * <tt>DatagramPacket</tt>s received through the
 * <tt>MultiplexedDatagramSocket</tt> will not be received through the
 * associated <tt>MultiplexingDatagramSocket</tt>.
 *
 * @author Lubomir Marinov
 */
public class MultiplexedDatagramSocket
    extends DatagramSocket
{

    /**
     * The <tt>DatagramPacketFilter</tt> which determines which
     * <tt>DatagramPacket</tt>s read from the network by {@link #multiplexing}
     * are to be received through this instance.
     */
    private final DatagramPacketFilter filter;

    /**
     * The <tt>MultiplexingDatagramSocket</tt> which does the actual reading
     * from the network and which forwards <tt>DatagramPacket</tt>s accepted by
     * {@link #filter} for receipt to this instance.
     */
    private final MultiplexingDatagramSocket multiplexing;

    /**
     * The list of <tt>DatagramPacket</tt>s to be received through this
     * <tt>DatagramSocket</tt> i.e. accepted by {@link #filter}.
     */
    final List<DatagramPacket> received
        = new LinkedList<DatagramPacket>();

    /**
     * Initializes a new <tt>MultiplexedDatagramSocket</tt> which is unbound and
     * filters <tt>DatagramPacket</tt>s away from a specific
     * <tt>MultiplexingDatagramSocket</tt> using a specific
     * <tt>DatagramPacketFilter</tt>.
     *
     * @param multiplexing the <tt>MultiplexingDatagramSocket</tt> which does
     * the actual reading from the network and which forwards
     * <tt>DatagramPacket</tt>s accepted by the specified <tt>filter</tt> to the
     * new instance
     * @param filter the <tt>DatagramPacketFilter</tt> which determines which
     * <tt>DatagramPacket</tt>s read from the network by the specified
     * <tt>multiplexing</tt> are to be received through the new instance
     * @throws SocketException if the socket could not be opened
     */
    MultiplexedDatagramSocket(
            MultiplexingDatagramSocket multiplexing,
            DatagramPacketFilter filter)
        throws SocketException
    {
        /*
         * Even if MultiplexingDatagramSocket allows MultiplexedDatagramSocket
         * to perform bind, binding in the super will not execute correctly this
         * early in the construction because the multiplexing field is not set
         * yet. That is why MultiplexedDatagramSocket does not currently support
         * bind at construction time.
         */
        super((SocketAddress) null);

        if (multiplexing == null)
            throw new NullPointerException("multiplexing");

        this.multiplexing = multiplexing;
        this.filter = filter;
    }

    /**
     * Binds this <tt>DatagramSocket</tt> to a specific address and port.
     * <p>
     * If the address is <tt>null</tt>, then the system will pick up an
     * ephemeral port and a valid local address to bind the socket.
     *</p>
     *
     * @param addr the address and port to bind to
     * @throws SocketException if any error happens during the bind, or if the
     * socket is already bound
     * @throws SecurityException if a security manager exists and its
     * <tt>checkListen</tt> method doesn't allow the operation
     * @throws IllegalArgumentException if <tt>addr</tt> is a
     * <tt>SocketAddress</tt> subclass not supported by this socket
     * @see DatagramSocket#bind(SocketAddress)
     */
    @Override
    public void bind(SocketAddress addr)
            throws SocketException
    {
        multiplexing.bind(addr);
    }

    /**
     * Closes this datagram socket.
     * <p>
     * Any thread currently blocked in {@link #receive(DatagramPacket)} upon
     * this socket will throw a {@link SocketException}.
     * </p>
     *
     * @see DatagramSocket#close()
     */
    @Override
    public void close()
    {
        multiplexing.close(this);
    }

    /**
     * Connects the socket to a remote address for this socket. When a socket is
     * connected to a remote address, packets may only be sent to or received
     * from that address. By default a datagram socket is not connected.
     * <p>
     * If the remote destination to which the socket is connected does not
     * exist, or is otherwise unreachable, and if an ICMP destination
     * unreachable packet has been received for that address, then a subsequent
     * call to {@link #send(DatagramPacket)} or {@link #receive(DatagramPacket)}
     * may throw a <tt>PortUnreachableException</tt>. Note, there is no
     * guarantee that the exception will be thrown.
     * </p>
     *
     * @param address the remote address for the socket
     * @param port the remote port for the socket
     * @throws IllegalArgumentException if the address is <tt>null</tt>, or the
     * port is out of range
     * @throws SecurityException if the caller is not allowed to send datagrams
     * to and receive datagrams from the address and port
     * @see DatagramSocket#connect(InetAddress, int)
     */
    @Override
    public void connect(InetAddress address, int port)
    {
        multiplexing.connect(address, port);
    }

    /**
     * Connects this socket to a remote socket address.
     *
     * @param addr the remote address
     * @throws SocketException if the connect fails
     * @throws IllegalArgumentException if <tt>addr</tt> is <tt>null</tt> or a
     * <tt>SocketAddress</tt> subclass not supported by this socket
     * @see DatagramSocket#connect(SocketAddress)
     */
    @Override
    public void connect(SocketAddress addr)
        throws SocketException
    {
        multiplexing.connect(addr);
    }

    /**
     * Disconnects the socket. This does nothing if the socket is not connected.
     *
     * @see DatagramSocket#disconnect()
     */
    @Override
    public void disconnect()
    {
        multiplexing.disconnect();
    }

    /**
     * Tests if <tt>SO_BROADCAST</tt> is enabled.
     *
     * @return a <tt>boolean</tt> indicating whether or not
     * <tt>SO_BROADCAST</tt> is enabled
     * @throws SocketException if there is an error in the underlying protocol,
     * such as an UDP error
     * @see DatagramSocket#getBroadcast()
     */
    @Override
    public boolean getBroadcast()
        throws SocketException
    {
        return multiplexing.getBroadcast();
    }

    /**
     * Returns the unique {@link DatagramChannel} object associated with this
     * datagram socket, if any.
     * <p>
     * A datagram socket will have a channel if, and only if, the channel itself
     * was created via the {@link DatagramChannel#open()} method
     * </p>
     *
     * @return the datagram channel associated with this datagram socket, or
     * <tt>null</tt> if this socket was not created for a channel
     * @see DatagramSocket#getChannel()
     */
    @Override
    public DatagramChannel getChannel()
    {
        return multiplexing.getChannel();
    }

    /**
     * Gets the <tt>DatagramPacketFilter</tt> which determines which
     * <tt>DatagramPacket</tt>s read from the network are to be received through
     * this <tt>DatagramSocket</tt>.
     *
     * @return the <tt>DatagramPacketFilter</tt> which determines which
     * <tt>DatagramPacket</tt>s read from the network are to be received through
     * this <tt>DatagramSocket</tt>
     */
    public DatagramPacketFilter getFilter()
    {
        return filter;
    }

    /**
     * Returns the address to which this socket is connected. Returns
     * <tt>null</tt> if the socket is not connected.
     *
     * @return the address to which this socket is connected
     * @see DatagramSocket#getInetAddress()
     */
    @Override
    public InetAddress getInetAddress()
    {
        return multiplexing.getInetAddress();
    }

    /**
     * Gets the local address to which the socket is bound.
     * <p>
     * If there is a security manager, its <tt>checkConnect</tt> method is first
     * called with the host address and <tt>-1</tt> as its arguments to see if
     * the operation is allowed.
     *
     * @return the local address to which the socket is bound, or an
     * <tt>InetAddress</tt> representing any local address if either the socket
     * is not bound, or the security manager <tt>checkConnect</tt> method does
     * not allow the operation
     * @see DatagramSocket#getLocalAddress()
     */
    @Override
    public InetAddress getLocalAddress()
    {
        return multiplexing.getLocalAddress();
    }

    /**
     * Returns the port number on the local host to which this socket is bound.
     *
     * @return the port number on the local host to which this socket is bound
     * @see DatagramSocket#getLocalPort()
     */
    @Override
    public int getLocalPort()
    {
        return multiplexing.getLocalPort();
    }

    /**
     * Returns the address of the endpoint this socket is bound to, or
     * <tt>null</tt> if it is not bound yet.
     *
     * @return a <tt>SocketAddress</tt> representing the local endpoint of this
     * socket, or <tt>null</tt> if it is not bound yet
     * @see DatagramSocket#getLocalSocketAddress()
     */
    @Override
    public SocketAddress getLocalSocketAddress()
    {
        return multiplexing.getLocalSocketAddress();
    }

    /**
     * Returns the port for this socket. Returns <tt>-1</tt> if the socket is
     * not connected.
     *
     * @return the port to which this socket is connected
     * @see DatagramSocket#getPort()
     */
    @Override
    public int getPort()
    {
        return multiplexing.getPort();
    }

    /**
     * Gets the value of the <tt>SO_RCVBUF</tt> option for this
     * <tt>DatagramSocket</tt>, that is the buffer size used by the platform for
     * input on this <tt>DatagramSocket</tt>.
     *
     * @return the value of the <tt>SO_RCVBUF</tt> option for this
     * <tt>DatagramSocket</tt>
     * @throws SocketException if there is an error in the underlying protocol,
     * such as an UDP error
     * @see DatagramSocket#getReceiveBufferSize()
     */
    @Override
    public int getReceiveBufferSize()
        throws SocketException
    {
        return multiplexing.getReceiveBufferSize();
    }

    /**
     * Returns the address of the endpoint this socket is connected to, or
     * <tt>null</tt> if it is unconnected.
     *
     * @return a <tt>SocketAddress</tt> representing the remote endpoint of this
     * socket, or <tt>null</tt> if it is not connected yet
     * @see DatagramSocket#getRemoteSocketAddress()
     */
    @Override
    public SocketAddress getRemoteSocketAddress()
    {
        return multiplexing.getRemoteSocketAddress();
    }

    /**
     * Tests if <tt>SO_REUSEADDR</tt> is enabled.
     *
     * @return a <tt>boolean</tt> indicating whether or not
     * <tt>SO_REUSEADDR</tt> is enabled
     * @throws SocketException if there is an error in the underlying protocol,
     * such as an UDP error
     * @see DatagramSocket#getReuseAddress()
     */
    @Override
    public boolean getReuseAddress()
        throws SocketException
    {
        return multiplexing.getReuseAddress();
    }

    /**
     * Gets the value of the <tt>SO_SNDBUF</tt> option for this
     * <tt>DatagramSocket</tt>, that is the buffer size used by the platform for
     * output on this <tt>DatagramSocket</tt>.
     *
     * @return the value of the <tt>SO_SNDBUF</tt> option for this
     * <tt>DatagramSocket</tt>
     * @throws SocketException if there is an error in the underlying protocol,
     * such as an UDP error
     * @see DatagramSocket#getSendBufferSize()
     */
    @Override
    public int getSendBufferSize()
        throws SocketException
    {
        return multiplexing.getSendBufferSize();
    }

    /**
     * Retrieves setting for <tt>SO_TIMEOUT</tt>.  Zero returned implies that
     * the option is disabled (i.e., timeout of infinity).
     *
     * @return the setting for <tt>SO_TIMEOUT</tt>
     * @throws SocketException if there is an error in the underlying protocol,
     * such as an UDP error
     * @see DatagramSocket#getSoTimeout()
     */
    @Override
    public int getSoTimeout()
        throws SocketException
    {
        return multiplexing.getSoTimeout();
    }

    /**
     * Gets the traffic class or type-of-service in the IP datagram header for
     * packets sent from this <tt>DatagramSocket</tt>.
     * <p>
     * As the underlying network implementation may ignore the traffic class or
     * type-of-service set using {@link #setTrafficClass(int)} this method may
     * return a different value than was previously set using the
     * {@link #setTrafficClass(int)} method on this <tt>DatagramSocket</tt>.
     * </p>
     *
     * @return the traffic class or type-of-service already set
     * @throws SocketException if there is an error obtaining the traffic class
     * or type-of-service value
     * @see DatagramSocket#getTrafficClass()
     */
    @Override
    public int getTrafficClass()
        throws SocketException
    {
        return multiplexing.getTrafficClass();
    }

    /**
     * Returns the binding state of the socket.
     *
     * @return <tt>true</tt> if the socket successfully bound to an address;
     * otherwise, <tt>false</tt>
     * @see DatagramSocket#isBound()
     */
    @Override
    public boolean isBound()
    {
        return multiplexing.isBound();
    }

    /**
     * Returns whether the socket is closed or not.
     *
     * @return <tt>true</tt> if the socket has been closed; otherwise,
     * <tt>false</tt>
     * @see DatagramSocket#isClosed()
     */
    @Override
    public boolean isClosed()
    {
        return multiplexing.isClosed();
    }

    /**
     * Returns the connection state of the socket.
     *
     * @return <tt>true</tt> if the socket successfully connected to a server;
     * otherwise, <tt>false</tt>
     * @see DatagramSocket#isConnected()
     */
    @Override
    public boolean isConnected()
    {
        return multiplexing.isConnected();
    }

    /**
     * Receives a datagram packet from this socket. When this method returns,
     * the <tt>DatagramPacket</tt>'s buffer is filled with the data received.
     * The datagram packet also contains the sender's IP address, and the port
     * number on the sender's machine.
     * <p>
     * This method blocks until a datagram is received. The <tt>length</tt>
     * field of the datagram packet object contains the length of the received
     * message. If the message is longer than the packet's length, the message
     * is truncated.
     * </p>
     * <p>
     * If there is a security manager, a packet cannot be received if the
     * security manager's <tt>checkAccept</tt> method does not allow it.
     * </p>
     *
     * @param p the <tt>DatagramPacket</tt> into which to place the incoming
     * data
     * @throws IOException if an I/O error occurs
     * @see DatagramSocket#receive(DatagramPacket)
     */
    @Override
    public void receive(DatagramPacket p)
        throws IOException
    {
        multiplexing.receive(this, p);
    }

    /**
     * Sends a datagram packet from this socket. The <tt>DatagramPacket</tt>
     * includes information indicating the data to be sent, its length, the IP
     * address of the remote host, and the port number on the remote host.
     * <p>
     * If there is a security manager, and the socket is not currently connected
     * to a remote address, this method first performs some security checks.
     * First, if <tt>p.getAddress().isMulticastAddress()</tt> is true, this
     * method calls the security manager's <tt>checkMulticast</tt> method with
     * <tt>p.getAddress()</tt> as its argument. If the evaluation of that
     * expression is <tt>false</tt>, this method instead calls the security
     * manager's <tt>checkConnect</tt> method with arguments
     * <tt>p.getAddress().getHostAddress()</tt> and <tt>p.getPort()</tt>. Each
     * call to a security manager method could result in a
     * <tt>SecurityException</tt> if the operation is not allowed.
     * </p>
     *
     * @param p the <tt>DatagramPacket</tt> to be sent
     * @throws IOException if an I/O error occurs
     * @see DatagramSocket#send(DatagramPacket)
     */
    @Override
    public void send(DatagramPacket p)
        throws IOException
    {
        multiplexing.send(p);
    }

    /**
     * Enables/disables <tt>SO_BROADCAST</tt>.
     *
     * @param on whether or not to have broadcast turned on
     * @throws SocketException if there is an error in the underlying protocol,
     * such as an UDP error
     * @see DatagramSocket#setBroadcast(boolean)
     */
    @Override
    public void setBroadcast(boolean on)
        throws SocketException
    {
        multiplexing.setBroadcast(on);
    }

    /**
     * Sets the <tt>SO_RCVBUF</tt> option to the specified value for this
     * <tt>DatagramSocket</tt>. The <tt>SO_RCVBUF</tt> option is used by the
     * network implementation as a hint to size the underlying network I/O
     * buffers. The <tt>SO_RCVBUF</tt> setting may also be used by the network
     * implementation to determine the maximum size of the packet that can be
     * received on this socket.
     * <p>
     * Because <tt>SO_RCVBUF</tt> is a hint, applications that want to verify
     * what size the buffers were set to should call
     * {@link #getReceiveBufferSize()}.
     * </p>
     *
     * @param size the size to which to set the receive buffer size. The value
     * must be greater than zero
     * @throws SocketException if there is an error in the underlying protocol,
     * such as an UDP error
     * @throws IllegalArgumentException if the value is zero or is negative
     * @see DatagramSocket#setReceiveBufferSize(int)
     */
    @Override
    public void setReceiveBufferSize(int size)
        throws SocketException
    {
        multiplexing.setReceiveBufferSize(size);
    }

    /**
     * Enables/disables the <tt>SO_REUSEADDR</tt> socket option.
     *
     * @param on whether to enable or disable the <tt>SO_REUSEADDR</tt> socket
     * option
     * @throws SocketException if an error occurs enabling or disabling the
     * <tt>SO_RESUEADDR</tt> socket option, or the socket is closed
     * @see DatagramSocket#setReuseAddress(boolean)
     */
    @Override
    public void setReuseAddress(boolean on)
        throws SocketException
    {
        multiplexing.setReuseAddress(on);
    }

    /**
     * Sets the <tt>SO_SNDBUF</tt> option to the specified value for this
     * <tt>DatagramSocket</tt>. The <tt>SO_SNDBUF</tt> option is used by the
     * network implementation as a hint to size the underlying network I/O
     * buffers. The <tt>SO_SNDBUF</tt> setting may also be used by the network
     * implementation to determine the maximum size of the packet that can be
     * sent on this socket.
     * <p>
     * As <tt>SO_SNDBUF</tt> is a hint, applications that want to verify what
     * size the buffer is should call {@link #getSendBufferSize()}.
     * </p>
     * <p>
     * Increasing the buffer size may allow multiple outgoing packets to be
     * queued by the network implementation when the send rate is high.
     * </p>
     *
     * @param size the size to which to set the send buffer size. The value must
     * be greater than zero
     * @throws SocketException if there is an error in the underlying protocol,
     * such as an UDP error
     * @throws IllegalArgumentException if the value is zero or is negative
     * @see DatagramSocket#setSendBufferSize(int)
     */
    @Override
    public void setSendBufferSize(int size)
        throws SocketException
    {
        multiplexing.setSendBufferSize(size);
    }

    /**
     * Enables/disables <tt>SO_TIMEOUT</tt> with the specified timeout, in
     * milliseconds. With this option set to a non-zero timeout, a call to
     * {@link #receive(DatagramPacket)} for this <tt>DatagramSocket</tt> will
     * block for only this amount of time.  If the timeout expires, a
     * <tt>SocketTimeoutException</tt> is raised, though the
     * <tt>DatagramSocket</tt> is still valid.  The option must be enabled prior
     * to entering the blocking operation to have effect.  The timeout must be
     * greater than zero. A timeout of zero is interpreted as an infinite
     * timeout.
     *
     * @param timeout the specified timeout in milliseconds
     * @throws SocketException if there is an error in the underlying protocol,
     * such as an UDP error
     * @see DatagramSocket#setSoTimeout(int)
     */
    @Override
    public void setSoTimeout(int timeout)
        throws SocketException
    {
        multiplexing.setSoTimeout(timeout);
    }

    /**
     * Sets traffic class or type-of-service octet in the IP datagram header for
     * datagrams sent from this <tt>DatagramSocket</tt>. As the underlying
     * network implementation may ignore this value applications should consider
     * it a hint.
     *
     * @param tc an <tt>int</tt> value for the bitset
     * @throws SocketException if there is an error setting the traffic class or
     * type-of-service
     * @see DatagramSocket#setTrafficClass(int)
     */
    @Override
    public void setTrafficClass(int tc)
        throws SocketException
    {
        multiplexing.setTrafficClass(tc);
    }
}
