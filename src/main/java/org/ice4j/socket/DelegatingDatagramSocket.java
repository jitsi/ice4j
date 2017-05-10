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
import java.nio.channels.*;

import org.ice4j.stack.*;

/**
 * Implements a <tt>DatagramSocket</tt> which delegates its calls to a specific
 * <tt>DatagramSocket</tt>.
 *
 * @author Lyubomir Marinov
 */
public class DelegatingDatagramSocket
    extends DatagramSocket
{
    /**
     * Assigns a factory to generate custom DatagramSocket to replace classical
     * "java" DatagramSocket. This way external applications can define the
     * type of DatagramSocket to use.
     * If "null", then the classical "java" DatagramSocket is used. Otherwise
     * the factory generates custom DatagramSockets.
     */
    private static DatagramSocketFactory delegateFactory = null;

    /**
     * The size to which to set the receive buffer size. This value must set by
     * using the DelegatingDatagramSocket.setDefaultReceiveBufferSize(int)
     * function before calling the DelegatingDatagramSocket constructor and must
     * be greater than 0 to be effective.
     */
    private static int defaultReceiveBufferSize = -1;

    /**
     * If a factory is provided, then any new instances of
     * DelegatingDatagramSocket will automatically use a socket from  the
     * factory instead of the super class.
     *
     * If this method is used, the factory class needs to ensure the socket
     * objects are properly constructed and initialized - in particular, any
     * default receive buffer size specified through
     * DelegatingDatagramSocket#setDefaultReceiveBufferSize() won't
     * automatically be applied to sockets obtain from the factory.
     *
     * @param factory The factory assigned to generates the new DatagramSocket
     * for each new DelegatingDatagramSocket which do not use a delegate socket.
     */
    public static void setDefaultDelegateFactory(DatagramSocketFactory factory)
    {
        delegateFactory = factory;
    }

    /**
     * Specifies a default receive buffer size for the underlying sockets.
     * This function must be called before using the DelegatingDatagramSocket
     * constructor. The size must be greater than 0 to be effective.
     *
     * @see DatagramSocket#setReceiveBufferSize(int) for a discussion of the
     * effect of changing this setting.
     *
     * @param size the size to which to set the receive buffer size. This value
     * must be greater than 0.
     */
    public static void setDefaultReceiveBufferSize(int size)
    {
        defaultReceiveBufferSize = size;
    }

    /**
     * Determines whether a packet should be logged, given the number of sent
     * or received packets.
     *
     * @param numOfPacket the number of packets sent or received.
     */
    static boolean logNonStun(long numOfPacket)
    {
        return (numOfPacket == 1)
                || (numOfPacket == 300)
                || (numOfPacket == 500)
                || (numOfPacket == 1000)
                || ((numOfPacket % 5000) == 0);
    }

    /**
     * The <tt>DatagramSocket</tt> to which this
     * <tt>DelegatingDatagramSocket</tt> delegates its calls.
     */
    protected final DatagramSocket delegate;

    /**
     * The number of non-STUN packets received on this socket.
     */
    private long nbReceivedPackets = 0;

    /**
     * The number of non-STUN packets sent through this socket.
     */
    private long nbSentPackets = 0;

    /**
     * Whether this socket has been closed.
     */
    private boolean closed = false;

    /**
     * Initializes a new <tt>DelegatingDatagramSocket</tt> instance and binds it
     * to any available port on the local host machine.  The socket will be
     * bound to the wildcard address, an IP address chosen by the kernel.
     *
     * @throws SocketException if the socket could not be opened, or the socket
     * could not bind to the specified local port
     * @see DatagramSocket#DatagramSocket()
     */
    public DelegatingDatagramSocket()
        throws SocketException
    {
        this(null, new InetSocketAddress(0));
    }

    /**
     * Initializes a new <tt>DelegatingDatagramSocket</tt> instance which to
     * implement the <tt>DatagramSocket</tt> functionality by delegating to a
     * specific <tt>DatagramSocket</tt>.
     *
     * @param delegate the <tt>DatagramSocket</tt> to which the new instance is
     * to delegate
     * @throws SocketException if anything goes wrong while initializing the new
     * <tt>DelegatingDatagramSocket</tt> instance
     */
    public DelegatingDatagramSocket(DatagramSocket delegate)
        throws SocketException
    {
        this(delegate, null);
    }

    /**
     * Initializes a new <tt>DelegatingDatagramSocket</tt> instance  and binds
     * it to the specified port on the local host machine.  The socket will be
     * bound to the wildcard address, an IP address chosen by the kernel.
     *
     * @param port the port to bind the new socket to
     * @throws SocketException if the socket could not be opened, or the socket
     * could not bind to the specified local port
     * @see DatagramSocket#DatagramSocket(int)
     */
    public DelegatingDatagramSocket(int port)
        throws SocketException
    {
        this(null, new InetSocketAddress(port));
    }

    /**
     * Initializes a new <tt>DelegatingDatagramSocket</tt> instance bound to the
     * specified local address.  The local port must be between 0 and 65535
     * inclusive. If the IP address is 0.0.0.0, the socket will be bound to the
     * wildcard address, an IP address chosen by the kernel.
     *
     * @param port the local port to bind the new socket to
     * @param laddr the local address to bind the new socket to
     * @throws SocketException if the socket could not be opened, or the socket
     * could not bind to the specified local port
     * @see DatagramSocket#DatagramSocket(int, InetAddress)
     */
    public DelegatingDatagramSocket(int port, InetAddress laddr)
        throws SocketException
    {
        this(null, new InetSocketAddress(laddr, port));
    }

    /**
     * Creates a datagram socket, bound to the specified local socket address.
     * <p>
     * If, if the address is <tt>null</tt>, creates an unbound socket.
     * </p>
     *
     * @param bindaddr local socket address to bind, or <tt>null</tt> for an
     * unbound socket
     * @throws SocketException if the socket could not be opened, or the socket
     * could not bind to the specified local port
     */
    public DelegatingDatagramSocket(SocketAddress bindaddr)
        throws SocketException
    {
        this(null, bindaddr);
    }

    /**
     * Initializes a new <tt>DelegatingDatagramSocket</tt> instance which
     * implements the <tt>DatagramSocket</tt> functionality. If delegate is not
     * null, then the DatagramSocket functionality is delegated to a specific
     * <tt>DatagramSocket</tt>.
     *
     * @param delegate the <tt>DatagramSocket</tt> to which the new instance is
     * to delegate.
     * @param address The local socket address to bind, or <tt>null</tt> for an
     * unbound socket.
     *
     * @throws SocketException if the socket could not be opened, or the socket
     * could not bind to the specified local port.
     */
    public DelegatingDatagramSocket(
            DatagramSocket delegate,
            SocketAddress address)
        throws SocketException
    {
        super((SocketAddress) null);

        // Delegates the DatagramSocket functionality to the DatagramSocket
        // given in parameter.
        if(delegate != null)
        {
            this.delegate = delegate;
        }
        else
        {
            // Creates a custom DatagramSocket to replace classical "java"
            // DatagramSocket and set it as a delegate Socket
            if(delegateFactory != null)
            {
                this.delegate = delegateFactory.createUnboundDatagramSocket();
            }
            // Creates a socket directly connected to the network stack.
            else
            {
                this.delegate = null;
                initReceiveBufferSize();
            }
            // If not null, binds the delegate socket to the given address.
            // Otherwise bind the "super" socket to this address.
            bind(address);
        }
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
        if (delegate == null)
            super.bind(addr);
        else
            delegate.bind(addr);
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
        // We want both #delegate and super to actually get closed (and release
        // the FDs which they hold). But super will not close unless isClosed()
        // returns false. So we update the #closed flag last.
        if (delegate != null)
            delegate.close();

        super.close();
        closed = true;
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
        if (delegate == null)
            super.connect(address, port);
        else
            delegate.connect(address, port);
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
        if (delegate == null)
            super.connect(addr);
        else
            delegate.connect(addr);
    }

    /**
     * Disconnects the socket. This does nothing if the socket is not connected.
     *
     * @see DatagramSocket#disconnect()
     */
    @Override
    public void disconnect()
    {
        if (delegate == null)
            super.disconnect();
        else
            delegate.disconnect();
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
        return
            (delegate == null) ? super.getBroadcast() : delegate.getBroadcast();
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
        return (delegate == null) ? super.getChannel() : delegate.getChannel();
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
        return
            (delegate == null)
                ? super.getInetAddress()
                : delegate.getInetAddress();
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
        return
            (delegate == null)
                ? super.getLocalAddress()
                : delegate.getLocalAddress();
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
        return
            (delegate == null) ? super.getLocalPort() : delegate.getLocalPort();
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
        return
            (delegate == null)
                ? super.getLocalSocketAddress()
                : delegate.getLocalSocketAddress();
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
        return (delegate == null) ? super.getPort() : delegate.getPort();
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
        return
            (delegate == null)
                ? super.getReceiveBufferSize()
                : delegate.getReceiveBufferSize();
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
        return
            (delegate == null)
                ? super.getRemoteSocketAddress()
                : delegate.getRemoteSocketAddress();
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
        return
            (delegate == null)
                ? super.getReuseAddress()
                : delegate.getReuseAddress();
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
        return
            (delegate == null)
                ? super.getSendBufferSize()
                : delegate.getSendBufferSize();
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
        return
            (delegate == null) ? super.getSoTimeout() : delegate.getSoTimeout();
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
        return
            (delegate == null)
                ? super.getTrafficClass()
                : delegate.getTrafficClass();
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
        return (delegate == null) ? super.isBound() : delegate.isBound();
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
        return closed;
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
        return (delegate == null) ? super.isConnected() :
            delegate.isConnected();
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
        if (delegate == null)
        {
            // If the packet length is too small, then the
            // DatagramSocket.receive function will truncate the received
            // datagram. This problem appears when reusing the same
            // DatagramPacket i.e. if the first time we use the DatagramPacket
            // to receive a small packet and the second time a bigger one, then
            // after the first packet is received, the length is set to the size
            // of the first packet and the second packet is truncated.
            // http://docs.oracle.com/javase/6/docs/api/java/net/DatagramSocket.html
            //
            // XXX(boris): I think the above is wrong. I don't interpret the
            // API description this way, and testing on a couple of different
            // environments shows that  DatagramSocket.receive() grows the
            // packet's length to as much as much as the array (and offset)
            // would allow. I am leaving the code because it seems harmless.
            byte[] data = p.getData();

            p.setLength((data == null) ? 0 : (data.length - p.getOffset()));

            super.receive(p);

            if (StunDatagramPacketFilter.isStunPacket(p)
                    || logNonStun(++nbReceivedPackets))
            {
                StunStack.logPacketToPcap(
                        p,
                        false,
                        getLocalAddress(),
                        getLocalPort());
            }
        }
        else
        {
            delegate.receive(p);
        }
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
        // Sends the packet to the final DatagramSocket
        if (delegate == null)
        {
            try
            {
                super.send(p);
            }
            // DIRTY, DIRTY, DIRTY!!!
            // Here we correct a java under MAC OSX bug when dealing with
            // ipv6 local interface: the destination address (as well as the
            // source address) under java / MAC OSX must have a scope ID,
            // i.e.  "fe80::1%en1".  This correction (the whole "catch") is to
            // be removed as soon as java under MAC OSX implements a real ipv6
            // network stack.
            catch(Exception ex)
            {
                InetAddress tmpAddr = p.getAddress();
                if(((ex instanceof NoRouteToHostException)
                            || (ex.getMessage() != null
                                && ex.getMessage().equals("No route to host")))
                        && (tmpAddr instanceof Inet6Address)
                        && (tmpAddr.isLinkLocalAddress()))
                {
                    Inet6Address newAddr = Inet6Address.getByAddress(
                            "",
                            tmpAddr.getAddress(),
                            ((Inet6Address) super.getLocalAddress())
                            .getScopeId());
                    p.setAddress(newAddr);

                    super.send(p);

                } else if (ex instanceof IOException) {
                	throw((IOException)ex);
                }
           }

            if (logNonStun(++nbSentPackets))
            {
                StunStack.logPacketToPcap(
                        p,
                        true,
                        getLocalAddress(),
                        getLocalPort());
            }
        }
        // Else, the delegate socket will encapsulate the packet.
        else
        {
            delegate.send(p);
        }
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
        if (delegate == null)
            super.setBroadcast(on);
        else
            delegate.setBroadcast(on);
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
        if (delegate == null)
            super.setReceiveBufferSize(size);
        else
            delegate.setReceiveBufferSize(size);
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
        if (delegate == null)
            super.setReuseAddress(on);
        else
            delegate.setReuseAddress(on);
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
        if (delegate == null)
            super.setSendBufferSize(size);
        else
            delegate.setSendBufferSize(size);
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
        if (delegate == null)
            super.setSoTimeout(timeout);
        else
            delegate.setSoTimeout(timeout);
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
        if (delegate == null)
            super.setTrafficClass(tc);
        else
            delegate.setTrafficClass(tc);
    }


    /**
     * A utility method used by the constructors to ensure the receive buffer
     * size is set to the preferred default.
     * 
     * This implementation only has an impact of there is no delegate, in other
     * words, if we really are using the superclass socket implementation as the
     * raw socket.
     * 
     * @throws SocketException if there is an error in the underlying protocol,
     * such as an UDP error.
     */
    private void initReceiveBufferSize()
        throws SocketException
    {
        // Only change the buffer size on the real underlying DatagramSocket.
        if(delegate == null && defaultReceiveBufferSize > 0)
        {
            super.setReceiveBufferSize(defaultReceiveBufferSize);
        }
    }
}
