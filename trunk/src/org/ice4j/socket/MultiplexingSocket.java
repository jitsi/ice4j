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
import java.util.*;
import java.util.logging.*;

/**
 * Represents a <tt>Socket</tt> which allows filtering
 * <tt>DatagramPacket</tt>s it reads from the network using
 * <tt>DatagramPacketFilter</tt>s so that the <tt>DatagramPacket</tt>s do not
 * get received through it but through associated <tt>MultiplexedSocket</tt>s.
 *
 * @author Sebastien Vincent
 * @author Lyubomir Marinov
 */
public class MultiplexingSocket
    extends DelegatingSocket
{
    /**
     * The <tt>Logger</tt> used by the <tt>MultiplexingSocket</tt> class
     * and its instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(MultiplexingSocket.class.getName());

    /**
     * The constant which represents an empty array with
     * <tt>MultiplexedSocket</tt> element type. Explicitly defined in
     * order to reduce allocations.
     */
    private static final MultiplexedSocket[] NO_SOCKETS
        = new MultiplexedSocket[0];

    /**
     * The indicator which determines whether this <tt>Socket</tt> is
     * currently reading from the network  using
     * {@link #receive(DatagramPacket)}. When <tt>true</tt>,
     * subsequent requests to read from the network will be blocked until the
     * current read is finished.
     */
    private boolean inReceive = false;

    /**
     * The list of <tt>DatagramPacket</tt>s to be received through this
     * <tt>Socket</tt> i.e. not accepted by the <tt>DatagramFilter</tt>s
     * of {@link #sockets} at the time of the reading from the network.
     */
    private final List<DatagramPacket> received
        = new LinkedList<DatagramPacket>();

    /**
     * Custom <tt>InputStream</tt> for this <tt>Socket</tt>.
     */
    private final TCPInputStream inputStream = new TCPInputStream();

    /**
     * Custom <tt>OutputStream</tt> for this <tt>Socket</tt>.
     */
    private TCPOutputStream outputStream = null;

    /**
     * The <tt>Object</tt> which synchronizes the access to {@link #inReceive}.
     */
    private final Object receiveSyncRoot = new Object();

    /**
     * The <tt>MultiplexedSocket</tt>s filtering <tt>DatagramPacket</tt>s
     * away from this <tt>Socket</tt>.
     */
    private MultiplexedSocket[] sockets = NO_SOCKETS;

    /**
     * The <tt>Object</tt> which synchronizes the access to the {@link #sockets}
     * field of this instance.
     */
    private final Object socketsSyncRoot = new Object();

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @see Socket#Socket()
     */
    public MultiplexingSocket()
    {
        super();
        try
        {
            setTcpNoDelay(true);
        }
        catch(SocketException e)
        {
            logger.info("Cannot SO_TCPNODELAY");
        }
    }

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @see Socket#Socket(InetAddress, int)
     */
    public MultiplexingSocket(InetAddress address, int port)
        throws IOException
    {
        super(address, port);
        try
        {
            setTcpNoDelay(true);
        }
        catch(SocketException e)
        {
            logger.info("Cannot SO_TCPNODELAY");
        }
    }

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @see Socket#Socket(InetAddress, int, InetAddress, int)
     */
    public MultiplexingSocket(InetAddress address, int port,
        InetAddress localAddr, int localPort)
        throws IOException
    {
        super(address, port, localAddr, localPort);
        try
        {
            setTcpNoDelay(true);
        }
        catch(SocketException e)
        {
            logger.info("Cannot SO_TCPNODELAY");
        }
    }

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @see Socket#Socket(Proxy)
     */
    public MultiplexingSocket(Proxy proxy)
    {
        super(proxy);
        try
        {
            setTcpNoDelay(true);
        }
        catch(SocketException e)
        {
            logger.info("Cannot SO_TCPNODELAY");
        }
    }

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @see Socket#Socket(SocketImpl)
     */
    protected MultiplexingSocket(SocketImpl impl)
        throws SocketException
    {
        super(impl);
        try
        {
            setTcpNoDelay(true);
        }
        catch(SocketException e)
        {
            logger.info("Cannot SO_TCPNODELAY");
        }
    }

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @see Socket#Socket(String, int)
     */
    public MultiplexingSocket(String host, int port)
        throws UnknownHostException,
               IOException
    {
        super(host, port);
        try
        {
            setTcpNoDelay(true);
        }
        catch(SocketException e)
        {
            logger.info("Cannot SO_TCPNODELAY");
        }
    }

    /**
     * Initializes a new <tt>MultiplexingSocket</tt> instance.
     *
     * @see Socket#Socket(String, int, InetAddress, int)
     */
    public MultiplexingSocket(String host, int port,
        InetAddress localAddr, int localPort)
    {
         super(host, port, localAddr, localPort);
         try
         {
             setTcpNoDelay(true);
         }
         catch(SocketException e)
         {
             logger.info("Cannot SO_TCPNODELAY");
         }
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
        catch(SocketException e)
        {
            logger.info("Cannot SO_TCPNODELAY");
        }
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
        receive(received, p);
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
    void receive(
            MultiplexedSocket multiplexed,
            DatagramPacket p)
        throws IOException
    {
        try
        {
            setOriginalInputStream(super.getInputStream());
        }
        catch(Exception e)
        {
        }
        receive(multiplexed.received, p);
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
     * @throws IOException if an I/O error occurs
     */
    private void receive(List<DatagramPacket> received, DatagramPacket p)
        throws IOException
    {
        DatagramPacket r = null;

        do
        {
            boolean doReceive;

            synchronized (receiveSyncRoot)
            {
                if (received.isEmpty())
                {
                    if (inReceive)
                    {
                        doReceive = false;
                        try
                        {
                            receiveSyncRoot.wait();
                        }
                        catch (InterruptedException iex)
                        {
                            continue;
                        }
                    }
                    else
                    {
                        doReceive = true;
                        inReceive = true;
                    }
                }
                else
                {
                    doReceive = false;
                    r = received.remove(0);
                }
            }
            if (doReceive)
            {
                try
                {
                    super.receive(p);

                    synchronized (receiveSyncRoot)
                    {
                        synchronized (socketsSyncRoot)
                        {
                            boolean accepted = false;

                            for (MultiplexedSocket socket : sockets)
                                if (socket.getFilter().accept(p))
                                {
                                    socket.received.add(
                                        MultiplexingDatagramSocket.clone(p));
                                    accepted = true;

                                    /*
                                     * Emil: Don't break because we want all
                                     * filtering sockets to get this.
                                     */
                                    //break;
                                }

                            if (!accepted)
                                addReceivedPacket(p);
                        }
                    }
                }
                finally
                {
                    synchronized (receiveSyncRoot)
                    {
                        inReceive = false;
                        receiveSyncRoot.notify();
                    }
                }
            }
        }
        while (r == null);

        MultiplexingDatagramSocket.copy(r, p);
    }

    /**
     * Close socket.
     */
    public void close()
    {
        try
        {
            super.close();
        }
        catch(IOException e)
        {
        }
    }

    /**
     * Closes a specific <tt>MultiplexedSocket</tt> which filters
     * <tt>DatagramPacket</tt>s away from this <tt>Socket</tt>.
     *
     * @param multiplexed the <tt>MultiplexedSocket</tt> to close
     */
    void close(MultiplexedSocket multiplexed)
    {
        synchronized (socketsSyncRoot)
        {
            int socketCount = sockets.length;

            for (int i = 0; i < socketCount; i++)
            {
                if (sockets[i].equals(multiplexed))
                {
                    if (socketCount == 1)
                        sockets = NO_SOCKETS;
                    else
                    {
                        MultiplexedSocket[] newSockets
                            = new MultiplexedSocket[socketCount - 1];

                        System.arraycopy(sockets, 0, newSockets, 0, i);
                        System.arraycopy(
                                sockets, i + 1,
                                newSockets, i,
                                newSockets.length - i);
                        sockets = newSockets;
                    }
                    break;
                }
            }
        }
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
        if (filter == null)
            throw new NullPointerException("filter");

        synchronized (socketsSyncRoot)
        {
            /*
             * If a socket for the specified filter exists already, do not
             * create a new one and return the existing.
             */
            for (MultiplexedSocket socket : sockets)
                    if (filter.equals(socket.getFilter()))
                        return socket;

            // Create a new socket for the specified filter.
            MultiplexedSocket socket
                = new MultiplexedSocket(this, filter);

            // Remember the new socket.
            int socketCount = sockets.length;

            if (socketCount == 0)
                sockets = new MultiplexedSocket[] { socket };
            else
            {
                MultiplexedSocket[] newSockets
                    = new MultiplexedSocket[socketCount + 1];

                System.arraycopy(sockets, 0, newSockets, 0, socketCount);
                newSockets[socketCount] = socket;
                sockets = newSockets;
            }

            return socket;
        }
    }

    /**
     * Add received packet.
     *
     * @param p <tt>DatagramPacket</tt>
     */
    public void addReceivedPacket(DatagramPacket p)
    {
        byte data[] = p.getData();
        int len = p.getLength();
        byte newData[] = new byte[len];

        System.arraycopy(data, p.getOffset(), newData, 0, len);
        inputStream.addPacket(newData);
    }

    /**
     * {@inheritDoc}
     */
    public InputStream getInputStream()
        throws IOException
    {
        return inputStream;
    }

    /**
     * {@inheritDoc}
     */
    public OutputStream getOutputStream()
        throws IOException
    {
        if(outputStream == null)
        {
            outputStream = new TCPOutputStream(super.getOutputStream());
        }

        return outputStream;
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
}
