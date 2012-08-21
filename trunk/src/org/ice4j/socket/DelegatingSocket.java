/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.socket;

import java.io.*;
import java.nio.channels.*;
import java.net.*;

/**
 * Implements a <tt>Socket</tt> which delegates its calls to a specific
 * <tt>Socket</tt>.
 *
 * @author Sebastien Vincent
 */
public class DelegatingSocket
    extends Socket
{
    /**
     * Delegate <tt>Socket</tt>.
     */
    protected final Socket delegate;

    /**
     * InputStream for this socket.
     */
    private InputStream inputStream = null;

    /**
     * OutputStream for this socket.
     */
    private OutputStream outputStream = null;

    /**
     * The number of RTP packets received for this socket.
     */
    private long nbReceivedRtpPackets = 0;

    /**
     * The number of RTP packets sent for this socket.
     */
    private long nbSentRtpPackets = 0;

    /**
     * The number of RTP packets lost (not received) for this socket.
     */
    private long nbLostRtpPackets = 0;

    /**
     * The last RTP sequence number received for this socket.
     */
    private long lastRtpSequenceNumber = -1;

    /**
     * The last time an information about packet lost has been logged.
     */
    private long lastLostPacketLogTime = 0;

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     */
    public DelegatingSocket()
    {
        delegate = null;
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @see Socket#Socket(InetAddress, int)
     */
    public DelegatingSocket(InetAddress address, int port)
        throws IOException
    {
        delegate = null;
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @see Socket#Socket(InetAddress, int, InetAddress, int)
     */
    public DelegatingSocket(InetAddress address, int port,
        InetAddress localAddr, int localPort)
        throws IOException
    {
        delegate = null;
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @see Socket#Socket(Proxy)
     */
    public DelegatingSocket(Proxy proxy)
    {
        delegate = null;
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @see Socket#Socket(SocketImpl)
     */
    protected DelegatingSocket(SocketImpl impl)
        throws SocketException
    {
        delegate = null;
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @see Socket#Socket(String, int)
     */
    public DelegatingSocket(String host, int port)
        throws UnknownHostException,
        IOException
    {
        delegate = null;
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @see Socket#Socket(String, int, InetAddress, int)
     */
    public DelegatingSocket(String host, int port, InetAddress localAddr,
        int localPort)
    {
        delegate = null;
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @param socket delegating socket
     */
    public DelegatingSocket(Socket socket)
    {
        super();
        this.delegate = socket;
    }

    /**
     * {@inheritDoc}
     */
    public void bind(SocketAddress bindpoint) throws IOException
    {
        if (delegate != null)
        {
            delegate.bind(bindpoint);
        }
        else
        {
            super.bind(bindpoint);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void close() throws IOException
    {
        if (delegate != null)
        {
            delegate.close();
        }
        else
        {
            super.close();
        }
    }

    /**
     * {@inheritDoc}
     */
    public void connect(SocketAddress endpoint) throws IOException
    {
        if (delegate != null)
        {
            delegate.connect(endpoint);
        }
        else
        {
            super.connect(endpoint);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void connect(SocketAddress endpoint, int timeout) throws IOException
    {
        if (delegate != null)
        {
            delegate.connect(endpoint, timeout);
        }
        else
        {
            super.connect(endpoint, timeout);
        }
    }

    /**
     * {@inheritDoc}
     */
    public SocketChannel getChannel()
    {
        if (delegate != null)
        {
            return delegate.getChannel();
        }
        else
        {
            return super.getChannel();
        }
    }

    /**
     * {@inheritDoc}
     */
    public InetAddress getInetAddress()
    {
        if (delegate != null)
        {
            return delegate.getInetAddress();
        }
        else
        {
            return super.getInetAddress();
        }
    }

    /**
     * {@inheritDoc}
     */
    public InputStream getInputStream() throws IOException
    {
        if (delegate != null)
        {
            return delegate.getInputStream();
        }
        else
        {
            return super.getInputStream();
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean getKeepAlive() throws SocketException
    {
        if (delegate != null)
        {
            return delegate.getKeepAlive();
        }
        else
        {
            return super.getKeepAlive();
        }
    }

    /**
     * {@inheritDoc}
     */
    public InetAddress getLocalAddress()
    {
        if (delegate != null)
        {
            return delegate.getLocalAddress();
        }
        else
        {
            return super.getLocalAddress();
        }
    }

    /**
     * {@inheritDoc}
     */
    public int getLocalPort()
    {
        if (delegate != null)
        {
            return delegate.getLocalPort();
        }
        else
        {
            return super.getLocalPort();
        }
    }

    /**
     * {@inheritDoc}
     */
    public SocketAddress getLocalSocketAddress()
    {
        if (delegate != null)
        {
            return delegate.getLocalSocketAddress();
        }
        else
        {
            return super.getLocalSocketAddress();
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean getOOBInline() throws SocketException
    {
        if (delegate != null)
        {
            return delegate.getOOBInline();
        }
        else
        {
            return super.getOOBInline();
        }
    }

    /**
     * {@inheritDoc}
     */
    public OutputStream getOutputStream() throws IOException
    {
        if (delegate != null)
        {
            return delegate.getOutputStream();
        }
        else
        {
            return super.getOutputStream();
        }
    }

    /**
     * {@inheritDoc}
     */
    public int getPort()
    {
        if (delegate != null)
        {
            return delegate.getPort();
        }
        else
        {
            return super.getPort();
        }
    }

    /**
     * {@inheritDoc}
     */
    public int getReceiveBufferSize() throws SocketException
    {
        if (delegate != null)
        {
            return delegate.getReceiveBufferSize();
        }
        else
        {
            return super.getReceiveBufferSize();
        }
    }

    /**
     * {@inheritDoc}
     */
    public SocketAddress getRemoteSocketAddress()
    {
        if (delegate != null)
        {
            return delegate.getRemoteSocketAddress();
        }
        else
        {
            return super.getRemoteSocketAddress();
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean getReuseAddress() throws SocketException
    {
        if (delegate != null)
        {
            return delegate.getReuseAddress();
        }
        else
        {
            return super.getReuseAddress();
        }
    }

    /**
     * {@inheritDoc}
     */
    public int getSendBufferSize() throws SocketException
    {
        if (delegate != null)
        {
            return delegate.getSendBufferSize();
        }
        else
        {
            return super.getSendBufferSize();
        }
    }

    /**
     * {@inheritDoc}
     */
    public int getSoLinger() throws SocketException
    {
        if (delegate != null)
        {
            return delegate.getSoLinger();
        }
        else
        {
            return super.getSoLinger();
        }
    }

    /**
     * {@inheritDoc}
     */
    public int getSoTimeout() throws SocketException
    {
        if (delegate != null)
        {
            return delegate.getSoTimeout();
        }
        else
        {
            return super.getSoTimeout();
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean getTcpNoDelay() throws SocketException
    {
        if (delegate != null)
        {
            return delegate.getTcpNoDelay();
        }
        else
        {
            return super.getTcpNoDelay();
        }
    }

    /**
     * {@inheritDoc}
     */
    public int getTrafficClass() throws SocketException
    {
        if (delegate != null)
        {
            return delegate.getTrafficClass();
        }
        else
        {
            return super.getTrafficClass();
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean isBound()
    {
        if (delegate != null)
        {
            return delegate.isBound();
        }
        else
        {
            return super.isBound();
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean isClosed()
    {
        if (delegate != null)
        {
            return delegate.isClosed();
        }
        else
        {
            return super.isClosed();
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean isConnected()
    {
        if (delegate != null)
        {
            return delegate.isConnected();
        }
        else
        {
            return super.isConnected();
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean isInputShutdown()
    {
        if (delegate != null)
        {
            return delegate.isInputShutdown();
        }
        else
        {
            return super.isInputShutdown();
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean isOutputShutdown()
    {
        if (delegate != null)
        {
            return delegate.isOutputShutdown();
        }
        else
        {
            return super.isOutputShutdown();
        }
    }

    /**
     * {@inheritDoc}
     */
    public void sendUrgentData(int data) throws IOException
    {
        if (delegate != null)
        {
            delegate.sendUrgentData(data);
        }
        else
        {
            super.sendUrgentData(data);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void setKeepAlive(boolean on) throws SocketException
    {
        if (delegate != null)
        {
            delegate.setKeepAlive(on);
        }
        else
        {
            super.setKeepAlive(on);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void setOOBInline(boolean on) throws SocketException
    {
        if (delegate != null)
        {
            delegate.setOOBInline(on);
        }
        else
        {
            super.setOOBInline(on);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void setPerformancePreferences(int connectionTime, int latency,
        int bandwidth)
    {
        if (delegate != null)
        {
            delegate.setPerformancePreferences(connectionTime, bandwidth,
                bandwidth);
        }
        else
        {
            super.setPerformancePreferences(connectionTime, latency, bandwidth);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void setReceiveBufferSize(int size) throws SocketException
    {
        if (delegate != null)
        {
            delegate.setReceiveBufferSize(size);
        }
        else
        {
            super.setReceiveBufferSize(size);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void setReuseAddress(boolean on) throws SocketException
    {
        if (delegate != null)
        {
            delegate.setReuseAddress(on);
        }
        else
        {
            super.setReuseAddress(on);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void setSendBufferSize(int size) throws SocketException
    {
        if (delegate != null)
        {
            delegate.setSendBufferSize(size);
        }
        else
        {
            super.setSendBufferSize(size);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void setSoLinger(boolean on, int linger) throws SocketException
    {
        if (delegate != null)
        {
            delegate.setSoLinger(on, linger);
        }
        else
        {
            super.setSoLinger(on, linger);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void setSoTimeout(int timeout) throws SocketException
    {
        if (delegate != null)
        {
            delegate.setSoTimeout(timeout);
        }
        else
        {
            super.setSoTimeout(timeout);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void setTcpNoDelay(boolean on) throws SocketException
    {
        if (delegate != null)
        {
            delegate.setTcpNoDelay(on);
        }
        else
        {
            super.setTcpNoDelay(on);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void setTrafficClass(int tc) throws SocketException
    {
        if (delegate != null)
        {
            delegate.setTrafficClass(tc);
        }
        else
        {
            super.setTrafficClass(tc);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void shutdownInput() throws IOException
    {
        if (delegate != null)
        {
            delegate.shutdownInput();
        }
        else
        {
            super.shutdownInput();
        }
    }

    /**
     * {@inheritDoc}
     */
    public void shutdownOutput() throws IOException
    {
        if (delegate != null)
        {
            delegate.shutdownOutput();
        }
        else
        {
            super.shutdownOutput();
        }
    }

    /**
     * {@inheritDoc}
     */
    public String toString()
    {
        if (delegate != null)
        {
            return delegate.toString();
        }
        else
        {
            return super.toString();
        }
    }

    /**
     * Send a datagram packet from this socket.
     *
     * @param p <tt>DatagramPacket</tt> to sent
     * @throws IOException if something goes wrong during send
     */
    public void send(DatagramPacket p) throws IOException
    {
        // The delegate socket will encapsulate the packet.
        if (delegate != null && delegate instanceof DelegatingSocket)
        {
            ((DelegatingSocket) delegate).send(p);
            return;
        }

        if (outputStream == null)
        {
            outputStream = getOutputStream();
        }

        // Else, sends the packet to the final socket (outputStream).
        outputStream.write(p.getData(), p.getOffset(), p.getLength());

        // no exception packet is successfully sent, log it.
        ++nbSentRtpPackets;
        InetSocketAddress localAddress
            = (InetSocketAddress) super.getLocalSocketAddress();
        DelegatingDatagramSocket.logPacketToPcap(
                p,
                this.nbSentRtpPackets,
                true,
                localAddress.getAddress(),
                localAddress.getPort());
    }

    /**
     * Receives a datagram packet from this socket. The <tt>DatagramPacket</tt>s
     * returned by this method do not match any of the
     * <tt>DatagramPacketFilter</tt>s of the <tt>MultiplexedSocket</tt>s
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
     *            data
     * @throws IOException if an I/O error occurs
     * @see #receive(DatagramPacket)
     */
    public void receive(DatagramPacket p)
        throws IOException
    {
        if (delegate != null && delegate instanceof DelegatingSocket)
        {
            ((DelegatingSocket) delegate).receive(p);
        }
        else
        {
            if (inputStream == null)
            {
                inputStream = this.getInputStream();
            }

            DelegatingSocket.receiveFromNetwork(
                    p,
                    inputStream,
                    this.getInetAddress(),
                    this.getPort());

            // no exception packet is successfully received, log it.
            // If this is not a STUN/TURN packet, then this is a RTP packet.
            if(!StunDatagramPacketFilter.isStunPacket(p))
            {
                ++nbReceivedRtpPackets;
            }
            InetSocketAddress localAddress
                = (InetSocketAddress) super.getLocalSocketAddress();
            DelegatingDatagramSocket.logPacketToPcap(
                    p,
                    this.nbReceivedRtpPackets,
                    false,
                    localAddress.getAddress(),
                    localAddress.getPort());
            // Log RTP losses if > 5%.
            updateRtpLosses(p);
        }

    }

    /**
     * Reads TCP stream and fit corresponding bytes to the datagram given in
     * parameter.
     *
     * @param p the <tt>DatagramPacket</tt> into which to place the incoming
     * data.
     * @param inputStream The TCP stream to be read.
     * @param inetAddress The receiver address (local address) to set to the
     * datagram packet.
     * @param port The receiver port (local port) to set to the datagram packet.
     *
     * @throws IOException if an I/O error occurs
     * @see #receive(DatagramPacket)
     */
    public static void receiveFromNetwork(
            DatagramPacket p,
            InputStream inputStream,
            InetAddress inetAddress,
            int port)
        throws IOException
    {
        byte data[] = p.getData();
        int len = 0;

        int fb = inputStream.read();
        int sb = inputStream.read();

        // If we do not achieve to read the first bytes, then it was just an
        // hole punch packet.
        if(fb == -1 || sb == -1)
        {
            p.setLength(0);
            throw new SocketException("read failed");
        }

        int desiredLength = (((fb & 0xff) << 8) | (sb & 0xff));
        int readLen = 0;
        int offset = 0;

        while(readLen < desiredLength)
        {
            len = inputStream.read(data, offset, desiredLength - offset);
            if(len == -1)
                throw new SocketException("read failed");
            offset += len;
            readLen += len;
        }

        if (readLen == desiredLength)
        {
            p.setData(data);
            p.setLength(len);
            p.setAddress(inetAddress);
            p.setPort(port);
        }
        else
        {
            throw new SocketException("Failed to receive data from socket");
        }

        data = null;
    }

    /**
     * Set original <tt>InputStream</tt>.
     *
     * @param inputStream <tt>InputStream</tt>
     */
    public void setOriginalInputStream(InputStream inputStream)
    {
        if(this.inputStream == null && inputStream != null)
            this.inputStream = inputStream;
    }

    /**
     * Updates and Logs information about RTP losses if there is more then 5% of
     * RTP packet lost (at most every 5 seconds).
     *
     * @param p The last packet received.
     */
    public void updateRtpLosses(DatagramPacket p)
    {
        // If this is not a STUN/TURN packet, then this is a RTP packet.
        if(!StunDatagramPacketFilter.isStunPacket(p))
        {
            long newSeq = DelegatingDatagramSocket.getRtpSequenceNumber(p);
            if(this.lastRtpSequenceNumber != -1)
            {
                nbLostRtpPackets += DelegatingDatagramSocket
                    .getNbLost(this.lastRtpSequenceNumber, newSeq);
            }
            this.lastRtpSequenceNumber = newSeq;

            this.lastLostPacketLogTime = DelegatingDatagramSocket.logRtpLosses(
                    this.nbLostRtpPackets,
                    this.nbReceivedRtpPackets,
                    this.lastLostPacketLogTime);
        }
    }
}
