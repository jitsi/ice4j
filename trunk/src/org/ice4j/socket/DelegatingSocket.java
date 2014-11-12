/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.socket;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;

/**
 * Implements a <tt>Socket</tt> which delegates its calls to a specific
 * <tt>Socket</tt>.
 *
 * @author Sebastien Vincent
 * @author Lyubomir Marinov
 */
public class DelegatingSocket
    extends Socket
{
    /**
     * Receives an RFC4571-formatted frame from <tt>inputStream</tt> into
     * <tt>p</tt>, and sets <tt>p</tt>'s port and address to <tt>port</tt> and
     * <tt>inetAddress</tt>.
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
    public static void receiveFromInputStream(
            DatagramPacket p,
            InputStream inputStream,
            InetAddress inetAddress, int port)
        throws IOException
    {
        int b0 = inputStream.read();
        int b1 = inputStream.read();

        // If we do not achieve to read the first bytes, then it was just a hole
        // punch packet.
        if (b0 == -1 || b1 == -1)
        {
            p.setLength(0);
            throw new SocketException("read failed");
        }

        int frameLen = ((b0 & 0xFF) << 8) | (b1 & 0xFF);
        int readLen = 0;
        byte[] data = p.getData();
        int off = 0;

        while (readLen < frameLen)
        {
            int len = inputStream.read(data, off, frameLen - off);

            if (len == -1)
            {
                throw new SocketException("read failed");
            }
            else
            {
                off += len;
                readLen += len;
            }
        }

        if (readLen == frameLen)
        {
            p.setAddress(inetAddress);
            p.setData(data, 0, frameLen);
            p.setPort(port);
        }
        else
        {
            throw new SocketException("Failed to receive data from socket");
        }
    }

    /**
     * Delegate <tt>Socket</tt>.
     */
    protected final Socket delegate;

    /**
     * A <tt>DelegatingSocket</tt> view of {@link #delegate} if the latter
     * implements the former; otherwise, <tt>null</tt>.
     */
    private final DelegatingSocket delegateAsDelegatingSocket;

    /**
     * The <tt>ByteBuffer</tt> instance used in
     * {@link #receiveFromChannel(java.nio.channels.SocketChannel,
     * java.net.DatagramPacket)} to read the 2-byte length field into.
     */
    private final ByteBuffer frameLengthByteBuffer = ByteBuffer.allocate(2);

    /**
     * InputStream for this socket.
     */
    private InputStream inputStream = null;

    /**
     * The last time an information about packet lost has been logged.
     */
    private long lastLostPacketLogTime = 0;

    /**
     * The last RTP sequence number received for this socket.
     */
    private long lastRtpSequenceNumber = -1;

    /**
     * The number of RTP packets lost (not received) for this socket.
     */
    private long nbLostRtpPackets = 0;

    /**
     * The number of RTP packets received for this socket.
     */
    private long nbReceivedRtpPackets = 0;

    /**
     * The number of RTP packets sent for this socket.
     */
    private long nbSentRtpPackets = 0;

    /**
     * OutputStream for this socket.
     */
    private OutputStream outputStream = null;

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     */
    public DelegatingSocket()
    {
        this((Socket) null);
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @see Socket#Socket(InetAddress, int)
     */
    public DelegatingSocket(InetAddress address, int port)
        throws IOException
    {
        this((Socket) null);
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @see Socket#Socket(InetAddress, int, InetAddress, int)
     */
    public DelegatingSocket(
            InetAddress address, int port,
            InetAddress localAddr, int localPort)
        throws IOException
    {
        this((Socket) null);
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @see Socket#Socket(Proxy)
     */
    public DelegatingSocket(Proxy proxy)
    {
        this((Socket) null);
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @param delegate delegating socket
     */
    public DelegatingSocket(Socket delegate)
    {
        this.delegate = delegate;

        delegateAsDelegatingSocket
            = (delegate instanceof DelegatingSocket)
                ? (DelegatingSocket) delegate
                : null;
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @see Socket#Socket(SocketImpl)
     */
    protected DelegatingSocket(SocketImpl impl)
        throws SocketException
    {
        this((Socket) null);
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @see Socket#Socket(String, int)
     */
    public DelegatingSocket(String host, int port)
        throws UnknownHostException, IOException
    {
        this((Socket) null);
    }

    /**
     * Initializes a new <tt>DelegatingSocket</tt>.
     *
     * @see Socket#Socket(String, int, InetAddress, int)
     */
    public DelegatingSocket(
            String host, int port,
            InetAddress localAddr, int localPort)
    {
        this((Socket) null);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void bind(SocketAddress bindpoint) throws IOException
    {
        if (delegate == null)
            super.bind(bindpoint);
        else
            delegate.bind(bindpoint);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws IOException
    {
        if (delegate == null)
            super.close();
        else
            delegate.close();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void connect(SocketAddress endpoint) throws IOException
    {
        if (delegate == null)
            super.connect(endpoint);
        else
            delegate.connect(endpoint);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException
    {
        if (delegate == null)
            super.connect(endpoint, timeout);
        else
            delegate.connect(endpoint, timeout);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SocketChannel getChannel()
    {
        return (delegate == null) ? super.getChannel() : delegate.getChannel();
    }

    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    @Override
    public InputStream getInputStream() throws IOException
    {
        return
            (delegate == null)
                ? super.getInputStream()
                : delegate.getInputStream();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getKeepAlive() throws SocketException
    {
        return
            (delegate == null) ? super.getKeepAlive() : delegate.getKeepAlive();
    }

    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    @Override
    public int getLocalPort()
    {
        return
            (delegate == null) ? super.getLocalPort() : delegate.getLocalPort();
    }

    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    @Override
    public boolean getOOBInline() throws SocketException
    {
        return
            (delegate == null) ? super.getOOBInline() : delegate.getOOBInline();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OutputStream getOutputStream() throws IOException
    {
        return
            (delegate == null)
                ? super.getOutputStream()
                : delegate.getOutputStream();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getPort()
    {
        return (delegate == null) ? super.getPort() : delegate.getPort();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getReceiveBufferSize() throws SocketException
    {
        return
            (delegate == null)
                ? super.getReceiveBufferSize()
                : delegate.getReceiveBufferSize();
    }

    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    @Override
    public boolean getReuseAddress() throws SocketException
    {
        return
            (delegate == null)
                ? super.getReuseAddress()
                : delegate.getReuseAddress();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getSendBufferSize() throws SocketException
    {
        return
            (delegate == null)
                ? super.getSendBufferSize()
                : delegate.getSendBufferSize();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getSoLinger() throws SocketException
    {
        return
            (delegate == null) ? super.getSoLinger() : delegate.getSoLinger();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getSoTimeout() throws SocketException
    {
        return
            (delegate == null) ? super.getSoTimeout() : delegate.getSoTimeout();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getTcpNoDelay() throws SocketException
    {
        return
            (delegate == null)
                ? super.getTcpNoDelay()
                : delegate.getTcpNoDelay();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getTrafficClass() throws SocketException
    {
        return
            (delegate == null)
                ? super.getTrafficClass()
                : delegate.getTrafficClass();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isBound()
    {
        return (delegate == null) ? super.isBound() : delegate.isBound();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isClosed()
    {
        return (delegate == null) ? super.isClosed() : delegate.isClosed();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isConnected()
    {
        return
            (delegate == null) ? super.isConnected() : delegate.isConnected();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isInputShutdown()
    {
        return
            (delegate == null)
                ? super.isInputShutdown()
                : delegate.isInputShutdown();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isOutputShutdown()
    {
        return
            (delegate == null)
                ? super.isOutputShutdown()
                : delegate.isOutputShutdown();
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
        if (delegateAsDelegatingSocket != null)
        {
            delegateAsDelegatingSocket.receive(p);
        }
        else
        {
            SocketChannel channel = getChannel();

            if (channel == null)
            {
                // Read from our InputStream
                if (inputStream == null)
                    inputStream = getInputStream();

                DelegatingSocket.receiveFromInputStream(
                        p,
                        inputStream,
                        getInetAddress(), getPort());
            }
            else
            {
                // For nio SocketChannel-s, the read() from the InputStream and
                // the write() to the OutputStream both lock on the same object.
                // So, read from the Channel directly in order to avoid
                // preventing any writing threads from proceeding.
                receiveFromChannel(channel, p);
            }

            // No exception, a packet is successfully received - log it. If it
            // is not a STUN/TURN packet, then it is an RTP packet.
            if (!StunDatagramPacketFilter.isStunPacket(p))
                ++nbReceivedRtpPackets;

            InetSocketAddress localAddress
                = (InetSocketAddress) super.getLocalSocketAddress();

            DelegatingDatagramSocket.logPacketToPcap(
                    p,
                    nbReceivedRtpPackets,
                    false,
                    localAddress.getAddress(), localAddress.getPort());
            // Log RTP losses if > 5%.
            updateRtpLosses(p);
        }
    }

    /**
     * Receives an RFC4571-formatted frame from <tt>channel</tt> into
     * <tt>p</tt>, and sets <tt>p</tt>'s port and address to the remote port
     * and address of this <tt>Socket</tt>.
     *
     * @param channel
     * @param p
     * @throws IOException
     */
    private synchronized void receiveFromChannel(
            SocketChannel channel,
            DatagramPacket p)
        throws IOException
    {
        while (frameLengthByteBuffer.hasRemaining())
        {
            int read = channel.read(frameLengthByteBuffer);

            if (read == -1)
            {
                throw new SocketException(
                        "Failed to receive data from socket.");
            }
        }
        frameLengthByteBuffer.flip();

        int b0 = frameLengthByteBuffer.get();
        int b1 = frameLengthByteBuffer.get();
        int frameLength = ((b0 & 0xFF) << 8) | (b1 & 0xFF);

        frameLengthByteBuffer.flip();

        byte[] data = p.getData();

        if (data == null || data.length < frameLength)
            data = new byte[frameLength];

        ByteBuffer byteBuffer = ByteBuffer.wrap(data, 0, frameLength);

        while (byteBuffer.hasRemaining())
        {
            int read = channel.read(byteBuffer);

            if (read == -1)
            {
                throw new SocketException(
                        "Failed to receive data from socket.");
            }
        }

        p.setAddress(getInetAddress());
        p.setData(data, 0, frameLength);
        p.setPort(getPort());
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
        if (delegateAsDelegatingSocket != null)
        {
            delegateAsDelegatingSocket.send(p);
        }
        else
        {
            if (outputStream == null)
                outputStream = getOutputStream();

            // Else, sends the packet to the final socket (outputStream).
            outputStream.write(p.getData(), p.getOffset(), p.getLength());

            // no exception packet is successfully sent, log it.
            ++nbSentRtpPackets;
            InetSocketAddress localAddress
                = (InetSocketAddress) super.getLocalSocketAddress();

            DelegatingDatagramSocket.logPacketToPcap(
                    p,
                    nbSentRtpPackets,
                    true,
                    localAddress.getAddress(), localAddress.getPort());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void sendUrgentData(int data) throws IOException
    {
        if (delegate == null)
            super.sendUrgentData(data);
        else
            delegate.sendUrgentData(data);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setKeepAlive(boolean on) throws SocketException
    {
        if (delegate == null)
            super.setKeepAlive(on);
        else
            delegate.setKeepAlive(on);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setOOBInline(boolean on) throws SocketException
    {
        if (delegate == null)
            super.setOOBInline(on);
        else
            delegate.setOOBInline(on);
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
     * {@inheritDoc}
     */
    @Override
    public void setPerformancePreferences(
            int connectionTime,
            int latency,
            int bandwidth)
    {
        if (delegate == null)
        {
            super.setPerformancePreferences(connectionTime, latency, bandwidth);
        }
        else
        {
            delegate.setPerformancePreferences(
                    connectionTime,
                    latency,
                    bandwidth);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setReceiveBufferSize(int size) throws SocketException
    {
        if (delegate == null)
            super.setReceiveBufferSize(size);
        else
            delegate.setReceiveBufferSize(size);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setReuseAddress(boolean on) throws SocketException
    {
        if (delegate == null)
            super.setReuseAddress(on);
        else
            delegate.setReuseAddress(on);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setSendBufferSize(int size) throws SocketException
    {
        if (delegate == null)
            super.setSendBufferSize(size);
        else
            delegate.setSendBufferSize(size);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException
    {
        if (delegate == null)
            super.setSoLinger(on, linger);
        else
            delegate.setSoLinger(on, linger);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setSoTimeout(int timeout) throws SocketException
    {
        if (delegate == null)
            super.setSoTimeout(timeout);
        else
            delegate.setSoTimeout(timeout);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setTcpNoDelay(boolean on) throws SocketException
    {
        if (delegate == null)
            super.setTcpNoDelay(on);
        else
            delegate.setTcpNoDelay(on);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setTrafficClass(int tc) throws SocketException
    {
        if (delegate == null)
            super.setTrafficClass(tc);
        else
            delegate.setTrafficClass(tc);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void shutdownInput() throws IOException
    {
        if (delegate == null)
            super.shutdownInput();
        else
            delegate.shutdownInput();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void shutdownOutput() throws IOException
    {
        if (delegate == null)
            super.shutdownOutput();
        else
            delegate.shutdownOutput();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return (delegate == null) ? super.toString() : delegate.toString();
    }

    /**
     * Updates and Logs information about RTP losses if there is more then 5% of
     * RTP packet lost (at most every 5 seconds).
     *
     * @param p The last packet received.
     */
    private void updateRtpLosses(DatagramPacket p)
    {
        // If this is not a STUN/TURN packet, then this is a RTP packet.
        if(!StunDatagramPacketFilter.isStunPacket(p))
        {
            long newSeq = DelegatingDatagramSocket.getRtpSequenceNumber(p);

            if(lastRtpSequenceNumber != -1)
            {
                nbLostRtpPackets
                    += DelegatingDatagramSocket.getNbLost(
                            lastRtpSequenceNumber,
                            newSeq);
            }
            lastRtpSequenceNumber = newSeq;

            lastLostPacketLogTime
                = DelegatingDatagramSocket.logRtpLosses(
                        nbLostRtpPackets,
                        nbReceivedRtpPackets,
                        lastLostPacketLogTime);
        }
    }
}
