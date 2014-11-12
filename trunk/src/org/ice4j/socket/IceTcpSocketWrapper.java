/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.socket;

import java.io.*;
import java.net.*;

/**
 * TCP implementation of the <tt>IceSocketWrapper</tt>.
 *
 * @author Sebastien Vincent
 */
public class IceTcpSocketWrapper
    extends IceSocketWrapper
{
    /**
     * InputStream for this socket.
     */
    private final InputStream inputStream;

    /**
     * OutputStream for this socket.
     */
    private final OutputStream outputStream;

    /**
     * Delegate TCP <tt>Socket</tt>.
     */
    private final Socket socket;

    /**
     * A <tt>DelegatingSocket</tt> view of {@link #socket} if the latter
     * implements the former; otherwise, <tt>null</tt>.
     */
    private final DelegatingSocket socketAsDelegatingSocket;

    /**
     * Constructor.
     *
     * @param delegate delegate <tt>Socket</tt>
     *
     * @throws IOException if something goes wrong during initialization
     */
    public IceTcpSocketWrapper(Socket delegate)
        throws IOException
    {
        socket = delegate;

        if(delegate instanceof DelegatingSocket)
        {
            inputStream = null;
            outputStream = null;
            socketAsDelegatingSocket = (DelegatingSocket) delegate;
        }
        else
        {
            inputStream = delegate.getInputStream();
            outputStream = delegate.getOutputStream();
            socketAsDelegatingSocket = null;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close()
    {
        try
        {
            socket.close();
        }
        catch(IOException e)
        {
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public InetAddress getLocalAddress()
    {
        return socket.getLocalAddress();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getLocalPort()
    {
        return socket.getLocalPort();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SocketAddress getLocalSocketAddress()
    {
        return socket.getLocalSocketAddress();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Socket getTCPSocket()
    {
        return socket;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DatagramSocket getUDPSocket()
    {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void receive(DatagramPacket p) throws IOException
    {
        if (socketAsDelegatingSocket != null)
        {
            socketAsDelegatingSocket.receive(p);
        }
        else
        {
            DelegatingSocket.receiveFromInputStream(
                    p,
                    inputStream,
                    getLocalAddress(), getLocalPort());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void send(DatagramPacket p)
        throws IOException
    {
        if (socketAsDelegatingSocket != null)
        {
            socketAsDelegatingSocket.send(p);
        }
        else
        {
            int len = p.getLength();
            int off = p.getOffset();
            byte data[] = new byte[len + 2];

            data[0] = (byte)((len >> 8) & 0xff);
            data[1] = (byte)(len & 0xff);
            System.arraycopy(p.getData(), off, data, 2, len);
            outputStream.write(data, 0, len + 2);
        }
    }
}
