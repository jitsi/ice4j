/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.socket;

import java.io.*;

/**
 * TCP output stream for TCP socket. It is used to multiplex sockets and keep
 * the <tt>OutputStream</tt> interface to users.
 *
 * @author Sebastien Vincent
 */
public class TCPOutputStream
    extends OutputStream
{
    /**
     * Original <tt>OutputStream</tt> that this class wraps.
     */
    private final OutputStream outputStream;

    /**
     * Initializes a new <tt>TCPOutputStream</tt>.
     *
     * @param outputStream original <tt>OutputStream</tt>
     */
    public TCPOutputStream(OutputStream outputStream)
    {
        this.outputStream = outputStream;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close()
        throws IOException
    {
        outputStream.close();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void flush()
        throws IOException
    {
        outputStream.flush();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void write(byte[] b)
        throws IOException
    {
        write(b, 0, b.length);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void write(byte[] b, int off, int len)
        throws IOException
    {
        // GoogleRelayedCandidateSocket will encapsulate data in TURN message
        // so do not add framing here
        if(outputStream instanceof GoogleRelayedCandidateSocket.TCPOutputStream)
        {
            outputStream.write(b, off, len);
            return;
        }

        byte data[] = new byte[len + 2];
        data[0] = (byte)((len >> 8) & 0xff);
        data[1] = (byte)(len & 0xff);
        System.arraycopy(b, off, data, 2, len);
        outputStream.write(data, 0, len + 2);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void write(int arg0) throws IOException
    {
        // TODO Auto-generated method stub
    }
}
