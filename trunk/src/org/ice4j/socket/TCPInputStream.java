/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.socket;

import java.io.*;
import java.util.*;

/**
 * TCP input stream for TCP socket. It is used to multiplex sockets and keep
 * the <tt>InputStream</tt> interface to users.
 *
 * @author Sebastien Vincent
 */
public class TCPInputStream
    extends InputStream
{
    /**
     * List of packets.
     */
    private final List<byte[]> packets = new ArrayList<byte[]>();

    /**
     * Current packet being processed if any.
     */
    private byte[] currentPacket = null;

    /**
     * Current offset.
     */
    private int currentPacketOffset = 0;

    /**
     * Current packet length.
     */
    private int currentPacketLength = 0;

    /**
     * Synchronization object for read operation.
     */
    private final Object readSyncRoot = new Object();

    /**
     * Initializes a new <tt>TCPInputStream</tt>.
     */
    public TCPInputStream()
    {
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int available()
    {
        return 0;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close()
        throws IOException
    {
        packets.clear();
        currentPacket = null;
        currentPacketOffset = 0;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void mark(int readLimit)
    {
        /* do nothing */
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean markSupported()
    {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read(byte[] b)
    {
        return read(b, 0, b.length);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read(byte[] b, int off, int len)
    {
        synchronized(readSyncRoot)
        {
            getNextPacket();

            int length = currentPacketLength;

            if(len < length)
            {
                length = len;
            }

            System.arraycopy(currentPacket, currentPacketOffset, b, off,
                length);

            currentPacketOffset += length;
            currentPacketLength -= length;

            if(currentPacketLength <= 0)
            {
                currentPacket = null;
                currentPacketOffset = 0;
                currentPacketLength = 0;
            }
            return length;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void reset()
        throws IOException
    {
        if(!markSupported())
        {
            throw new IOException("TCPInputStream does not support reset()");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long skip(long n)
        throws IOException
    {
        synchronized(readSyncRoot)
        {
            getNextPacket();

            if(n > currentPacketLength)
            {
                n = currentPacketLength;
            }
            currentPacketOffset += n;
            currentPacketLength -= n;

            if(currentPacketLength <= 0)
            {
                currentPacket = null;
                currentPacketOffset = 0;
                currentPacketLength = 0;
            }

            return n;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read()
        throws IOException
    {
        getNextPacket();
        int ret = currentPacket[currentPacketOffset];
        currentPacketOffset++;
        currentPacketLength--;

        return ret;
    }

    /**
     * Get next packet. It blocks if no packets are available.
     *
     * @return next packet
     */
    private byte[] getNextPacket()
    {
        synchronized(packets)
        {
            if(packets.size() == 0)
            {
                try
                {
                    packets.wait();
                }
                catch (InterruptedException iex)
                {
                }
            }

            if(currentPacket == null)
            {
                currentPacket = packets.remove(0);
                currentPacketOffset = 0;
                currentPacketLength = currentPacket.length;
            }

        }
        return currentPacket;
    }

    /**
     * Add packet to this <tt>InputStream</tt>.
     *
     * @param p packet bytes
     */
    public void addPacket(byte[] p)
    {
        synchronized(packets)
        {
            this.packets.add(p);
            packets.notifyAll();
        }
    }
}
