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
     * The indicator which determines whether this <tt>TCPOutputStream</tt> is
     * to frame RTP and RTCP packets in accord with RFC 4571 &quot;Framing
     * Real-time Transport Protocol (RTP) and RTP Control Protocol (RTCP)
     * Packets over Connection-Oriented Transport&quot;.
     */
    private final boolean frame;

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

        // GoogleRelayedCandidateSocket will encapsulate data in TURN message so
        // do not frame.
        frame
            = !(outputStream
                    instanceof GoogleRelayedCandidateSocket.TCPOutputStream);
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
    public void write(byte[] b, int off, int len)
        throws IOException
    {
        if (frame)
        {
            int newLen = len + 2;
            byte newB[] = new byte[newLen];

            newB[0] = (byte) ((len >> 8) & 0xFF);
            newB[1] = (byte) (len & 0xFF);
            System.arraycopy(b, off, newB, 2, len);
            outputStream.write(newB, 0, newLen);
        }
        else
        {
            outputStream.write(b, off, len);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void write(int b)
        throws IOException
    {
        // TODO Auto-generated method stub
    }
}
