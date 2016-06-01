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
package org.ice4j.socket.jdk8;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;

/**
 * Prepends a {@link DatagramPacket} to a {@link SocketChannel}. In other words,
 * enables looking ahead at the {@code byte}s of a {@code SocketChannel}.
 *
 * @author Lyubomir Marinov
 */
class PreReadSocketChannel
    extends DelegatingSocketChannel<SocketChannel>
{
    /**
     * The {@link DatagramPacket} which is to be prepended to the
     * {@link SocketChannel} which is the {@link #delegate} of this
     * {@link DelegatingSocketChannel}.
     */
    private final DatagramPacket preRead;

    /**
     * Initializes a new {@code PreReadSocketChannel} instance which is to
     * prepend a specific {@link DatagramPacket} to a specific
     * {@link SocketChannel}.
     *
     * @param preRead the {@code DatagramPacket} to prepend to {@code delegate}
     * @param delegate the {@code SocketChannel} to prepend {@code preRead} to
     */
    public PreReadSocketChannel(DatagramPacket preRead, SocketChannel delegate)
    {
        super(delegate);

        this.preRead = preRead;
    }

    /**
     * {@inheritDoc}
     *
     * Reads from {@link #preRead} first (until it is fully read) and then
     * continues with the {@code super} implementation.
     */
    @Override
    public int read(ByteBuffer dst)
        throws IOException
    {
        synchronized (preRead)
        {
            int len = preRead.getLength();
            int read;

            if (len > 0)
            {
                int toRead = Math.min(len, dst.remaining());

                if (toRead > 0)
                {
                    byte[] buf = preRead.getData();
                    int off = preRead.getOffset();

                    dst.put(buf, off, toRead);
                    read = toRead;
                    preRead.setData(buf, off + read, len - read);
                }
                else
                {
                    read = 0;
                }
            }
            else
            {
                read = 0;
            }

            if (read == 0)
            {
                read = super.read(dst);
            }
            else if (dst.hasRemaining())
            {
                int superRead = super.read(dst);

                if (superRead > 0)
                    read += superRead;
            }
            return read;
        }
    }
}
