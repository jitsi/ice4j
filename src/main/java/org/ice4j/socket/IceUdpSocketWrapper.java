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

/**
 * UDP implementation of the <tt>IceSocketWrapper</tt>.
 *
 * @author Sebastien Vincent
 */
public class IceUdpSocketWrapper
    extends IceSocketWrapper
{
    /**
     * Delegate UDP <tt>DatagramSocket</tt>.
     */
    private final DatagramSocket socket;

    /**
     * Constructor.
     *
     * @param delegate delegate <tt>DatagramSocket</tt>
     */
    public IceUdpSocketWrapper(DatagramSocket delegate)
    {
        this.socket = delegate;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void send(DatagramPacket p)
        throws IOException
    {
        socket.send(p);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void receive(DatagramPacket p) throws IOException
    {
        socket.receive(p);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close()
    {
        socket.close();
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
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DatagramSocket getUDPSocket()
    {
        return socket;
    }
}
