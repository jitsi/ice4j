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

/**
 * Implements a {@code ServerSocket} which delegates (its method calls) to
 * another {@code ServerSocket}. In other words, the former wraps the latter.
 *
 * @author Lyubomir Marinov
 */
public class DelegatingServerSocket
    extends ServerSocket
{
    /**
     * The {@link ServerSocketChannel} of this instance. If {@code null}, the
     * one of the {@link #delegate} is used.
     */
    protected final ServerSocketChannel channel;

    /**
     * The {@link ServerSocket} this instance delegates (its method calls) to.
     */
    protected final ServerSocket delegate;

    /**
     * Initializes a new {@code DelegatingServerSocket} instance which is to
     * delegate (its method calls) to a specific {@link ServerSocket}.
     *
     * @param delegate the {@code ServerSocket} the new instance is to delegate
     * (it method calls) to
     * @throws IOException never thrown
     */
    public DelegatingServerSocket(ServerSocket delegate)
        throws IOException
    {
        this(delegate, delegate.getChannel());
    }

    /**
     * Initializes a new {@code DelegatingServerSocket} instance which is to
     * delegate (its method calls) to a specific {@link ServerSocket} and is to
     * report a specific {@link ServerSocketChannel}.
     *
     * @param delegate the {@code ServerSocket} the new instance is to delegate
     * (it method calls) to
     * @param channel the {@code ServerSocketChannel} to be reported by the new
     * instance or {@code null} to report the one of {@code delegate}
     * @throws IOException never thrown
     */
    public DelegatingServerSocket(
            ServerSocket delegate,
            ServerSocketChannel channel)
        throws IOException
    {
        this.delegate = delegate;
        this.channel = channel;
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public Socket accept()
        throws IOException
    {
        return delegate.accept();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public void bind(SocketAddress endpoint)
        throws IOException
    {
        delegate.bind(endpoint);
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public void bind(SocketAddress endpoint, int backlog)
        throws IOException
    {
        delegate.bind(endpoint, backlog);
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public void close()
        throws IOException
    {
        delegate.close();
    }

    /**
     * {@inheritDoc}
     *
     * If {@link #channel} is not {@code null}, returns it. Otherwise, forwards
     * to {@link #delegate}.
     */
    @Override
    public ServerSocketChannel getChannel()
    {
        ServerSocketChannel channel = this.channel;

        return (channel == null) ? delegate.getChannel() : channel;
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public InetAddress getInetAddress()
    {
        return delegate.getInetAddress();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public int getLocalPort()
    {
        return delegate.getLocalPort();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public SocketAddress getLocalSocketAddress()
    {
        return delegate.getLocalSocketAddress();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public int getReceiveBufferSize()
        throws SocketException
    {
        return delegate.getReceiveBufferSize();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public boolean getReuseAddress()
        throws SocketException
    {
        return delegate.getReuseAddress();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public int getSoTimeout()
        throws IOException
    {
        return delegate.getSoTimeout();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public boolean isBound()
    {
        return delegate.isBound();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public boolean isClosed()
    {
        return delegate.isClosed();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public void setPerformancePreferences(int connectionTime,
                                          int latency,
                                          int bandwidth)
    {
        delegate.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public void setReceiveBufferSize(int size)
        throws SocketException
    {
        delegate.setReceiveBufferSize(size);
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public void setReuseAddress(boolean on)
        throws SocketException
    {
        delegate.setReuseAddress(on);
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public void setSoTimeout(int timeout)
        throws SocketException
    {
        delegate.setSoTimeout(timeout);
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public String toString()
    {
        return delegate.toString();
    }
}
