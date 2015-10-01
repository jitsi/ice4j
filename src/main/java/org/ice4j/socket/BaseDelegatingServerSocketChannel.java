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
import java.util.*;

/**
 * Implements a {@code ServerSocketChannel} which delegates (its method calls)
 * to another {@code ServerSocketChannel}. In other words, the former wraps the
 * latter.
 *
 * @author Lyubomir Marinov
 */
public class BaseDelegatingServerSocketChannel<T extends ServerSocketChannel>
    extends ServerSocketChannel
{
    /**
     * The {@link ServerSocketChannel} this instance delegates (its method
     * calls) to.
     */
    protected final T delegate;

    /**
     * The {@code ServerSocket} to be reported by this instance.
     */
    private ServerSocket socket;

    /**
     * The <tt>Object</tt> which synchronizes the access to {@link #socket}.
     */
    private final Object socketSyncRoot = new Object();

    /**
     * Initializes a new {@code BaseDelegatingServerSocketChannel} instance
     * which is to delegate (its method calls) to a specific
     * {@code ServerSocketChannel}.
     *
     * @param delegate the {@code ServerSocketChannel} the new instance is to
     * delegate (its method calls) to
     */
    public BaseDelegatingServerSocketChannel(T delegate)
    {
        super(delegate.provider());

        this.delegate = delegate;
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public SocketChannel accept()
        throws IOException
    {
        SocketChannel channel = delegate.accept();

        return (channel == null) ? null : implAccept(channel);
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate} and returns {@code this}.
     */
    @Override
    public ServerSocketChannel bind(SocketAddress local, int backlog)
        throws IOException
    {
        delegate.bind(local, backlog);
        return this;
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public SocketAddress getLocalAddress()
        throws IOException
    {
        return delegate.getLocalAddress();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public <U> U getOption(SocketOption<U> name)
        throws IOException
    {
        return delegate.getOption(name);
    }

    /**
     * Allows extenders to optionally configure (e.g. wrap) a
     * <tt>SocketChannel</tt> which has been accepted by {@link #delegate} and
     * before it is returned by {@link #accept()}.
     *
     * @param accepted the <tt>SocketChannel</tt> accepted by <tt>delegate</tt>
     * @return the <tt>SocketChannel</tt> to be returned by {@link #accept()}
     * (in place of <tt>accepted</tt>)
     * @throws IOException if an I/O error occurs
     */
    protected SocketChannel implAccept(SocketChannel accepted)
        throws IOException
    {
        return accepted;
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    protected void implCloseSelectableChannel()
        throws IOException
    {
        delegate.close();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    protected void implConfigureBlocking(boolean block)
        throws IOException
    {
        delegate.configureBlocking(block);
    }

    /**
     * Allows extenders to optionally configure (e.g. wrap) the
     * {@code ServerSocket} of {@link #delegate} and before it is returned by
     * {@link #socket()}.
     *
     * @param socket the {@code ServerSocket} of {@code delegate}
     * @return the {@code ServerSocket} to be returned by {@link #socket()} (in
     * place of {@code socket})
     * @throws IOException if an I/O error occurs
     */
    protected ServerSocket implSocket(ServerSocket socket)
        throws IOException
    {
        return new DelegatingServerSocket(socket, this);
    }

    /**
     * Determines whether this {@code BaseDelegatingServerSocketChannel} is
     * bound.
     *
     * @return {@code true} if this instancei bound; otherwise, {@code false}
     */
    public boolean isBound()
    {
        try
        {
            return getLocalAddress() != null;
        }
        catch (IOException ioe)
        {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate} and returns {@code this}.
     */
    @Override
    public <U> ServerSocketChannel setOption(SocketOption<U> name, U value)
        throws IOException
    {
        delegate.setOption(name, value);
        return this;
    }

    /**
     * {@inheritDoc}
     *
     * Allows wrapping the {@code socket} of {@link #delegate}.
     */
    @Override
    public ServerSocket socket()
    {
        ServerSocket socket = delegate.socket();

        synchronized (socketSyncRoot)
        {
            if (this.socket == null)
            {
                if (socket != null)
                {
                    try
                    {
                        this.socket = implSocket(socket);
                    }
                    catch (IOException ioe)
                    {
                        throw new RuntimeException(ioe);
                    }
                }
            }
            else if (socket == null)
            {
                this.socket = null;
            }
            else
            {
                // TODO For the sake of completeness, maybe check that the
                // value of this.socket still delegates to the latest value of
                // socket. However, the value of socket is very likely final so
                // do not bother with it at the time of this writing.
            }
            return this.socket;
        }
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public Set<SocketOption<?>> supportedOptions()
    {
        return delegate.supportedOptions();
    }
}
