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
import java.nio.*;
import java.nio.channels.*;
import java.util.*;

/**
 * Implements a {@code SocketChannel} which delegates (its method calls) to
 * another {@code SocketChannel}. In other words, the former wraps the latter.
 *
 * @author Lyubomir Marinov
 */
public class BaseDelegatingSocketChannel<T extends SocketChannel>
    extends SocketChannel
{
    /**
     * The {@link SocketChannel} this instance delegates (its method calls) to.
     */
    protected final T delegate;

    /**
     * The {@code Socket} to be reported by this instance.
     */
    private Socket socket;

    /**
     * The <tt>Object</tt> which synchronizes the access to {@link #socket}.
     */
    private final Object socketSyncRoot = new Object();

    /**
     * Initializes a new {@code BaseDelegatingSocketChannel} instance which is
     * to delegate (its method calls) to a specific {@code SocketChannel}.
     *
     * @param delegate the {@code SocketChannel} the new instance is to delegate
     * (its method calls) to
     */
    public BaseDelegatingSocketChannel(T delegate)
    {
        super(delegate.provider());

        this.delegate = delegate;
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate} and returns {@code this}.
     */
    @Override
    public SocketChannel bind(SocketAddress local)
        throws IOException
    {
        delegate.bind(local);
        return this;
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public boolean connect(SocketAddress remote)
        throws IOException
    {
        return delegate.connect(remote);
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public boolean finishConnect()
        throws IOException
    {
        return delegate.finishConnect();
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
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public SocketAddress getRemoteAddress()
        throws IOException
    {
        return delegate.getRemoteAddress();
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
     * Allows extenders to optionally configure (e.g. wrap) the {@code Socket}
     * of {@link #delegate} and before it is returned by {@link #socket()}.
     *
     * @param socket the {@code Socket} of {@code delegate}
     * @return the {@code Socket} to be returned by {@link #socket()} (in place
     * of {@code socket})
     * @throws IOException if an I/O error occurs
     */
    protected Socket implSocket(Socket socket)
        throws IOException
    {
        return new DelegatingSocket(socket, this);
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public boolean isConnected()
    {
        return delegate.isConnected();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public boolean isConnectionPending()
    {
        return delegate.isConnectionPending();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public int read(ByteBuffer dst)
        throws IOException
    {
        return delegate.read(dst);
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public long read(ByteBuffer[] dsts, int offset, int length)
        throws IOException
    {
        return delegate.read(dsts, offset, length);
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate} and returns {@code this}.
     */
    @Override
    public <U> SocketChannel setOption(SocketOption<U> name, U value)
        throws IOException
    {
        delegate.setOption(name, value);
        return this;
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate} and returns {@code this}.
     */
    @Override
    public SocketChannel shutdownInput()
        throws IOException
    {
        delegate.shutdownInput();
        return this;
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate} and returns {@code this}.
     */
    @Override
    public SocketChannel shutdownOutput()
        throws IOException
    {
        delegate.shutdownOutput();
        return this;
    }

    /**
     * {@inheritDoc}
     *
     * Allows wrapping the {@code socket} of {@link #delegate}.
     */
    @Override
    public Socket socket()
    {
        Socket socket = delegate.socket();

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

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public int write(ByteBuffer src)
        throws IOException
    {
        return delegate.write(src);
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public long write(ByteBuffer[] srcs, int offset, int length)
        throws IOException
    {
        return delegate.write(srcs, offset, length);
    }
}
