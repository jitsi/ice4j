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
import java.nio.channels.*;
import java.util.*;
import org.ice4j.socket.*;

/**
 * Implements a {@link ServerSocketChannel} which is capable of sharing its
 * listening endpoint with multiple others like it.
 *
 * @author Lyubomir Marinov
 */
public class MuxServerSocketChannel
    extends DelegatingServerSocketChannel<MuxingServerSocketChannel>
{
    /**
     * Asserts that <tt>t</tt> is not <tt>null</tt> by throwing a
     * <tt>NullPointerException</tt> if it is.
     *
     * @param t the <tt>Object</tt> to assert that it is not <tt>null</tt>
     * @param message the (detail) message of the <tt>NullPointerException</tt>
     * to be thrown if <tt>t</tt> is <tt>null</tt>
     * @param <T> the type of <tt>t</tt>
     * @return <tt>t</tt>
     * @throws NullPointerException if <tt>t</tt> is <tt>null</tt>. The (detail)
     * message of the <tt>NullPointerException</tt> is <tt>message</tt>
     */
    public static <T> T assertIsNotNull(T t, String message)
        throws NullPointerException
    {
        if (t == null)
            throw new NullPointerException(message);
        else
            return t;
    }

    /**
     * Opens and binds a new {@code MuxServerSocketChannel} instance. If there
     * are other (existing) {@code MuxServerSocketChannel} open and bound on the
     * specified listening {@code endpoint}, the new instance will share it with
     * them.
     *
     * @param properties a {@code Map} of the values to be assigned to
     * properties of the underlying {@link ServerSocketChannel} which is to
     * actually listen on the specified {@code endpoint}. If the new instance is
     * not the first to open and bind the specified {@code endpoint}, the
     * {@code properties} and their respective values may not be used.
     * @param endpoint the IP and port the new instance is to bind to
     * @param backlog the requested maximum number of pending incoming
     * connections to be queued. If the new instance is not the first to open
     * and bind the specified {@code endpoint}, the value may not be used.
     * @param filter the {@code DatagramPacketFilter} to demultiplex (i.e.
     * recognize) the content meant for the new instance
     * @return a new {@code MuxServerSocketChannel} instance open and bound on
     * the specified listening {@code endpoint}
     * @throws IOException if an I/O error occurs
     */
    public static MuxServerSocketChannel openAndBind(
            Map<String,Object> properties,
            SocketAddress endpoint,
            int backlog,
            DatagramPacketFilter filter)
        throws IOException
    {
        return
            MuxingServerSocketChannel.openAndBind(
                    properties,
                    endpoint,
                    backlog,
                    filter);
    }

    /**
     * The (ordered) list (i.e. queue) of <tt>SocketChannel</tt>s to be returned
     * by {@link #accept()}.
     */
    private final Queue<SocketChannel> acceptQ
        = new LinkedList<SocketChannel>();

    /**
     * The {@code DatagramPacketFilter} which demultiplexes
     * {@code SocketChannel}s accepted by the associated
     * {@code MuxingServerSocketChannel}.
     */
    protected final DatagramPacketFilter filter;

    /**
     * The <tt>Object</tt> which synchronizes the access to the state of this
     * <tt>MuxServerSocketChannel</tt> such as {@link #acceptQ}.
     */
    private final Object syncRoot = new Object();

    /**
     * Initializes a new {@code MuxServerSocketChannel} instance which is to
     * demultiplex {@link SocketChannel}s accepted by a specific
     * {@link MuxingServerSocketChannel} using a specific
     * {@link DatagramPacketFilter}. The new instance shares the listening
     * endpoint of {@code delegate} with any other associated
     * {@code MuxServerSocketChannel}s.
     *
     * @param delegate the {@code MuxingServerSocketChannel} which is actually
     * open and bound to a listening endpoint and accepts {@code SocketChannel}s
     * to be filtered by associated
     * {@code MuxServerSocketChannel}s
     * @param filter the {@code DatagramPacketFilter} which is to demultiplex
     * {@code SocketChannel}s accepted by {@code delegate}
     */
    protected MuxServerSocketChannel(
            MuxingServerSocketChannel delegate,
            DatagramPacketFilter filter)
    {
        super(assertIsNotNull(delegate, "delegate"));

        this.filter = assertIsNotNull(filter, "filter");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SocketChannel accept()
        throws IOException
    {
        SocketChannel accepted;

        // Pop a SocketChannel from acceptQ.
        do
        {
            if (!isOpen())
            {
                throw new ClosedChannelException();
            }
            else if (!isBound())
            {
                throw new NotYetBoundException();
            }
            else
            {
                synchronized (syncRoot)
                {
                    accepted = acceptQ.poll();
                    if (accepted == null)
                    {
                        if (isBlocking())
                        {
                            try
                            {
                                syncRoot.wait();
                            }
                            catch (InterruptedException ie)
                            {
                            }
                        }
                        else
                        {
                            break;
                        }
                    }
                    else if (accepted.isOpen())
                    {
                        // Allow the MuxServerSocketChannel class and/or its
                        // super(s) to have a final say on the accepted
                        // SocketChannel such as wrapping it into a suitable
                        // specialization of DelegatingSocketChannel.
                        accepted = implAccept(accepted);
                        if (accepted != null)
                            break;
                    }
                }
            }
        }
        while (true);
        return accepted;
    }

    /**
     * Determines whether the {@link #filter} of this instance accepts a
     * specific {@code SocketChannel} from which a specific
     * {@code DatagramPacket} has been read and, if it does, queues the
     * {@code channel} to be accepted through this instance.
     *
     * @param p the {@code DatagramPacket} which has been read from
     * {@code channel} and which is to be analyzed by the {@code filter} of this
     * instance
     * @param channel the {@code SocketChannel} from which {@code p} has been
     * read and which is to be queued for acceptance through this instance if
     * the {@code filter} accepts {@code p} 
     * @return {@code true} if the {@code filter} of this instance accepts
     * {@code p} and {@code channel} was queued for acceptance through this
     * instance; otherwise, {@code false}
     */
    protected boolean filterAccept(DatagramPacket p, SocketChannel channel)
    {
        boolean b;

        if (filter.accept(p))
            b = qAccept(new PreReadSocketChannel(p, channel));
        else
            b = false;
        return b;
    }

    /**
     * {@inheritDoc}
     *
     * Adjusts the blocking mode of {@link #delegate}.
     */
    @Override
    protected void implConfigureBlocking(boolean block)
        throws IOException
    {
        // If at least one MuxServerSocketChannel is configured as non-blocking,
        // then MuxingServerSocketChannel has to be configured as non-blocking
        // as well.
        if (!block)
            delegate.configureBlocking(block);
    }

    /**
     * {@inheritDoc}
     *
     * Associates a {@link MuxServerSocket} with this
     * {@code MuxServerSocketChannel}.
     */
    @Override
    protected MuxServerSocket implSocket(ServerSocket socket)
        throws IOException
    {
        return new MuxServerSocket((MuxingServerSocket) socket, this);
    }

    /**
     * Queues a {@link SocketChannel} for acceptance through this instance.
     *
     * @param channel the {@code SocketChannel} to queue for acceptance through
     * this instance
     * @return {@code true} if {@code channel} was queued for acceptance through
     * this instance; otherwise, {@code false}
     */
    private boolean qAccept(SocketChannel channel)
    {
        boolean b;

        synchronized (syncRoot)
        {
            if (acceptQ.offer(channel))
            {
                syncRoot.notifyAll();
                b = true;
            }
            else
            {
                b = false;
            }
        }
        return b;
    }
}
