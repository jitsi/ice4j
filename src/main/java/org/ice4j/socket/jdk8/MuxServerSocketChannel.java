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
    private final Queue<Timestamped<SocketChannel>> acceptQ
        = new LinkedList<>();

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
        super(Objects.requireNonNull(delegate, "delegate"));

        this.filter = Objects.requireNonNull(filter, "filter");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SocketChannel accept()
        throws IOException
    {
        SocketChannel accepted = null;
        boolean interrupted = false;

        // Pop a SocketChannel from acceptQ.
        try
        {
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
                        Timestamped<SocketChannel> timestamped = acceptQ.poll();

                        if (timestamped == null)
                        {
                            if (isBlocking())
                            {
                                try
                                {
                                    syncRoot.wait();
                                }
                                catch (InterruptedException ie)
                                {
                                    interrupted = true;
                                }
                            }
                            else
                            {
                                break;
                            }
                        }
                        else if ((accepted = timestamped.o).isOpen())
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
        }
        finally
        {
            // Restore the interrupted state of the current thread if we've
            // cleared it in the loop above.
            if (interrupted)
                Thread.currentThread().interrupt();
        }
        return accepted;
    }

    /**
     * Weeds out abandoned {@code SocketChannels} from {@link #acceptQ} i.e.
     * which were classified/filtered into this {@code MuxServerSocketChannel}
     * but were not accepted (out of it) for a long time.
     *
     * @param now the (system) time in milliseconds at which the method is
     * invoked
     */
    void closeAbandonedSocketChannels(long now)
    {
        synchronized (syncRoot)
        {
            Collection<Timestamped<SocketChannel>> chs = acceptQ;

            if (!chs.isEmpty())
            {
                for (Iterator<Timestamped<SocketChannel>> i = chs.iterator();
                        i.hasNext();)
                {
                    Timestamped<SocketChannel> ch = i.next();

                    if (now - ch.timestamp
                            >= MuxingServerSocketChannel
                                .SOCKET_CHANNEL_READ_TIMEOUT)
                    {
                        i.remove();
                        MuxingServerSocketChannel.closeNoExceptions(ch.o);
                    }
                }
            }
        }
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
        return
            filter.accept(p) && qAccept(new PreReadSocketChannel(p, channel));
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
    boolean qAccept(SocketChannel channel)
    {
        boolean b;

        synchronized (syncRoot)
        {
            if (acceptQ.offer(
                    new Timestamped<>(channel, System.currentTimeMillis())))
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
