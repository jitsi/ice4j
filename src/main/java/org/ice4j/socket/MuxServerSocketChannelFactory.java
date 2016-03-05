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
import java.lang.reflect.*;
import java.net.*;
import java.nio.channels.*;
import java.util.*;
import java.util.logging.*;

/**
 * If supported by the runtime, initializes {@link ServerSocketChannel}s which
 * are capable of sharing their listening endpoints with multiple others like
 * them.
 *
 * @author Lyubomir Marinov
 */
public class MuxServerSocketChannelFactory
{
    /**
     * The {@code Logger} used by the {@code MuxServerSocketChannelFactory}
     * class (and its instances) to print debug information.
     */
    private static final Logger logger
        = Logger.getLogger(MuxServerSocketChannelFactory.class.getName());

    /**
     * The reflection of the {@code openAndBind} method of the
     * {@code MuxServerSocketChannel} class.
     */
    private static final Method OPEN_AND_BIND_METHOD;

    /**
     * The maximum number of milliseconds to wait for an accepted
     * {@code SocketChannel} to provide incoming/readable data before it is
     * considered abandoned by the client.
     */
    public static final int SOCKET_CHANNEL_READ_TIMEOUT = 15 * 1000;

    /**
     * The name of the {@code boolean} property of the {@code socket} property
     * of the {@code ServerSocketChannel} returned by
     * {@link #openAndBindMuxServerSocketChannel(Map, SocketAddress, int,
     * DatagramPacketFilter)} which specifies the value of the
     * {@code SO_REUSEADDR} socket option.
     */
    public static final String SOCKET_REUSE_ADDRESS_PROPERTY_NAME
        = "socket.reuseAddress";

    static
    {
        Class<?> clazz;

        try
        {
            clazz
                = Class.forName("org.ice4j.socket.jdk8.MuxServerSocketChannel");
        }
        catch (ClassNotFoundException cnfex)
        {
            // The class cannot be located probably because ICE4J was not built
            // on JDK 8.
            clazz = null;
            logger.warning(
                    "ICE4J does not support sharing of listening endpoints"
                        + " (probably because it was not built on JDK 8).");
        }
        catch (LinkageError lerr)
        {
            // The linkage fails probably because ICE4J was built on JDK 8 but
            // is not run on JDK 8.
            clazz = null;
            logger.warning(
                    "ICE4J does not support sharing of listening endpoints"
                        + " (probably because it is not running on JDK 8).");
        }

        Method method;

        if (clazz == null)
        {
            method = null;
        }
        else
        {
            try
            {
                method
                    = clazz.getDeclaredMethod(
                            "openAndBind",
                            Map.class,
                            SocketAddress.class,
                            int.class,
                            DatagramPacketFilter.class);
            }
            catch (NoSuchMethodException nsmex)
            {
                throw new RuntimeException(nsmex);
            }
        }
        OPEN_AND_BIND_METHOD = method;
    }

    /**
     * Closes a {@code Channel} and swallows any {@link IOException}.
     *
     * @param channel the {@code Channel} to close
     */
    public static void closeNoExceptions(Channel channel)
    {
        try
        {
            channel.close();
        }
        catch (IOException ioe)
        {
            // The whole idea of the method is to close a specific Channel
            // without caring about any possible IOException.
        }
    }

    /**
     * Opens and binds a new {@code MuxServerSocketChannel} instance if
     * supported by the runtime. If there are other (existing)
     * {@code MuxServerSocketChannel} open and bound on the specified listening
     * {@code endpoint}, the new instance will share it with them. If the
     * sharing of listening endpoints is not supported by the runtime, falls
     * back to {@link #openAndBindServerSocketChannel(Map, SocketAddress, int)}.
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
    public static ServerSocketChannel openAndBindMuxServerSocketChannel(
            Map<String,Object> properties,
            SocketAddress endpoint,
            int backlog,
            DatagramPacketFilter filter)
        throws IOException
    {
        Method method = OPEN_AND_BIND_METHOD;

        if (method == null)
        {
            return
                openAndBindServerSocketChannel(properties, endpoint, backlog);
        }
        else
        {
            try
            {
                return
                    (ServerSocketChannel)
                        method.invoke(
                                null,
                                properties, endpoint, backlog, filter);
            }
            catch (IllegalAccessException iaex)
            {
                IllegalAccessError iaerr
                    = new IllegalAccessError(iaex.getMessage());

                iaerr.initCause(iaex);
                throw iaerr;
            }
            catch (InvocationTargetException itex)
            {
                Throwable cause = itex.getCause();

                if (cause == null)
                    throw new RuntimeException(itex);
                else if (cause instanceof Error)
                    throw (Error) cause;
                else if (cause instanceof IOException)
                    throw (IOException) cause;
                else if (cause instanceof RuntimeException)
                    throw (RuntimeException) cause;
                else
                    throw new RuntimeException(cause);
            }
        }
    }

    /**
     * Opens and binds a new {@code ServerSocketChannel} instance.
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
     * @return a new {@code ServerSocketChannel} instance open and bound on the
     * specified listening {@code endpoint}
     * @throws IOException if an I/O error occurs
     */
    public static ServerSocketChannel openAndBindServerSocketChannel(
            Map<String,Object> properties,
            SocketAddress endpoint,
            int backlog)
        throws IOException
    {
        ServerSocketChannel channel = ServerSocketChannel.open();
        // Apply the specified properties.
        ServerSocket socket = channel.socket();

        if (properties != null && !properties.isEmpty())
        {
            for (Map.Entry<String,Object> property
                    : properties.entrySet())
            {
                String name = property.getKey();

                if (SOCKET_REUSE_ADDRESS_PROPERTY_NAME.equals(name))
                {
                    Object value = property.getValue();
                    boolean on;

                    if (value == null)
                        on = false;
                    else if (value instanceof Boolean)
                        on = (Boolean) value;
                    else
                        on = Boolean.valueOf(value.toString());

                    socket.setReuseAddress(on);
                }
            }
        }

        socket.bind(endpoint, backlog);

        return channel;
    }
}
