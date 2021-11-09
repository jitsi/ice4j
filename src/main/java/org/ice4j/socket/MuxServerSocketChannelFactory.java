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
 * If supported by the runtime, initializes {@link ServerSocketChannel}s which
 * are capable of sharing their listening endpoints with multiple others like
 * them.
 *
 * @author Lyubomir Marinov
 */
public class MuxServerSocketChannelFactory
{
    /**
     * The maximum number of milliseconds to wait for an accepted
     * {@code SocketChannel} to provide incoming/readable data before it is
     * considered abandoned by the client.
     */
    public static final int SOCKET_CHANNEL_READ_TIMEOUT = 15 * 1000;

    /**
     * The name of the {@code boolean} property of the {@code socket} property
     * of the {@code ServerSocketChannel} returned by
     * {@link #openAndBindServerSocketChannel(Map, SocketAddress, int)} which
     * specifies the value of the {@code SO_REUSEADDR} socket option.
     */
    public static final String SOCKET_REUSE_ADDRESS_PROPERTY_NAME
        = "socket.reuseAddress";

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
            Map<String, Object> properties,
            SocketAddress endpoint,
            int backlog)
        throws IOException
    {
        ServerSocketChannel channel = ServerSocketChannel.open();
        // Apply the specified properties.
        ServerSocket socket = channel.socket();

        if (properties != null && !properties.isEmpty())
        {
            for (Map.Entry<String, Object> property
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
                        on = Boolean.parseBoolean(value.toString());

                    socket.setReuseAddress(on);
                }
            }
        }

        socket.bind(endpoint, backlog);

        return channel;
    }
}
