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
import java.util.*;

import org.ice4j.socket.*;

/**
 * Represents a {@link ServerSocket} associated with a
 * {@code MuxServerSocketChannel}.
 *
 * @author Lyubomir Marinov
 */
class MuxServerSocket
    extends DelegatingServerSocket
{
    /**
     * Initializes a new {@code MuxServerSocket} instance which delegates (its
     * method calls) to a specific {@code MuxingServerSocket} and is associated
     * with a specific {@code MuxServerSocketChannel}.
     *
     * @param delegate the {@code MuxingServerSocket} the new instance is to
     * delegate (its method calls) to. Technically, it is the {@code socket} of
     * the {@code delegate} of {@code channel}.
     * @param channel the {@code MuxServerSocketChannel} associated with the new
     * instance
     * @throws IOException if an I/O error occurs
     */
    public MuxServerSocket(
            MuxingServerSocket delegate,
            MuxServerSocketChannel channel)
        throws IOException
    {
        super(
                Objects.requireNonNull(delegate, "delegate"),
                Objects.requireNonNull(channel, "channel"));
    }
}
