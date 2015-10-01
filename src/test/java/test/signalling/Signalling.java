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
package test.signalling;

import java.net.*;

/**
 * A simple signalling utility that we use for ICE tests.
 *
 * @author Emil Ivov
 */
public class Signalling
{
    /**
     * The socket where we send and receive signalling
     */
//    private final Socket signallingSocket;

//    private final SignallingCallback signallingCallback;

    /**
     * Creates a signalling instance over the specified socket.
     *
     * @param socket the socket that this instance should use for signalling
     */
    public Signalling(Socket socket, SignallingCallback signallingCallback)
    {
//        this.signallingSocket = socket;
//        this.signallingCallback = signallingCallback;
    }

    /**
     * Creates a server signalling object. The method will block until a
     * connection is actually received on
     *
     * @param socketAddress our bind address
     * @param signallingCallback the callback that we will deliver signalling
     * to.
     *
     * @return the newly created Signalling object
     *
     * @throws Throwable if anything goes wrong (which could happen with the
     * socket stuff).
     */
    public static Signalling createServerSignalling(
            InetSocketAddress socketAddress,
            SignallingCallback signallingCallback)
        throws Throwable
    {
//        ServerSocket serverSocket = new ServerSocket(socketAddress);
//        Signalling signalling = new Signalling(socketAddress, signallingCallback);
        return null;
    }
}
