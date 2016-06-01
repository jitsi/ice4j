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
package org.ice4j.pseudotcp;

import java.io.*;
import java.net.*;
import javax.net.*;

public class PseudoTcpSocketFactory
    extends SocketFactory
    implements SocketImplFactory
{
    /**
     * Default conversation ID
     */
    public static final long DEFAULT_CONVERSATION_ID=0;

    /**
     * Default timeout for connect operation
     */
    public static final int DEFAULT_CONNECT_TIMEOUT=5000;

    /**
     * Creates a socket and connects it to the specified 
     * port number at the specified address.
     */
    public Socket createSocket(String host, int port)
        throws IOException,
               UnknownHostException
    {
        Socket socket = createSocket();
        connectSocket(socket, new InetSocketAddress(host, port));
        return socket;
    }

    /**
     * Creates a socket and connect it to the specified remote address 
     * on the specified remote port.
     */
    public Socket createSocket(InetAddress host, int port) throws IOException
    {
        Socket socket = createSocket();
        connectSocket(socket, new InetSocketAddress(host, port));
        return socket;
    }    

    private void connectSocket(Socket socket, InetSocketAddress remoteSockAddr)
        throws IOException
    {
        socket.connect(remoteSockAddr, DEFAULT_CONNECT_TIMEOUT);
    }

    /**
     * Creates socket bound to local <tt>sockAddr</tt>
     * @param sockAddr address for the pseudo socket
     * @return socket bound to local address
     * @throws IOException if the socket could not be opened, or the socket
     * could not bind to the specified local port.
     */
    public Socket createBoundSocket(InetSocketAddress sockAddr) 
        throws IOException
    {
        return new PseudoTcpSocket(
            new PseudoTcpSocketImpl(DEFAULT_CONVERSATION_ID,
                new DatagramSocket(sockAddr)));
    }

    /**
     *  Creates a socket and connects it to the specified remote host at the specified remote port.
     */
    public Socket createSocket(String host, 
                               int port, 
                               InetAddress localHost,
                               int localPort)
        throws IOException, 
               UnknownHostException
    {
        Socket socket = createBoundSocket(
                        new InetSocketAddress(localHost, localPort));
        connectSocket(socket, new InetSocketAddress(host, port));
        return socket;
    }

    /**
     * Creates a socket and connects it to the specified remote host on the specified remote port.
     */
    public Socket createSocket(InetAddress address, int port,
        InetAddress localAddress, int localPort) throws IOException
    {
        Socket socket = createBoundSocket(
            new InetSocketAddress(localAddress, localPort));
        connectSocket(socket, new InetSocketAddress(address, port));
        return socket;
    }

    /**
     * Creates a socket that will run on given <tt>datagramSocket</tt>
     * 
     * @param datagramSocket the socket to run on
     * @return new socket running on given <tt>datagramSocket</tt>
     * @throws SocketException if there is an error in the underlying protocol,
     * such as a TCP error.
     */
    public PseudoTcpSocket createSocket(DatagramSocket datagramSocket) 
        throws SocketException
    {        
        return new PseudoTcpSocket(
            new PseudoTcpSocketImpl(DEFAULT_CONVERSATION_ID, datagramSocket));
    }

    /**
     * Creates the PseudoTcp socket and binds it to any available port
     * on the local host machine.  The socket will be bound to the
     * {@link InetAddress#isAnyLocalAddress wildcard} address,
     * an IP address chosen by the kernel.
     */
    @Override
    public PseudoTcpSocket createSocket() 
        throws SocketException
    {        
        return new PseudoTcpSocket(
            new PseudoTcpSocketImpl(DEFAULT_CONVERSATION_ID));
    }

    public SocketImpl createSocketImpl()
    {
        try
        {
            return new PseudoTcpSocketImpl(DEFAULT_CONVERSATION_ID);
        }
        catch (SocketException e)
        {
            throw new RuntimeException(e);
        }        
    }
}
