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

/**
 * 
 * @author Pawel Domas
 */
public class PseudoTcpSocket extends Socket 
{
    private final PseudoTcpSocketImpl socketImpl;

    private final Object connectLock = new Object();

    private final Object closeLock = new Object();
    
    PseudoTcpSocket(PseudoTcpSocketImpl socketImpl) 
        throws SocketException 
    {
        super(socketImpl);
        this.socketImpl = socketImpl;
    }
    
    /**
     * 
     * @return PseudoTCP conversation ID
     */
    public long getConversationID()
    {
        return socketImpl.getConversationID();
    }
    
    /**
     * Set conversation ID for the socket
     * Must be called on unconnected socket
     * 
     * @param convID the conversation ID to set
     * @throws IllegalStateException when called on connected or closed socket
     */
    public void setConversationID(long convID)
        throws IllegalStateException
    {
        socketImpl.setConversationID(convID);
    }
    
    /**
     * Sets MTU (maximum transmission unit) value
     * @param mtu  the MTU value
     */
    public void setMTU(int mtu)
    {
        socketImpl.setMTU(mtu);
    }
    
    /**
     * Gets MTU (maximum transmission unit) value
     * @return MTU value
     */
    public int getMTU()
    {
        return socketImpl.getMTU();
    }
    
    /**
     * Sets an {@link Option} on this socket.
     * @return PseudoTCP option value
     * 
     * @param option the option to set on this socket.
     * @see Option
     */
    public long getOption(Option option)
    {
        return socketImpl.getPTCPOption(option);
    }
    
    /**
     * 
     * @param option PseudoTCP option to set
     * @param optValue option's value
     * 
     * @see Option
     */
    public void setOption(Option option, long optValue)
    {
        socketImpl.setPTCPOption(option, optValue);
    }
    
    /**
     * Blocking method waits for connection.
     *
     * @param timeout for this operation in ms
     * @throws IOException If socket gets closed or timeout expires
     */
    public void accept(int timeout) 
        throws IOException
    {
        socketImpl.accept(timeout);
    }

    /**
     * Sets debug name that will be displayed in log messages for this socket
     * @param debugName the name of this socket for debug messages
     */
    public void setDebugName(String debugName)
    {
        socketImpl.setDebugName(debugName);
    }

    /**
     * Returns current <tt>PseudoTcpState</tt> of this socket
     * @return current <tt>PseudoTcpState</tt>
     * 
     * @see PseudoTcpState
     */
    public PseudoTcpState getState()
    {
        return socketImpl.getState();
    }
    
    @Override
    public boolean isConnected() 
    {
        return getState() == PseudoTcpState.TCP_ESTABLISHED;
    }
    
    /**
     * 
     * @return true if socket is connected or is trying to connect
     */
    public boolean isConnecting()
    {
        PseudoTcpState currentState = getState();
        return currentState == PseudoTcpState.TCP_ESTABLISHED
            || currentState == PseudoTcpState.TCP_SYN_RECEIVED
            || currentState == PseudoTcpState.TCP_SYN_SENT;
    }
    
    @Override
    public boolean isClosed()
    {
        return getState() == PseudoTcpState.TCP_CLOSED;
    }

    /**
     * {@inheritDoc}
     *
     * Connects without the timeout.
     */
    @Override
    public void connect(SocketAddress endpoint)
            throws IOException
    {
        this.connect(endpoint, 0);
    }

    /**
     * Checks destination port number.
     *
     * @param dstPort the destination port to check.
     */
    private void checkDestination(int dstPort)
    {
        if (dstPort < 0 || dstPort > 65535)
        {
            throw new IllegalArgumentException("Port out of range: " + dstPort);
        }
    }

    /**
     * {@inheritDoc}
     *
     * On Android, we must not use the default <tt>connect</tt> implementation,
     * because that one deals directly with physical resources, while we create
     * a socket on top of another socket.
     *
     */
    @Override
    public void connect(SocketAddress remoteAddr, int timeout)
            throws IOException
    {
        if (isClosed())
        {
            throw new SocketException("Socket is closed");
        }
        if (timeout < 0)
        {
            throw new IllegalArgumentException("timeout < 0");
        }
        if (isConnected())
        {
            throw new SocketException("Already connected");
        }
        if (remoteAddr == null)
        {
            throw new IllegalArgumentException("remoteAddr == null");
        }
        if (!(remoteAddr instanceof InetSocketAddress))
        {
            throw new IllegalArgumentException(
                    "Remote address not an InetSocketAddress: " +
                            remoteAddr.getClass());
        }
        InetSocketAddress inetAddr = (InetSocketAddress) remoteAddr;
        if (inetAddr.getAddress() == null)
        {
            throw new UnknownHostException(
                    "Host is unresolved: " + inetAddr.getHostName());
        }

        int port = inetAddr.getPort();
        checkDestination(port);

        synchronized (connectLock)
        {
            try
            {
                socketImpl.connect(remoteAddr, timeout);
            }
            catch (IOException e)
            {
                socketImpl.close();
                throw e;
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized void close()
            throws IOException
    {
        synchronized (closeLock)
        {
            if (isClosed())
                return;
            socketImpl.close();
        }
    }

    @Override
    public OutputStream getOutputStream() throws IOException
    {
        return socketImpl.getOutputStream();
    }

    /**
     * Allows to set up the remote address directly.
     * Otherwise, when using the other <tt>accept</tt> methods,
     * the first address from which a packet is received, is considered
     * the remote address.
     *
     * @param remoteAddress the one and only remote address that will be
     *                      accepted as remote packet's source
     * @param timeout connection accept timeout value in milliseconds, after
     *                which the exception will be thrown.
     * @throws IOException if socket is closed or timeout expires
     */
    public void accept(SocketAddress remoteAddress, int timeout)
            throws IOException
    {
        socketImpl.accept(remoteAddress, timeout);
    }

    /**
     * Return the <tt>FileDescriptor</tt> of the underlying socket.
     * @return the <tt>FileDescriptor</tt> of the underlying socket.
     */
    public FileDescriptor getFileDescriptor()
    {
        return socketImpl.getFileDescriptor();
    }
}
