/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the Jitsi community (https://jitsi.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
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
     * @param convID
     * @throws IllegalStateException when called on connected or closed socket
     */
    public void setConversationID(long convID)
        throws IllegalStateException
    {
        socketImpl.setConversationID(convID);
    }
	
    /**
     * Sets MTU value
     * @param mtu
     */
	public void setMTU(int mtu)
	{
	    socketImpl.setMTU(mtu);
	}
	
	/**
	 * 
	 * @return MTU value
	 */
	public int getMTU()
	{
	    return socketImpl.getMTU();
	}
	
	/**
	 * 
	 * @return PseudoTCP option value
	 * 
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
     * @param debugName 
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

}
