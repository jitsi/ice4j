/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.stack;

import java.io.*;
import java.net.*;

import org.ice4j.*;
/**
 * The entry point to the Stun4J stack. The class is used to start, stop and
 * configure the stack.
 *
 * @author Emil Ivov
 */
public class StunStack
{
    /**
     * We shouldn't need more than one stack in the same application.
     */
    private static StunStack stackInstance = null;

    /**
     * Our network gateway.
     */
    private NetAccessManager netAccessManager = null;

    /**
     * The number of threads to split our flow in.
     */
    public static final int DEFAULT_THREAD_POOL_SIZE = 3;

    /**
     * This stack's provider.
     */
    private StunProvider stunProvider = null;

    /**
     * Returns a reference to the singleton StunStack instance. If the stack
     * had not yet been initialized, a new instance will be created.
     *
     * @return a reference to the StunStack.
     */
    public static synchronized StunStack getInstance()
    {
        if (stackInstance == null)
            stackInstance = new StunStack();

        return stackInstance;
    }

    /**
     * Sets the number of Message processors running in the same time.
     *
     * @param threadPoolSize the number of message process threads to run.
     * @throws IllegalArgumentException if threadPoolSize is not a valid size.
     */
    public void setThreadPoolSize(int threadPoolSize)
        throws IllegalArgumentException
    {
        netAccessManager.setThreadPoolSize(threadPoolSize);
    }

    /**
     * Creates and starts the specified Network Access Point based on the
     * specified socket and returns a relevant descriptor.
     *
     * @param sock The socket that the new access point should represent.
     * @throws IOException if we fail to setup the socket.
     */
   public void addSocket(DatagramSocket sock)
       throws IOException
   {
       netAccessManager.addSocket(sock);
   }


    /**
     * Stops and deletes the connector listening on the specified local address.
     *
     * @param localAddr the access  point to remove
     */
    public void removeSocket(TransportAddress localAddr)
    {
        netAccessManager.removeSocket(localAddr);


    }



    /**
     * Returns a StunProvider instance to be used for sending and receiving
     * messages.
     *
     * @return an instance of StunProvider
     */
    public StunProvider getProvider()
    {
        return stunProvider;
    }

    /**
     * Private constructor as we want a singleton pattern.
     */
    private StunStack()
    {
        stunProvider = new StunProvider(this);

        netAccessManager = new NetAccessManager(stunProvider);
    }

    /**
     * Returns the currently active instance of NetAccessManager.
     * @return the currently active instance of NetAccessManager.
     */
    NetAccessManager getNetAccessManager()
    {
        return netAccessManager;
    }
}
