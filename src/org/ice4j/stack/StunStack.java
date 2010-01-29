/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.stack;

import java.net.DatagramSocket;
import java.io.*;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * The entry point to the Stun4J stack. The class is used to start, stop and
 * configure the stack.
 *
 * <p>Organisation: Louis Pasteur University, Strasbourg, France</p>
 *               <p>Network Research Team (http://www-r2.u-strasbg.fr)</p></p>
 * @author Emil Ivov
 * @version 0.1
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

    private StunProvider stunProvider = null;

    /**
     * Returns a reference to the singleton StunStack insance. If the stack
     * had not yet been initialised, a new instance will be created.
     *
     * @return a reference to the StunStack.
     */
    public static synchronized StunStack getInstance()
    {
        if (stackInstance == null)
            stackInstance = new StunStack();

        return stackInstance;
    }

    //----------------------- PUBLIC INTERFACE ---------------------------------


    /**
     * Sets the number of Message processors running in the same time.
     *
     * @param threadPoolSize the number of message process threads to run.
     * @throws StunException
     */
    public void setThreadPoolSize(int threadPoolSize)
        throws StunException
    {
        netAccessManager.setThreadPoolSize(threadPoolSize);
    }

    /**
     * Creates and starts the specified Network Access Point.
     *
     * @param apDescriptor A descriptor containing the address and port of the
     * STUN server that the newly created access point will communicate with.
     * @throws IOException if we fail to bind a datagram socket on the specified
     * address and port (NetAccessPointDescriptor)
     */
    public void installNetAccessPoint(NetAccessPointDescriptor apDescriptor)
        throws IOException
    {
        netAccessManager.installNetAccessPoint(apDescriptor);
    }

    /**
     * Creates and starts the specified Network Access Point based on the specified
     * socket and returns a relevant descriptor.
     *
     * @param sock The socket that the new access point should represent.
     * @throws IOException if we fail to setup the socket.
     * @return a descriptor of the newly created access point.
     */
   public NetAccessPointDescriptor installNetAccessPoint(DatagramSocket sock)
       throws IOException
   {
       return netAccessManager.installNetAccessPoint(sock);
   }


    /**
     * Stops and deletes the specified access point.
     * @param apDescriptor the access  point to remove
     */
    public void removeNetAccessPoint(NetAccessPointDescriptor apDescriptor)
    {
        netAccessManager.removeNetAccessPoint(apDescriptor);
    }



    /**
     * Returns a StunProvider instance to be used for sending and receiving
     * mesages.
     *
     * @return an instance of StunProvider
     */
    public StunProvider getProvider()
    {
        return stunProvider;
    }

    //-------------------- internal stuff --------------------------------------
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
