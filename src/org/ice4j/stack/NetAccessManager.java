/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.stack;


import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * Manages NetAccessPoints and MessageProcessor pooling. This class serves as a
 * layer that masks network primitives and provides equivalent STUN abstractions.
 * Instances that operate with the NetAccessManager are only supposed to
 * understand STUN talk and shouldn't be aware of datagrams sockets, and etc.
 *
 * @author Emil Ivov
 */

class NetAccessManager
    implements ErrorHandler
{
    /**
     * Our class logger
     */
    private static final Logger logger =
        Logger.getLogger(NetAccessManager.class.getName());
    /**
     * All access points currently in use. The table maps
     * <tt>TransportAddress</tt>es to <tt>Connector</tt>s
     */
    private Hashtable<TransportAddress, NetAccessPoint> netAccessPoints
            = new Hashtable<TransportAddress, NetAccessPoint>();

    /**
     * A synchronized FIFO where incoming messages are stocked for processing.
     */
    private MessageQueue messageQueue = new MessageQueue();

    /**
     * A thread pool of message processors.
     */
    private Vector<MessageProcessor> messageProcessors
                                            = new Vector<MessageProcessor>();

    /**
     * The instance that should be notified whan an incoming message has been
     * processed and ready for delivery
     */
    private MessageEventHandler messageEventHandler = null;

    /**
     * The size of the thread pool to start with.
     */
    private int initialThreadPoolSize = StunStack.DEFAULT_THREAD_POOL_SIZE;

    /**
     * Constructs a NetAccessManager.
     *
     * @param evtHandler the handler that incoming message requests should be
     * passed to.
     */
    NetAccessManager(MessageEventHandler evtHandler)
    {
        setEventHandler(evtHandler);
        initThreadPool();
    }

    /**
     * Sets the instance to notify for incoming message events.
     * @param evtHandler the entity that will handle incoming messages.
     */
    void setEventHandler(MessageEventHandler evtHandler)
    {
        messageEventHandler = evtHandler;
    }

    /**
     * A civilized way of not caring!
     * @param message a description of the error
     * @param error   the error that has occurred
     */
    public void handleError(String message, Throwable error)
    {
        /**
         * apart from logging, i am not sure what else we could do here.
         */
        logger.log( Level.WARNING, "The following error occurred", error);
    }

    /**
     * Clears the faulty thread and reports the problem.
     *
     * @param callingThread the thread where the error occurred.
     * @param message       A description of the error
     * @param error         The error itself
     */
    public void handleFatalError(Runnable callingThread,
                                 String message,
                                 Throwable error)
    {
        if (callingThread instanceof NetAccessPoint)
        {
            NetAccessPoint ap = (NetAccessPoint)callingThread;

            //make sure nothing's left and notify user
            removeNetAccessPoint(ap.getListenAddress());
            logger.log(Level.WARNING, "Removing connector:"+ ap);
        }
        else if( callingThread instanceof MessageProcessor )
        {
            MessageProcessor mp = (MessageProcessor)callingThread;
            logger.log( Level.WARNING, "A message processor has unexpectedly "
                    +"stopped. AP:" + mp.toString(), error);

            //make sure the guy's dead.
            mp.stop();
            messageProcessors.remove(mp);

            mp = new MessageProcessor(messageQueue, messageEventHandler, this);
            mp.start();
            logger.fine("A message processor has been relaunched because "
                        +"of an error.");
        }
    }

    /**
     * Creates and starts a new access point based on the specified socket.
     * If the specified access point has already been installed the method
     * has no effect.
     *
     * @param  socket   the socket that the access point should use.
     *
     * @throws IOException if we fail to setup the socket.
     */
    protected void installUdpConnector(DatagramSocket socket)
        throws IOException
    {

        //no null check - let it through a null pointer exception
        TransportAddress localAddr = new TransportAddress(
               socket.getLocalAddress(), socket.getLocalPort(), Transport.UDP);

        if(netAccessPoints.containsKey(localAddr))
            return;

        NetAccessPoint ap = new NetAccessPoint(socket, messageQueue, this);

        netAccessPoints.put(localAddr, ap);

        ap.start();
    }


    /**
     * Stops and deletes the specified access point.
     *
     * @param address the address of the connector to remove.
     */
    protected void removeNetAccessPoint(TransportAddress address)
    {
        NetAccessPoint ap = netAccessPoints.remove(address);

        if(ap != null)
            ap.stop();
    }

    //---------------thread pool implementation --------------------------------
    /**
     * Adjusts the number of concurrently running MessageProcessors.
     * If the number is smaller or bigger than the number of threads
     * currentlyrunning, then message processors are created/deleted so that
     * their count matches the new value.
     *
     * @param threadPoolSize the number of MessageProcessors that should be
     * running concurrently
     * @throws IllegalArgumentException if threadPoolSize is not a valid size.
     */
    void setThreadPoolSize(int threadPoolSize)
        throws IllegalArgumentException
    {
        if(threadPoolSize < 1)
            throw new IllegalArgumentException(
                threadPoolSize
                + " is not a legal thread pool size value.");

        //if we are not running just record the size
        //so that we could init later.
        if(messageProcessors.size() < threadPoolSize)
        {
            //create additional processors
            fillUpThreadPool(threadPoolSize);
        }
        else
        {
            //delete extra processors
            shrinkThreadPool(threadPoolSize);
        }
    }

    /**
     * Fills the thread pool with the initially specified number of message
     * processors.
     */
    private void initThreadPool()
    {
            //create additional processors
            fillUpThreadPool(initialThreadPoolSize);
    }


    /**
     * Starts all message processors
     *
     * @param newSize the new thread pool size
     */
    private void fillUpThreadPool(int newSize)
    {
        //make sure we don't resize more than once
        messageProcessors.ensureCapacity(newSize);

        for (int i = messageProcessors.size(); i < newSize; i++)
        {
            MessageProcessor mp = new MessageProcessor(messageQueue,
                                                       messageEventHandler,
                                                       this);
            messageProcessors.add(mp);

            mp.start();
        }

    }

    /**
     * Starts all message processors
     *
     * @param newSize the new thread poolsize
     */
    private void shrinkThreadPool(int newSize)
    {
        while(messageProcessors.size() > newSize)
        {
            MessageProcessor mp = messageProcessors.remove(0);
            mp.stop();
        }
    }

    //--------------- SENDING MESSAGES -----------------------------------------
    /**
     * Sends the specified stun message through the specified access point.
     *
     * @param stunMessage the message to send
     * @param srcAddr the access point to use to send the message
     * @param remoteAddr the destination of the message.
     *
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws StunException if message encoding fails,
     */
    void sendMessage(Message          stunMessage,
                     TransportAddress srcAddr,
                     TransportAddress remoteAddr)
        throws IOException, IllegalArgumentException, StunException
    {
        byte[] bytes = stunMessage.encode();
        NetAccessPoint ap = netAccessPoints.get(srcAddr);

        if(ap == null)
            throw new IllegalArgumentException(
                          "The specified access point had not been installed.");

        ap.sendMessage(bytes, remoteAddr);
    }

}
