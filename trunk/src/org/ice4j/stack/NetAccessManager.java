/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 * 
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.stack;

import java.io.*;
import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.message.*;
import org.ice4j.socket.*;

/**
 * Manages <tt>Connector</tt>s and <tt>MessageProcessor</tt> pooling. This class
 * serves as a layer that masks network primitives and provides equivalent STUN
 * abstractions. Instances that operate with the NetAccessManager are only
 * supposed to understand STUN talk and shouldn't be aware of datagrams sockets,
 * and etc.
 * 
 * @author Emil Ivov
 * @author Aakash Garg
 */
class NetAccessManager
    implements ErrorHandler
{
    /**
     * Our class logger
     */
    private static final Logger logger
        = Logger.getLogger(NetAccessManager.class.getName());

    /**
     * All access points currently in use with UDP. The table maps
     * <tt>TransportAddress</tt>es to <tt>Connector</tt>s.
     *
     * Due to the final hashCode() method of InetSocketAddress, TransportAddress
     * cannot override and it causes problem to store both UDP and TCP address
     * (i.e. 192.168.0.3:5000/tcp has the same hashcode as 192.168.0.3:5000/udp
     * because InetSocketAddress does not take into account transport).
     */
    private Map<TransportAddress, Connector> netUDPAccessPoints
            = new Hashtable<TransportAddress, Connector>();

    /**
     * All access points currently in use with TCP. The table maps
     * <tt>TransportAddress</tt>es to <tt>Connector</tt>s.
     *
     * Due to the final hashCode() method of InetSocketAddress, TransportAddress
     * cannot override and it causes problem to store both UDP and TCP address
     * (i.e. 192.168.0.3:5000/tcp has the same hashcode as 192.168.0.3:5000/udp
     * because InetSocketAddress does not take into account transport).
     */
    private Map<TransportAddress, Connector> netTCPAccessPoints
            = new Hashtable<TransportAddress, Connector>();

    /**
     * A synchronized FIFO where incoming messages are stocked for processing.
     */
    private final MessageQueue messageQueue = new MessageQueue();

    /**
     * A thread pool of message processors.
     */
    private Vector<MessageProcessor> messageProcessors
                                            = new Vector<MessageProcessor>();

    /**
     * The instance that should be notified when an incoming message has been
     * processed and ready for delivery
     */
    private final MessageEventHandler messageEventHandler;

    /**
     * The instance that should be notified when an incoming UDP message has
     * been processed and ready for delivery
     */
    private final PeerUdpMessageEventHandler peerUdpMessageEventHandler;

    /**
     * The instance that should be notified when an incoming ChannelData message
     * has been processed and ready for delivery
     */
    private final ChannelDataEventHandler channelDataEventHandler;

    /**
     * The size of the thread pool to start with.
     */
    private int initialThreadPoolSize = StunStack.DEFAULT_THREAD_POOL_SIZE;

    /**
     * The <tt>StunStack</tt> which has created this instance, is its owner and
     * is the handler that incoming message requests should be passed to.
     */
    private final StunStack stunStack;

    /**
     * Constructs a NetAccessManager.
     *
     * @param stunStack the <tt>StunStack</tt> which is creating the new
     * instance, is going to be its owner and is the handler that incoming
     * message requests should be passed to
     */
    NetAccessManager(StunStack stunStack)
    {
        this(stunStack, null, null);
    }

    /**
     * Constructs a NetAccessManager with given peerUdpMessageEventHandler and
     * channelDataEventHandler.
     * 
     * @param stunStack the <tt>StunStack</tt> which is creating the new
     *            instance, is going to be its owner and is the handler that
     *            incoming message requests should be passed to
     * @param peerUdpMessageEventHandler the <tt>PeerUdpMessageEventHandler</tt>
     *            that will handle incoming UDP messages which are not STUN
     *            messages and ChannelData messages.
     * @param channelDataEventHandler the <tt>ChannelDataEventHandler</tt> that
     *            will handle incoming UDP messages which are ChannelData
     *            messages.
     */
    NetAccessManager(StunStack stunStack,
        PeerUdpMessageEventHandler peerUdpMessageEventHandler,
        ChannelDataEventHandler channelDataEventHandler)
    {
        this.stunStack = stunStack;
        this.messageEventHandler = stunStack;
        this.peerUdpMessageEventHandler = peerUdpMessageEventHandler;
        this.channelDataEventHandler = channelDataEventHandler;
        initThreadPool();
    }

    /**
     * Gets the <tt>MessageEventHandler</tt> of this <tt>NetAccessManager</tt>
     * which is to be notified when incoming messages have been processed and
     * are ready for delivery.
     *
     * @return the <tt>MessageEventHandler</tt> of this
     * <tt>NetAccessManager</tt> which is to be notified when incoming messages
     * have been processed and are ready for delivery
     */
    MessageEventHandler getMessageEventHandler()
    {
        return messageEventHandler;
    }

    /**
     * Gets the <tt>PeerUdpMessageEventHandler</tt> of this
     * <tt>NetAccessManager</tt> which is to be notified when incoming UDP
     * messages have been processed and are ready for delivery.
     * 
     * @return the <tt>PeerUdpMessageEventHandler</tt> of this
     *         <tt>NetAccessManager</tt> which is to be notified when incoming
     *         UDP messages have been processed and are ready for delivery
     */
    public PeerUdpMessageEventHandler getUdpMessageEventHandler()
    {
        return peerUdpMessageEventHandler;
    }

    /**
     * Gets the <tt>ChannelDataEventHandler</tt> of this
     * <tt>NetAccessManager</tt> which is to be notified when incoming
     * ChannelData messages have been processed and are ready for delivery.
     * 
     * @return the <tt>ChannelDataEventHandler</tt> of this
     *         <tt>NetAccessManager</tt> which is to be notified when incoming
     *         ChannelData messages have been processed and are ready for
     *         delivery
     */
    public ChannelDataEventHandler getChannelDataMessageEventHandler()
    {
        return channelDataEventHandler;
    }

    /**
     * Gets the <tt>MessageQueue</tt> of this <tt>NetAccessManager</tt> in which
     * incoming messages are stocked for processing.
     *
     * @return the <tt>MessageQueue</tt> of this <tt>NetAccessManager</tt> in
     * which incoming messages are stocked for processing
     */
    MessageQueue getMessageQueue()
    {
        return messageQueue;
    }

    /**
     * Gets the <tt>StunStack</tt> which has created this instance and is its
     * owner.
     *
     * @return the <tt>StunStack</tt> which has created this instance and is its
     * owner
     */
    StunStack getStunStack()
    {
        return stunStack;
    }

    /**
     * A civilized way of not caring!
     * @param message a description of the error
     * @param error   the error that has occurred
     */
    @Override
    public void handleError(String message, Throwable error)
    {
        /**
         * apart from logging, i am not sure what else we could do here.
         */
        logger.log( Level.FINE,
                        "The following error occurred with "
                        +"an incoming message:",
                        error);
    }

    /**
     * Clears the faulty thread and reports the problem.
     *
     * @param callingThread the thread where the error occurred.
     * @param message       A description of the error
     * @param error         The error itself
     */
    @Override
    public void handleFatalError(Runnable callingThread,
                                 String message,
                                 Throwable error)
    {
        if (callingThread instanceof Connector)
        {
            Connector ap = (Connector)callingThread;

            //make sure nothing's left and notify user
            removeSocket(ap.getListenAddress());
            logger.log(Level.WARNING, "Removing connector:" + ap, error);
        }
        else if( callingThread instanceof MessageProcessor )
        {
            MessageProcessor mp = (MessageProcessor)callingThread;
            logger.log( Level.WARNING, "A message processor has unexpectedly "
                    + "stopped. AP:" + mp, error);

            //make sure the guy's dead.
            mp.stop();
            messageProcessors.remove(mp);

            mp = new MessageProcessor(this);
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
     */
    protected void addSocket(IceSocketWrapper socket)
    {
        //no null check - let it through as a NullPointerException
        TransportAddress localAddr
            = new TransportAddress(
                    socket.getLocalAddress(),
                    socket.getLocalPort(),
                    socket.getUDPSocket() != null ? Transport.UDP :
                        Transport.TCP);

        if (socket.getUDPSocket() != null &&
            !netUDPAccessPoints.containsKey(localAddr))
        {
            Connector ap = new Connector(socket, messageQueue, this);

            netUDPAccessPoints.put(localAddr, ap);
            ap.start();
        }

        if (socket.getTCPSocket() != null &&
            !netTCPAccessPoints.containsKey(localAddr))
        {
            Connector ap = new Connector(socket, messageQueue, this);

            netTCPAccessPoints.put(localAddr, ap);
            ap.start();
        }
    }

    /**
     * Stops and deletes the specified access point.
     *
     * @param address the address of the connector to remove.
     */
    protected void removeSocket(TransportAddress address)
    {
        Connector ap;

        switch (address.getTransport())
        {
        case TCP:
            ap = netTCPAccessPoints.remove(address);
            break;
        case UDP:
            ap = netUDPAccessPoints.remove(address);
            break;
        default:
            ap = null;
            break;
        }

        if(ap != null)
            ap.stop();
    }

    /**
     * Stops <tt>NetAccessManager</tt> and all of its <tt>MessageProcessor</tt>.
     */
    public void stop()
    {
        for(MessageProcessor mp : messageProcessors)
        {
            mp.stop();
        }
    }

    //---------------thread pool implementation --------------------------------
    /**
     * Adjusts the number of concurrently running MessageProcessors.
     * If the number is smaller or bigger than the number of threads
     * currently running, then message processors are created/deleted so that
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
            MessageProcessor mp = new MessageProcessor(this);

            messageProcessors.add(mp);
            mp.start();
        }
    }

    /**
     * Stops message processors until processors count equals newSize.
     *
     * @param newSize the new thread pool size
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
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     */
    void sendMessage(
            Message stunMessage,
            TransportAddress srcAddr,
            TransportAddress remoteAddr)
        throws IllegalArgumentException,
               IOException
    {
        byte[] bytes = stunMessage.encode(stunStack);

        Connector ap = null;

        if (srcAddr.getTransport() == Transport.UDP)
            ap = netUDPAccessPoints.get(srcAddr);
        else if (srcAddr.getTransport() == Transport.TCP)
            ap = netTCPAccessPoints.get(srcAddr);
        if (ap == null)
        {
            throw new IllegalArgumentException(
                    "No socket has been added for source address: " + srcAddr);
        }

        ap.sendMessage(bytes, remoteAddr);
    }
    
    /**
     * Sends the specified stun message through the specified access point.
     *
     * @param channelData the message to send
     * @param srcAddr the access point to use to send the message
     * @param remoteAddr the destination of the message.
     *
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws StunException 
     */
    void sendMessage(
            ChannelData channelData,
            TransportAddress srcAddr,
            TransportAddress remoteAddr)
        throws IllegalArgumentException,
               IOException, StunException
    {
        byte[] bytes = channelData.encode();

        Connector ap = null;

        if (srcAddr.getTransport() == Transport.UDP)
            ap = netUDPAccessPoints.get(srcAddr);
        else if (srcAddr.getTransport() == Transport.TCP)
            ap = netTCPAccessPoints.get(srcAddr);
        if (ap == null)
        {
            throw new IllegalArgumentException(
                    "No socket has been added for source address: " + srcAddr);
        }

        ap.sendMessage(bytes, remoteAddr);
    }

    /**
     * Sends the specified bytes through the specified access point.
     *
     * @param bytes the bytes to send.
     * @param srcAddr the access point to use to send the bytes.
     * @param remoteAddr the destination of the message.
     *
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws StunException 
     */
    void sendMessage(
            byte[] bytes,
            TransportAddress srcAddr,
            TransportAddress remoteAddr)
        throws IllegalArgumentException,
               IOException, StunException
    {
        Connector ap = null;
        if (srcAddr.getTransport() == Transport.UDP)
            ap = netUDPAccessPoints.get(srcAddr);
        else if (srcAddr.getTransport() == Transport.TCP)
            ap = netTCPAccessPoints.get(srcAddr);
        if (ap == null)
        {
            throw new IllegalArgumentException(
                    "No socket has been added for source address: " + srcAddr);
        }
        ap.sendMessage(bytes, remoteAddr);
    }
}
