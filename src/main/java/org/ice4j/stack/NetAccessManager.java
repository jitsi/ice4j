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
package org.ice4j.stack;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
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
 * @author Boris Grozev
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
     * Thread pool to execute {@link MessageProcessor}s across all
     * {@link NetAccessManager}s.
     * The work-stealing thread pool {@link java.util.concurrent.ForkJoinPool}
     * tries to utilizes all available processors in parallel, but does not
     * have guarantee about the order of execution, but underlying transport
     * (UDP) also does not have such guarantee, so it is ok when some of the
     * messages will be processed out of arrival (enqueuing) order, but faster.
     */
    private static ForkJoinPool messageProcessorExecutor
        = new ForkJoinPool(Runtime.getRuntime().availableProcessors());

    /**
     * Pool of <tt>MessageProcessor</tt> objects to avoid extra-allocations of
     * processor object per <tt>RawMessage</tt> needed to process.
     */
    private final ArrayBlockingQueue<MessageProcessor> messageProcessorsPool
        = new ArrayBlockingQueue<>(8);

    /**
     * The set of <tt>Future</tt>'s of not yet processed <tt>RawMessage</tt>s,
     * this tracking is necessary to properly cancel pending tasks in case
     * {@link #stop()} is called.
     */
    private final ConcurrentHashMap.KeySetView<MessageProcessor, Boolean>
        activeMessageProcessors = ConcurrentHashMap.newKeySet();

    /**
     * All <tt>Connectors</tt> currently in use with UDP. The table maps a local
     * <tt>TransportAddress</tt> and and a remote <tt>TransportAddress</tt> to
     * a <tt>Connector</tt>. We allow a <tt>Connector</tt> to be added without
     * a specified remote address, under the <tt>null</tt> key.
     *
     * Due to the final hashCode() method of InetSocketAddress, TransportAddress
     * cannot override and it causes problem to store both UDP and TCP address
     * (i.e. 192.168.0.3:5000/tcp has the same hashcode as 192.168.0.3:5000/udp
     * because InetSocketAddress does not take into account transport).
     */
    private final Map<TransportAddress, Map<TransportAddress, Connector>>
        udpConnectors
            = new HashMap<>();

    /**
     * All <tt>Connectors</tt> currently in use with TCP. The table maps a local
     * <tt>TransportAddress</tt> and and a remote <tt>TransportAddress</tt> to
     * a <tt>Connector</tt>. We allow a <tt>Connector</tt> to be added without
     * a specified remote address, under the <tt>null</tt> key.
     *
     * Due to the final hashCode() method of InetSocketAddress, TransportAddress
     * cannot override and it causes problem to store both UDP and TCP address
     * (i.e. 192.168.0.3:5000/tcp has the same hashcode as 192.168.0.3:5000/udp
     * because InetSocketAddress does not take into account transport).
     */
    private final Map<TransportAddress, Map<TransportAddress, Connector>>
        tcpConnectors
            = new HashMap<>();

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
     * The <tt>StunStack</tt> which has created this instance, is its owner and
     * is the handler that incoming message requests should be passed to.
     */
    private final StunStack stunStack;

    /**
     * Indicates if this <tt>NetAccessManager</tt> is stopped
     */
    private final AtomicBoolean isStopped = new AtomicBoolean(false);

    /**
     * Callback to be called when scheduled <tt>MessageProcessor</tt> completes
     * processing it's <tt>RawMessage</tt>.
     */
    private final Consumer<MessageProcessor>
        onMessageProcessorProcessedRawMessage = messageProcessor -> {
        activeMessageProcessors.remove(messageProcessor);
        messageProcessorsPool.offer(messageProcessor);
    };

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
        if (this.isStopped.get())
        {
            logger.log(Level.WARNING,
                "Got error when stopped, ignoring: " + message, error);
            return;
        }
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
        if (this.isStopped.get())
        {
            logger.log(Level.WARNING,
                "Got fatal error when stopped, ignoring: " + message, error);
            return;
        }

        if (callingThread instanceof Connector)
        {
            Connector connector = (Connector)callingThread;

            //make sure nothing's left and notify user
            removeSocket(connector.getListenAddress(),
                         connector.getRemoteAddress());
            if (error != null)
            {
                logger.log(Level.WARNING, "Removing connector:" + connector,
                           error);
            } else if (logger.isLoggable(Level.FINE))
            {
                logger.fine("Removing connector " + connector);
            }
        }
        else
        {
            logger.log(Level.SEVERE, message, error);
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
        Socket tcpSocket  = socket.getTCPSocket();

        TransportAddress remoteAddress = null;
        if (tcpSocket != null)
        {
            // In case of TCP we can extract the remote address from the actual
            // Socket.
            remoteAddress
                = new TransportAddress(tcpSocket.getInetAddress(),
                                       tcpSocket.getPort(),
                                       Transport.TCP);
        }

        addSocket(socket, remoteAddress);
    }

    /**
     * Creates and starts a new access point based on the specified socket.
     * If the specified access point has already been installed the method
     * has no effect.
     *
     * @param  socket   the socket that the access point should use.
     * @param remoteAddress the remote address of the socket of the
     * {@link Connector} to be created if it is a TCP socket, or null if it
     * is UDP.
     */
    protected void addSocket(IceSocketWrapper socket,
                             TransportAddress remoteAddress)
    {
        Transport transport
            = socket.getUDPSocket() != null ? Transport.UDP : Transport.TCP;
        TransportAddress localAddress
            = new TransportAddress(
                    socket.getLocalAddress(),
                    socket.getLocalPort(),
                    transport);

        final Map<TransportAddress, Map<TransportAddress, Connector>>
            connectorsMap
                = (transport == Transport.UDP)
                ? udpConnectors
                : tcpConnectors;

        synchronized (connectorsMap)
        {
            Map<TransportAddress, Connector> connectorsForLocalAddress
                = connectorsMap.get(localAddress);

            if (connectorsForLocalAddress == null)
            {
                connectorsForLocalAddress = new HashMap<>();
                connectorsMap.put(localAddress, connectorsForLocalAddress);
            }

            if (!connectorsForLocalAddress.containsKey(remoteAddress))
            {
                Connector connector
                    = new Connector(socket, remoteAddress, this::onIncomingRawMessage, this);

                connectorsForLocalAddress.put(remoteAddress, connector);
                connector.start();
            }
            else
            {
                logger.info("Not creating a new Connector, because we already "
                            + "have one for the given address pair: "
                            + localAddress + " -> " + remoteAddress);
            }
        }
    }

    /**
     * Stops and deletes the specified access point.
     *
     * @param localAddress the local address of the connector to remove.
     * @param remoteAddress the remote address of the connector to remote. Use
     * <tt>null</tt> to match the <tt>Connector</tt> with no specified remote
     * address.
     */
    protected void removeSocket(TransportAddress localAddress,
                                TransportAddress remoteAddress)
    {
        Connector connector = null;

        final Map<TransportAddress, Map<TransportAddress, Connector>>
                connectorsMap
                = (localAddress.getTransport() == Transport.UDP)
                ? udpConnectors
                : tcpConnectors;

        synchronized (connectorsMap)
        {
            Map<TransportAddress, Connector> connectorsForLocalAddress
                    = connectorsMap.get(localAddress);

            if (connectorsForLocalAddress != null)
            {
                connector = connectorsForLocalAddress.get(remoteAddress);

                if (connector != null)
                {
                    connectorsForLocalAddress.remove(remoteAddress);
                    if (connectorsForLocalAddress.isEmpty())
                        connectorsMap.remove(localAddress);
                }
            }
        }

        if(connector != null)
            connector.stop();
    }

    /**
     * Stops <tt>NetAccessManager</tt> and all of its <tt>MessageProcessor</tt>.
     */
    @SuppressWarnings("unchecked")
    public void stop()
    {
        // Mark NetAccessManager as stopped, it will immediately result in
        // ignoring of all concurrent requests to handle messages
        this.isStopped.set(true);

        // no item can be added to {@link #unprocessedMessageFutures} when
        // NetAccessManager is stopped, so it is safe to iterate without
        // removing item in-place.
        for (MessageProcessor messageProcessor: activeMessageProcessors)
        {
            messageProcessor.cancel();
        }
        activeMessageProcessors.clear();

        for (Object o : new Object[]{udpConnectors, tcpConnectors})
        {
            Map<TransportAddress, Map<TransportAddress, Connector>>
                connectorsMap
                    = (Map<TransportAddress, Map<TransportAddress, Connector>>)o;

            synchronized (connectorsMap)
            {
                for (Map<TransportAddress, Connector> connectorsForLocalAddress
                        : connectorsMap.values())
                {
                    for (Connector connector : connectorsForLocalAddress.values())
                    {
                        connector.stop();
                    }
                }
            }

        }
    }

    /**
     * Returns the <tt>Connector</tt> responsible for a particular source
     * address and a particular destination address.
     *
     * @param localAddress the source address.
     * @param remoteAddress the destination address.
     * Returns the <tt>Connector</tt> responsible for a particular source
     * address and a particular destination address, or <tt>null</tt> if there's
     * none.
     */
    private Connector getConnector(TransportAddress localAddress,
                                   TransportAddress remoteAddress)
    {
        boolean udp = localAddress.getTransport() == Transport.UDP;
        final Map<TransportAddress, Map<TransportAddress, Connector>>
                connectorsMap
                = udp
                ? udpConnectors
                : tcpConnectors;
        Connector connector = null;

        synchronized (connectorsMap)
        {
            Map<TransportAddress, Connector> connectorsForLocalAddress
                    = connectorsMap.get(localAddress);

            if (connectorsForLocalAddress != null)
            {
                connector = connectorsForLocalAddress.get(remoteAddress);

                // Fallback to the socket with no specific remote address
                if (udp && connector == null)
                    connector = connectorsForLocalAddress.get(null);
            }
        }

        return connector;
    }

    /**
     * Enqueues incoming message
     * @param message <tt>RawMessage</tt> to process
     */
    private void onIncomingRawMessage(final RawMessage message)
    {
        if (this.isStopped.get())
        {
            logger.fine("Got RawMessage when stopping, ignoring.");
            return;
        }

        MessageProcessor messageProcessor = messageProcessorsPool.poll();
        if (messageProcessor == null)
        {
            messageProcessor = new MessageProcessor(this);
        }
        else
        {
            messageProcessor.resetState();
        }

        messageProcessor.setMessage(
            message,
            onMessageProcessorProcessedRawMessage);

        // Because MessageProcessor is ForkJoinTask<Void> it is not re-wrapped
        // inside ForkJoinPool and no hidden allocation is done inside pool.
        messageProcessorExecutor.submit(messageProcessor);
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
        sendMessage(stunMessage.encode(stunStack), srcAddr, remoteAddr);
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
        boolean pad = srcAddr.getTransport() == Transport.TCP
            || srcAddr.getTransport() == Transport.TLS;
        sendMessage(channelData.encode(pad), srcAddr, remoteAddr);
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
     */
    void sendMessage(
            byte[] bytes,
            TransportAddress srcAddr,
            TransportAddress remoteAddr)
        throws IllegalArgumentException,
               IOException
    {
        Connector ap = getConnector(srcAddr, remoteAddr);
        if (ap == null)
        {
            throw new IllegalArgumentException(
                    "No socket found for " + srcAddr + "->" + remoteAddr);
        }

        ap.sendMessage(bytes, remoteAddr);
    }
}
