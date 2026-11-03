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
package org.ice4j.socket;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.ice.*;
import org.ice4j.ice.harvest.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;

/**
 * Represents an application-purposed (as opposed to an ICE-specific)
 * <tt>DatagramSocket</tt> for a <tt>RelayedCandidate</tt> harvested by a
 * <tt>TurnCandidateHarvest</tt> (and its associated
 * <tt>TurnCandidateHarvester</tt>, of course).
 * <tt>RelayedCandidateDatagramSocket</tt> is associated with a successful
 * Allocation on a TURN server and implements sends and receives through it
 * using TURN messages to and from that TURN server.
 *
 * @author Lyubomir Marinov
 */
public class RelayedCandidateDatagramSocket
    extends DatagramSocket
    implements MessageEventHandler
{

    /**
     * The <tt>Logger</tt> used by the <tt>RelayedCandidateDatagramSocket</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(RelayedCandidateDatagramSocket.class.getName());

    /**
     * The constant which represents a channel number value signaling that no
     * channel number has been explicitly specified.
     */
    private static final char CHANNEL_NUMBER_NOT_SPECIFIED = 0;

    /**
     * The length in bytes of the Channel Number field of a TURN ChannelData
     * message.
     */
    private static final int CHANNELDATA_CHANNELNUMBER_LENGTH = 2;

    /**
     * The length in bytes of the Length field of a TURN ChannelData message.
     */
    private static final int CHANNELDATA_LENGTH_LENGTH = 2;

    /**
     * The maximum channel number which is valid for TURN ChannelBind
     * <tt>Request</tt>.
     */
    private static final char MAX_CHANNEL_NUMBER = 0x7FFF;

    /**
     * The minimum channel number which is valid for TURN ChannelBind
     * <tt>Request</tt>s.
     */
    private static final char MIN_CHANNEL_NUMBER = 0x4000;

    /**
     * The lifetime in milliseconds of a TURN permission created using a
     * CreatePermission request.
     */
    private static final long PERMISSION_LIFETIME = 300 /* seconds */ * 1000L;

    /**
     * The default value of {@link #permissionRetryInitialDelay}, used if the
     * configured value is invalid.
     */
    private static final long DEFAULT_PERMISSION_RETRY_INITIAL_DELAY = 1000;

    /**
     * The default value of {@link #permissionRetryMaxDelay}, used if the
     * configured value is invalid.
     */
    private static final long DEFAULT_PERMISSION_RETRY_MAX_DELAY = 30_000;

    /**
     * The time in milliseconds before a TURN permission expires that a
     * <tt>RelayedCandidateDatagramSocket</tt> is to try to reinstall it.
     */
    private static final long PERMISSION_LIFETIME_LEEWAY
        = 60 /* seconds */ * 1000L;

    /**
     * The <tt>DatagramSocket</tt> through which this
     * <tt>RelayedCandidateDatagramSocket</tt> actually sends and receives the
     * data it has been asked to {@link #send(DatagramPacket)} and
     * {@link #receive(DatagramPacket)}. Since data can be exchanged with a TURN
     * server using STUN messages (i.e. Send and Data indications),
     * <tt>RelayedCandidateDatagramSocket</tt> may send and receive data using
     * the associated <tt>StunStack</tt> and not <tt>channelDataSocket</tt>.
     * However, using <tt>channelDataSocket</tt> is supposed to be more
     * efficient than using <tt>StunStack</tt>.
     */
    private final DatagramSocket channelDataSocket;

    /**
     * The list of per-peer <tt>Channel</tt>s through which this
     * <tt>RelayedCandidateDatagramSocket</tt>s relays data send to it to
     * peer <tt>TransportAddress</tt>es.
     */
    private final List<Channel> channels = new LinkedList<>();

    /**
     * The indicator which determines whether this instance has started
     * executing or has executed its {@link #close()} method.
     */
    private boolean closed = false;

    /**
     * The <tt>DatagramPacketFilter</tt> which is able to determine whether a
     * specific <tt>DatagramPacket</tt> sent through a
     * <tt>RelayedCandidateDatagramSocket</tt> is part of the ICE connectivity
     * checks. The recognizing is necessary because RFC 5245 says that "it is
     * RECOMMENDED that the agent defer creation of a TURN channel until ICE
     * completes."
     */
    private static final DatagramPacketFilter connectivityCheckRecognizer
        = new StunDatagramPacketFilter();

    /**
     * The next free channel number to be returned by
     * {@link #getNextChannelNumber()} and marked as non-free.
     */
    private char nextChannelNumber = MIN_CHANNEL_NUMBER;

    /**
     * The <tt>DatagramPacket</tt>s which are to be received through this
     * <tt>DatagramSocket</tt> upon calls to its
     * {@link #receive(DatagramPacket)} method. They have been received from the
     * TURN server in the form of Data indications.
     */
    private final List<DatagramPacket> packetsToReceive = new LinkedList<>();

    /**
     * The <tt>DatagramSocket</tt>s which have been sent through this
     * <tt>DatagramSocket</tt> using its {@link #send(DatagramPacket)} method
     * and which are to be relayed through its associated TURN server in the
     * form of Send indications.
     */
    private final List<DatagramPacket> packetsToSend = new LinkedList<>();

    /**
     * The <tt>Thread</tt> which receives <tt>DatagramPacket</tt>s from
     * {@link #channelDataSocket} and queues them in {@link #packetsToReceive}.
     */
    private Thread receiveChannelDataThread;

    /**
     * The <tt>RelayedCandidate</tt> which uses this instance as the value of
     * its <tt>socket</tt> property.
     */
    private final RelayedCandidate relayedCandidate;

    /**
     * The <tt>Thread</tt> which is to send the {@link #packetsToSend} to the
     * associated TURN server.
     */
    private Thread sendThread;

    /**
     * The <tt>TurnCandidateHarvest</tt> which has harvested
     * {@link #relayedCandidate}.
     */
    private final TurnCandidateHarvest turnCandidateHarvest;

    /**
     * The delay in milliseconds before a CreatePermission <tt>Request</tt>
     * which failed with a transient error is retried. It doubles on each
     * consecutive failure up to {@link #permissionRetryMaxDelay}.
     */
    private final long permissionRetryInitialDelay;

    /**
     * The maximum delay in milliseconds between retries of a CreatePermission
     * <tt>Request</tt>.
     */
    private final long permissionRetryMaxDelay;

    /**
     * Initializes a new <tt>RelayedCandidateDatagramSocket</tt> instance which
     * is to be the <tt>socket</tt> of a specific <tt>RelayedCandidate</tt>
     * harvested by a specific <tt>TurnCandidateHarvest</tt>.
     *
     * @param relayedCandidate the <tt>RelayedCandidate</tt> which is to use the
     * new instance as the value of its <tt>socket</tt> property
     * @param turnCandidateHarvest the <tt>TurnCandidateHarvest</tt> which has
     * harvested <tt>relayedCandidate</tt>
     * @throws SocketException if anything goes wrong while initializing the new
     * <tt>RelayedCandidateDatagramSocket</tt> instance
     */
    public RelayedCandidateDatagramSocket(
            RelayedCandidate relayedCandidate,
            TurnCandidateHarvest turnCandidateHarvest)
        throws SocketException
    {
        super(/* bindaddr */ (SocketAddress) null);

        this.relayedCandidate = relayedCandidate;
        this.turnCandidateHarvest = turnCandidateHarvest;

        long initialDelay
            = HarvestConfig.config.getTurnPermissionRetryInitialDelay()
                .toMillis();
        long maxDelay
            = HarvestConfig.config.getTurnPermissionRetryMaxDelay().toMillis();

        if ((initialDelay <= 0) || (maxDelay < initialDelay))
        {
            logger.warning(
                    "Invalid TURN permission retry delays (initial="
                        + initialDelay + " ms, max=" + maxDelay
                        + " ms), using the defaults.");
            initialDelay = DEFAULT_PERMISSION_RETRY_INITIAL_DELAY;
            maxDelay = DEFAULT_PERMISSION_RETRY_MAX_DELAY;
        }
        permissionRetryInitialDelay = initialDelay;
        permissionRetryMaxDelay = maxDelay;

        this.turnCandidateHarvest
                .harvester
                    .getStunStack()
                        .addIndicationListener(
                                this.turnCandidateHarvest.hostCandidate
                                        .getTransportAddress(),
                                this);

        DatagramSocket hostSocket
            = this.turnCandidateHarvest.hostCandidate
                    .getCandidateIceSocketWrapper().getUDPSocket();

        if (hostSocket instanceof MultiplexingDatagramSocket)
        {
            channelDataSocket
                = ((MultiplexingDatagramSocket) hostSocket).getSocket(
                        new TurnDatagramPacketFilter(
                                this.turnCandidateHarvest.harvester.stunServer)
                        {
                            @Override
                            public boolean accept(DatagramPacket p)
                            {
                                return channelDataSocketAccept(p);
                            }

                            @Override
                            protected boolean acceptMethod(char method)
                            {
                                return channelDataSocketAcceptMethod(method);
                            }
                        });
        }
        else
            channelDataSocket = null;
    }

    /**
     * Determines whether a specific <tt>DatagramPacket</tt> is accepted by
     * {@link #channelDataSocket} (i.e. whether <tt>channelDataSocket</tt>
     * understands <tt>p</tt> and <tt>p</tt> is meant to be received by
     * <tt>channelDataSocket</tt>).
     *
     * @param p the <tt>DatagramPacket</tt> which is to be checked whether it is
     * accepted by <tt>channelDataSocket</tt>
     * @return <tt>true</tt> if <tt>channelDataSocket</tt> accepts <tt>p</tt>
     * (i.e. <tt>channelDataSocket</tt> understands <tt>p</tt> and <tt>p</tt> is
     * meant to be received by <tt>channelDataSocket</tt>); otherwise,
     * <tt>false</tt>
     */
    private boolean channelDataSocketAccept(DatagramPacket p)
    {
        // Is it from our TURN server?
        if (turnCandidateHarvest.harvester.stunServer.equals(
                p.getSocketAddress()))
        {
            int pLength = p.getLength();

            if (pLength
                    >= (CHANNELDATA_CHANNELNUMBER_LENGTH
                            + CHANNELDATA_LENGTH_LENGTH))
            {
                byte[] pData = p.getData();
                int pOffset = p.getOffset();

                /*
                 * The first two bits should be 0b01 because of the current
                 * channel number range 0x4000 - 0x7FFE. But 0b10 and 0b11 which
                 * are currently reserved and may be used in the future to
                 * extend the range of channel numbers.
                 */
                if ((pData[pOffset] & 0xC0) != 0)
                {
                    /*
                     * Technically, we cannot create a DatagramPacket from a
                     * ChannelData message with a Channel Number we do not know
                     * about. But determining that we know the value of the
                     * Channel Number field may be too much of an unnecessary
                     * performance penalty and it may be unnecessary because the
                     * message comes from our TURN server and it looks like a
                     * ChannelData message already.
                     */
                    pOffset += CHANNELDATA_CHANNELNUMBER_LENGTH;
                    pLength -= CHANNELDATA_CHANNELNUMBER_LENGTH;

                    int length
                        = ((pData[pOffset++] << 8)
                              | (pData[pOffset++] & 0xFF));

                    int padding = ((length % 4) > 0) ? 4 - (length % 4) : 0;

                    /*
                     * The Length field specifies the length in bytes of the
                     * Application Data field. The Length field does not include
                     * the padding that is sometimes present in the data of the
                     * DatagramPacket.
                     */
                    return length == pLength - padding - CHANNELDATA_LENGTH_LENGTH 
                        || length == pLength - CHANNELDATA_LENGTH_LENGTH;
                }
            }
        }
        return false;
    }

    /**
     * Determines whether {@link #channelDataSocket} accepts
     * <tt>DatagramPacket</tt>s which represent STUN messages with a specific
     * method.
     *
     * @param method the method of the STUN messages represented in
     * <tt>DatagramPacket</tt>s which is accepted by <tt>channelDataSocket</tt>
     * @return <tt>true</tt> if <tt>channelDataSocket</tt> accepts
     * <tt>DatagramPacket</tt>s which represent STUN messages with the specified
     * <tt>method</tt>; otherwise, <tt>false</tt>
     */
    private boolean channelDataSocketAcceptMethod(char method)
    {
        /*
         * Accept only ChannelData messages for now. ChannelData messages are
         * not STUN messages so they do not have a method associated with them.
         */
        return false;
    }

    /**
     * Closes this datagram socket.
     *
     * @see DatagramSocket#close()
     */
    @Override
    public void close()
    {
        synchronized (this)
        {
            if (this.closed)
                return;
            else
                this.closed = true;
        }
        synchronized (packetsToReceive)
        {
            packetsToReceive.notifyAll();
        }
        synchronized (packetsToSend)
        {
            packetsToSend.notifyAll();
        }
        turnCandidateHarvest.harvester.getStunStack().removeIndicationListener(
                turnCandidateHarvest.hostCandidate.getTransportAddress(),
                this);
        turnCandidateHarvest.close(this);

        super.close();
    }

    /**
     * Creates {@link #receiveChannelDataThread} which is to receive
     * <tt>DatagramPacket</tt>s from {@link #channelDataSocket} and queue them
     * in {@link #packetsToReceive}.
     */
    private void createReceiveChannelDataThread()
    {
        receiveChannelDataThread
            = new Thread()
            {
                @Override
                public void run()
                {
                    boolean done = false;

                    try
                    {
                        runInReceiveChannelDataThread();
                        done = true;
                    }
                    catch (SocketException sex)
                    {
                        done = true;
                    }
                    finally
                    {
                        /*
                         * If receiveChannelDataThread is dying and this
                         * RelayedCandidateDatagramSocket is not closed, then
                         * spawn a new receiveChannelDataThread.
                         */
                        synchronized (packetsToReceive)
                        {
                            if (receiveChannelDataThread
                                    == Thread.currentThread())
                                receiveChannelDataThread = null;
                            if ((receiveChannelDataThread == null)
                                    && !closed
                                    && !done)
                                createReceiveChannelDataThread();
                        }
                    }
                }
            };
        receiveChannelDataThread.start();
    }

    /**
     * Creates {@link #sendThread} which is to send {@link #packetsToSend} to
     * the associated TURN server.
     */
    private void createSendThread()
    {
        sendThread
            = new Thread()
            {
                @Override
                public void run()
                {
                    try
                    {
                        runInSendThread();
                    }
                    finally
                    {
                        /*
                         * If sendThread is dying and there are packetsToSend,
                         * then spawn a new sendThread.
                         */
                        synchronized (packetsToSend)
                        {
                            if (sendThread == Thread.currentThread())
                                sendThread = null;
                            if ((sendThread == null)
                                    && !closed
                                    && !packetsToSend.isEmpty())
                                createSendThread();
                        }
                    }
                }
            };
        sendThread.start();
    }

    /**
     * Gets the local address to which the socket is bound.
     * <tt>RelayedCandidateDatagramSocket</tt> returns the <tt>address</tt> of
     * its <tt>localSocketAddress</tt>.
     * <p>
     * If there is a security manager, its <tt>checkConnect</tt> method is first
     * called with the host address and <tt>-1</tt> as its arguments to see if
     * the operation is allowed.
     * </p>
     *
     * @return the local address to which the socket is bound, or an
     * <tt>InetAddress</tt> representing any local address if either the socket
     * is not bound, or the security manager <tt>checkConnect</tt> method does
     * not allow the operation
     * @see #getLocalSocketAddress()
     * @see DatagramSocket#getLocalAddress()
     */
    @Override
    public InetAddress getLocalAddress()
    {
        return getLocalSocketAddress().getAddress();
    }

    /**
     * Returns the port number on the local host to which this socket is bound.
     * <tt>RelayedCandidateDatagramSocket</tt> returns the <tt>port</tt> of its
     * <tt>localSocketAddress</tt>.
     *
     * @return the port number on the local host to which this socket is bound
     * @see #getLocalSocketAddress()
     * @see DatagramSocket#getLocalPort()
     */
    @Override
    public int getLocalPort()
    {
        return getLocalSocketAddress().getPort();
    }

    /**
     * Returns the address of the endpoint this socket is bound to, or
     * <tt>null</tt> if it is not bound yet. Since
     * <tt>RelayedCandidateDatagramSocket</tt> represents an
     * application-purposed <tt>DatagramSocket</tt> relaying data to and from a
     * TURN server, the <tt>localSocketAddress</tt> is the
     * <tt>transportAddress</tt> of the respective <tt>RelayedCandidate</tt>.
     *
     * @return a <tt>SocketAddress</tt> representing the local endpoint of this
     * socket, or <tt>null</tt> if it is not bound yet
     * @see DatagramSocket#getLocalSocketAddress()
     */
    @Override
    public InetSocketAddress getLocalSocketAddress()
    {
        return getRelayedCandidate().getTransportAddress();
    }

    /**
     * Gets the next free channel number to be allocated to a <tt>Channel</tt>
     * and marked as non-free.
     *
     * @return the next free channel number to be allocated to a
     * <tt>Channel</tt> and marked as non-free.
     */
    private char getNextChannelNumber()
    {
        char nextChannelNumber;

        if (this.nextChannelNumber > MAX_CHANNEL_NUMBER)
            nextChannelNumber = CHANNEL_NUMBER_NOT_SPECIFIED;
        else
        {
            nextChannelNumber = this.nextChannelNumber;
            this.nextChannelNumber++;
        }
        return nextChannelNumber;
    }

    /**
     * Gets the <tt>RelayedCandidate</tt> which uses this instance as the value
     * of its <tt>socket</tt> property.
     *
     * @return the <tt>RelayedCandidate</tt> which uses this instance as the
     * value of its <tt>socket</tt> property
     */
    public final RelayedCandidate getRelayedCandidate()
    {
        return relayedCandidate;
    }

    /**
     * Notifies this <tt>MessageEventHandler</tt> that a specific STUN message
     * has been received, parsed and is ready for delivery.
     * <tt>RelayedCandidateDatagramSocket</tt> handles STUN indications sent
     * from the associated TURN server and received at the associated local
     * <tt>TransportAddress</tt>.
     *
     * @param e a <tt>StunMessageEvent</tt> which encapsulates the received STUN
     * message
     */
    public void handleMessageEvent(StunMessageEvent e)
    {
        /*
         * Is it meant for us? (It should be because
         * RelayedCandidateDatagramSocket registers for STUN indications
         * received at the associated local TransportAddress only.)
         */
        if (!turnCandidateHarvest.hostCandidate.getTransportAddress().equals(
                e.getLocalAddress()))
            return;
        // Is it from our TURN server?
        if (!turnCandidateHarvest.harvester.stunServer.equals(
                e.getRemoteAddress()))
            return;

        Message message = e.getMessage();
        char messageType = message.getMessageType();

        if (messageType != Message.DATA_INDICATION)
            return;

        /*
         * RFC 5766: When the client receives a Data indication, it checks that
         * the Data indication contains both an XOR-PEER-ADDRESS and a DATA
         * attribute, and discards the indication if it does not.
         */
        XorPeerAddressAttribute peerAddressAttribute
            = (XorPeerAddressAttribute)
                message.getAttribute(Attribute.XOR_PEER_ADDRESS);

        if (peerAddressAttribute == null)
            return;

        DataAttribute dataAttribute
            = (DataAttribute) message.getAttribute(Attribute.DATA);

        if (dataAttribute == null)
            return;

        TransportAddress peerAddress
            = peerAddressAttribute.getAddress(message.getTransactionID());

        if (peerAddress == null)
            return;

        byte[] data = dataAttribute.getData();

        if (data == null)
            return;

        DatagramPacket packetToReceive;

        try
        {
            packetToReceive
                = new DatagramPacket(data, 0, data.length, peerAddress);
        }
        catch (Throwable t)
        {
            /*
             * The signature of the DatagramPacket constructor was changed
             * in JDK 8 to not declare that it may throw a SocketException.
             */
            if (t instanceof SocketException)
            {
                packetToReceive = null;
            }
            else if (t instanceof Error)
            {
                throw (Error) t;
            }
            else if (t instanceof RuntimeException)
            {
                throw (RuntimeException) t;
            }
            else
            {
                /*
                 * Unfortunately, we cannot re-throw it. Anyway, it was
                 * unlikely to occur on JDK 7.
                 */
                if (t instanceof InterruptedException)
                {
                    Thread.currentThread().interrupt();
                }
                packetToReceive = null;
            }
        }
        if (packetToReceive != null)
        {
            synchronized (packetsToReceive)
            {
                packetsToReceive.add(packetToReceive);
                packetsToReceive.notifyAll();
            }
        }
    }

    /**
     * Notifies this <tt>RelayedCandidateDatagramSocket</tt> that a specific
     * <tt>Request</tt> it has sent has either failed or received a STUN error
     * <tt>Response</tt>.
     *
     * @param response the <tt>Response</tt> which responds to <tt>request</tt>
     * @param request the <tt>Request</tt> sent by this instance to which
     * <tt>response</tt> responds
     * @return <tt>true</tt> if the failure or error condition has been handled
     * and the caller should assume this instance has recovered from it;
     * otherwise, <tt>false</tt>
     */
    public boolean processErrorOrFailure(Response response, Request request)
    {
        switch (request.getMessageType())
        {
        case Message.CHANNELBIND_REQUEST:
            setChannelNumberIsConfirmed(request, false);
            break;
        case Message.CREATEPERMISSION_REQUEST:
            processCreatePermissionFailure(response, request);
            break;
        default:
            break;
        }
        return false;
    }

    /**
     * Handles the failure of a CreatePermission <tt>Request</tt> (an error
     * <tt>Response</tt> or a transaction timeout) by updating the retry state
     * of the <tt>Channel</tt> for the peer in question and dropping the
     * <tt>DatagramPacket</tt>s queued for it.
     * <p>
     * The queued packets are dropped (as an unreliable datagram socket may)
     * so that the queue for a peer the server never permits does not grow
     * without bound, and so that stale packets are not delivered after a
     * backoff. Consequently a retry happens only when a new packet is sent to
     * the peer after the backoff has elapsed. Permanent errors such as 403
     * Forbidden are never retried.
     *
     * @param response the error <tt>Response</tt> to <tt>request</tt> or
     * <tt>null</tt> if the transaction failed without a response
     * @param request the CreatePermission <tt>Request</tt> which failed
     */
    private void processCreatePermissionFailure(
            Response response,
            Request request)
    {
        XorPeerAddressAttribute peerAddressAttribute
            = (XorPeerAddressAttribute)
                request.getAttribute(Attribute.XOR_PEER_ADDRESS);
        byte[] transactionID = request.getTransactionID();
        TransportAddress peerAddress
            = peerAddressAttribute.getAddress(transactionID);

        synchronized (packetsToSend)
        {
            Channel channel = findChannel(peerAddress);

            /*
             * Ignore a failure of a transaction other than the one we are
             * waiting for, e.g. a late failure of a request which has been
             * superseded by a forced re-bind. (If the harvest has retried the
             * request after a 401/438 challenge, processRetry has updated the
             * transaction we are waiting for.)
             */
            if ((channel == null) || !channel.isBindingWith(transactionID))
            {
                logger.fine(
                        "Ignoring a CreatePermission failure for peer "
                            + peerAddress.toRedactedString()
                            + " which we are not waiting for.");
                return;
            }

            channel.setBound(false, transactionID);

            int droppedPacketCount = 0;
            Iterator<DatagramPacket> it = packetsToSend.iterator();

            while (it.hasNext())
            {
                DatagramPacket p = it.next();

                if (channel.peerAddressEquals(
                        new TransportAddress(
                                p.getAddress(),
                                p.getPort(),
                                Transport.UDP)))
                {
                    it.remove();
                    droppedPacketCount++;
                }
            }
            channel.bindFailed(response, droppedPacketCount);
            packetsToSend.notifyAll();
        }
    }

    /**
     * Finds the <tt>Channel</tt> in {@link #channels} for a specific peer
     * <tt>TransportAddress</tt>. The caller must hold the
     * {@link #packetsToSend} lock.
     *
     * @param peerAddress the <tt>TransportAddress</tt> of the peer
     * @return the <tt>Channel</tt> for <tt>peerAddress</tt> or <tt>null</tt>
     * if there is none
     */
    private Channel findChannel(TransportAddress peerAddress)
    {
        for (Channel channel : channels)
        {
            if (channel.peerAddressEquals(peerAddress))
                return channel;
        }
        return null;
    }

    /**
     * Determines whether the error <tt>Response</tt> to a CreatePermission
     * <tt>Request</tt> indicates a condition which will not change if the
     * request is retried.
     *
     * @param response the error <tt>Response</tt> or <tt>null</tt> if the
     * transaction failed without a response
     * @return <tt>true</tt> if retrying the request is pointless
     */
    private static boolean isPermanentCreatePermissionError(Response response)
    {
        if (response == null)
            return false;

        ErrorCodeAttribute errorCodeAttribute
            = (ErrorCodeAttribute) response.getAttribute(Attribute.ERROR_CODE);

        if (errorCodeAttribute == null)
            return false;

        switch (errorCodeAttribute.getErrorCode())
        {
        case 400: // Bad Request
        case 401: // Unauthorized. The harvest only forwards a 401 here if it
                  // could not retry with credentials, see
                  // StunCandidateHarvest#processUnauthorized.
        case 403: // Forbidden: the server does not allow the peer address
        case 443: // Peer Address Family Mismatch
            return true;
        default:
            return false;
        }
    }

    /**
     * Notifies this <tt>RelayedCandidateDatagramSocket</tt> that a specific
     * <tt>Request</tt> it has sent has been retried by the
     * <tt>TurnCandidateHarvest</tt> as a new STUN transaction in response to a
     * 401 Unauthorized or 438 Stale Nonce challenge. The result of the retry
     * will be reported through {@link #processSuccess(Response, Request)} or
     * {@link #processErrorOrFailure(Response, Request)} with
     * <tt>retryRequest</tt>, so the <tt>Channel</tt> waiting for the result of
     * <tt>request</tt> has to wait for <tt>retryRequest</tt> instead.
     *
     * @param request the <tt>Request</tt> sent by this instance which has been
     * retried
     * @param retryRequest the new <tt>Request</tt> which has been sent in place
     * of <tt>request</tt>
     */
    public void processRetry(Request request, Request retryRequest)
    {
        if (request.getMessageType() != Message.CREATEPERMISSION_REQUEST)
            return;

        XorPeerAddressAttribute peerAddressAttribute
            = (XorPeerAddressAttribute)
                request.getAttribute(Attribute.XOR_PEER_ADDRESS);
        byte[] transactionID = request.getTransactionID();
        TransportAddress peerAddress
            = peerAddressAttribute.getAddress(transactionID);

        synchronized (packetsToSend)
        {
            Channel channel = findChannel(peerAddress);

            if ((channel != null) && channel.isBindingWith(transactionID))
                channel.bindingRetried(retryRequest.getTransactionID());
        }
    }

    /**
     * Notifies this <tt>RelayedCandidateDatagramSocket</tt> that a specific
     * <tt>Request</tt> it has sent has received a STUN success
     * <tt>Response</tt>.
     *
     * @param response the <tt>Response</tt> which responds to <tt>request</tt>
     * @param request the <tt>Request</tt> sent by this instance to which
     * <tt>response</tt> responds
     */
    public void processSuccess(Response response, Request request)
    {
        switch (request.getMessageType())
        {
        case Message.CHANNELBIND_REQUEST:
            setChannelNumberIsConfirmed(request, true);
            break;
        case Message.CREATEPERMISSION_REQUEST:
            setChannelBound(request, true);
            break;
        default:
            break;
        }
    }

    /**
     * Receives a datagram packet from this socket. When this method returns,
     * the <tt>DatagramPacket</tt>'s buffer is filled with the data received.
     * The datagram packet also contains the sender's IP address, and the port
     * number on the sender's machine.
     *
     * @param p the <tt>DatagramPacket</tt> into which to place the incoming
     * data
     * @throws IOException if an I/O error occurs
     * @see DatagramSocket#receive(DatagramPacket)
     */
    @Override
    public void receive(DatagramPacket p)
        throws IOException
    {
        synchronized (packetsToReceive)
        {
            do
            {
                /*
                 * According to the javadoc of DatagramSocket#close(), any
                 * thread currently blocked in #receive(DatagramPacket) upon
                 * this socket will throw a SocketException.
                 */
                if (closed)
                {
                    throw
                        new SocketException(
                                RelayedCandidateDatagramSocket.class
                                        .getSimpleName()
                                    + " has been closed.");
                }
                else if (packetsToReceive.isEmpty())
                {
                    try
                    {
                        packetsToReceive.wait();
                    }
                    catch (InterruptedException iex)
                    {
                    }
                }
                else
                {
                    DatagramPacket packetToReceive = packetsToReceive.remove(0);

                    MultiplexingXXXSocketSupport.copy(packetToReceive, p);
                    packetsToReceive.notifyAll();
                    break;
                }
            }
            while (true);
        }
    }

    /**
     * Runs in {@link #receiveChannelDataThread} to receive
     * <tt>DatagramPacket</tt>s from {@link #channelDataSocket} and queue them
     * in {@link #packetsToReceive}.
     *
     * @throws SocketException if anything goes wrong while receiving
     * <tt>DatagramPacket</tt>s from {@link #channelDataSocket} and
     * {@link #receiveChannelDataThread} is to no longer exist
     */
    private void runInReceiveChannelDataThread()
        throws SocketException
    {
        DatagramPacket p = null;

        while (!closed)
        {
            // read one datagram a time
            int receiveBufferSize = 1500;

            if (p == null)
            {
                p
                    = new DatagramPacket(
                            new byte[receiveBufferSize],
                            receiveBufferSize);
            }
            else
            {
                byte[] pData = p.getData();

                if ((pData == null) || (pData.length < receiveBufferSize))
                    p.setData(new byte[receiveBufferSize]);
                else
                    p.setLength(receiveBufferSize);
            }

            try
            {
                channelDataSocket.receive(p);
            }
            catch (Throwable t)
            {
                if (t instanceof ThreadDeath)
                {
                    // Death is the end of life no matter what.
                    throw (ThreadDeath) t;
                }
                else if (t instanceof SocketException)
                {
                    /*
                     * If the channelDataSocket has gone unusable, put an end to
                     * receiving from it.
                     */
                    throw (SocketException) t;
                }
                else
                {
                    if (logger.isLoggable(Level.WARNING))
                    {
                        logger.log(
                                Level.WARNING,
                                "Ignoring error while receiving from"
                                    + " ChannelData socket",
                                t);
                    }
                    continue;
                }
            }

            /*
             * We've been waiting in #receive so make sure we're still to
             * continue just in case.
             */
            if (closed)
                break;

            int channelDataLength = p.getLength();

            if (channelDataLength
                    < (CHANNELDATA_CHANNELNUMBER_LENGTH
                            + CHANNELDATA_LENGTH_LENGTH))
                continue;

            byte[] channelData = p.getData();
            int channelDataOffset = p.getOffset();
            char channelNumber
                = (char)
                    ((channelData[channelDataOffset++] << 8)
                            | (channelData[channelDataOffset++] & 0xFF));

            channelDataLength -= CHANNELDATA_CHANNELNUMBER_LENGTH;

            char length
                = (char)
                    ((channelData[channelDataOffset++] << 8)
                            | (channelData[channelDataOffset++] & 0xFF));

            channelDataLength -= CHANNELDATA_LENGTH_LENGTH;
            if (length > channelDataLength)
                continue;

            TransportAddress peerAddress = null;

            synchronized (packetsToSend)
            {
                int channelCount = channels.size();

                for (int channelIndex = 0;
                        channelIndex < channelCount;
                        channelIndex++)
                {
                    Channel channel = channels.get(channelIndex);

                    if (channel.channelNumberEquals(channelNumber))
                    {
                        peerAddress = channel.peerAddress;
                        break;
                    }
                }
            }
            if (peerAddress == null)
                continue;

            byte[] data = new byte[length];

            System.arraycopy(channelData, channelDataOffset, data, 0, length);

            DatagramPacket packetToReceive
                = new DatagramPacket(data, 0, length, peerAddress);

            synchronized (packetsToReceive)
            {
                packetsToReceive.add(packetToReceive);
                packetsToReceive.notifyAll();
            }
        }
    }

    /**
     * Runs in {@link #sendThread} to send {@link #packetsToSend} to the
     * associated TURN server.
     */
    private void runInSendThread()
    {
        synchronized (packetsToSend)
        {
            while (!closed)
            {
                if (packetsToSend.isEmpty())
                {
                    try
                    {
                        packetsToSend.wait();
                    }
                    catch (InterruptedException iex)
                    {
                    }
                    continue;
                }

                int packetToSendCount = packetsToSend.size();

                for (int packetToSendIndex = 0;
                        packetToSendIndex < packetToSendCount;
                        packetToSendIndex++)
                {
                    DatagramPacket packetToSend
                        = packetsToSend.get(packetToSendIndex);

                    /*
                     * Get a channel to the peer which is to receive the
                     * packetToSend.
                     */
                    TransportAddress peerAddress
                        = new TransportAddress(
                                packetToSend.getAddress(),
                                packetToSend.getPort(),
                                Transport.UDP);
                    Channel channel = findChannel(peerAddress);

                    if (channel == null)
                    {
                        channel = new Channel(peerAddress);
                        channels.add(channel);
                    }

                    /*
                     * RFC 5245 says that "it is RECOMMENDED that the agent
                     * defer creation of a TURN channel until ICE completes."
                     * RelayedCandidateDatagramSocket is not explicitly told
                     * from the outside that ICE has completed so it tries to
                     * determine it by assuming that connectivity checks send
                     * only STUN messages and ICE has completed by the time a
                     * non-STUN message is to be sent.
                     */
                    boolean forceBind = false;

                    if ((channelDataSocket != null)
                            && !channel.getChannelDataIsPreferred()
                            && !connectivityCheckRecognizer.accept(
                                    packetToSend))
                    {
                        channel.setChannelDataIsPreferred(true);
                        forceBind = true;
                    }

                    /*
                     * Either bind the channel or send the packetToSend through
                     * it.
                     */
                    if (!forceBind && channel.isBound())
                    {
                        packetsToSend.remove(packetToSendIndex);
                        try
                        {
                            channel.send(packetToSend, peerAddress);
                        }
                        catch (StunException sex)
                        {
                            if (logger.isLoggable(Level.INFO))
                            {
                                logger.log(
                                        Level.INFO,
                                        "Failed to send through "
                                            + RelayedCandidateDatagramSocket
                                                    .class.getSimpleName()
                                            + " channel." ,
                                        sex);
                            }
                        }
                        break;
                    }
                    else if (channel.isFailed() || channel.isBackingOff())
                    {
                        /*
                         * Either we have given up on obtaining a permission
                         * for this peer (the TURN server refused it with a
                         * permanent error), or a recent attempt has failed and
                         * we are backing off before trying again. Either way
                         * packetToSend cannot be delivered now, so drop it.
                         */
                        packetsToSend.remove(packetToSendIndex);
                        break;
                    }
                    else if (forceBind || !channel.isBinding())
                    {
                        try
                        {
                            channel.bind();
                        }
                        catch (StunException sex)
                        {
                            if (logger.isLoggable(Level.INFO))
                            {
                                logger.log(
                                        Level.INFO,
                                        "Failed to bind "
                                            + RelayedCandidateDatagramSocket
                                                    .class.getSimpleName()
                                            + " channel." ,
                                        sex);
                            }
                            /*
                             * Well, it may not be the fault of the packetToSend
                             * but it happened while we were trying to send it
                             * and we don't have a way to report an error so
                             * just drop packetToSend in order to change
                             * something and not just go again trying the same
                             * thing.
                             */
                            packetsToSend.remove(packetToSendIndex);
                            break;
                        }
                        /*
                         * If the Channel was bound but #bind() was forced on
                         * it, we cannot continue with the next packetToSend
                         * because it may be for the same Channel and then
                         * #bind() will not be forced and the Channel will be
                         * bound already so the send order of the packetsToSend
                         * will be disrupted.
                         */
                        if (forceBind)
                            break;
                    }
                }

                /*
                 * If no packetToSend has been sent by the current iteration,
                 * then we must be waiting for some condition to change in order
                 * to be able to send.
                 */
                if (packetsToSend.size() == packetToSendCount)
                {
                    try
                    {
                        packetsToSend.wait();
                    }
                    catch (InterruptedException iex)
                    {
                    }
                }
            }
        }
    }

    /**
     * Sends a datagram packet from this socket. The <tt>DatagramPacket</tt>
     * includes information indicating the data to be sent, its length, the IP
     * address of the remote host, and the port number on the remote host.
     *
     * @param p the <tt>DatagramPacket</tt> to be sent
     * @throws IOException if an I/O error occurs
     * @see DatagramSocket#send(DatagramPacket)
     */
    @Override
    public void send(DatagramPacket p)
        throws IOException
    {
        synchronized (packetsToSend)
        {
            if (closed)
            {
                throw
                    new IOException(
                            RelayedCandidateDatagramSocket.class.getSimpleName()
                                + " has been closed.");
            }
            else
            {
                packetsToSend.add(MultiplexingXXXSocketSupport.clone(p));
                if (sendThread == null)
                    createSendThread();
                else
                    packetsToSend.notifyAll();
            }
        }
    }

    /**
     * Sets the <tt>bound</tt> property of a <tt>Channel</tt> the installation
     * of which has been attempted by sending a specific <tt>Request</tt>.
     *
     * @param request the <tt>Request</tt> which has been attempted in order to
     * install a <tt>Channel</tt>
     * @param bound <tt>true</tt> if the <tt>bound</tt> property of the
     * <tt>Channel</tt> is to be set to <tt>true</tt>; otherwise, <tt>false</tt>
     */
    private void setChannelBound(Request request, boolean bound)
    {
        XorPeerAddressAttribute peerAddressAttribute
            = (XorPeerAddressAttribute)
                request.getAttribute(Attribute.XOR_PEER_ADDRESS);
        byte[] transactionID = request.getTransactionID();
        TransportAddress peerAddress
            = peerAddressAttribute.getAddress(transactionID);

        synchronized (packetsToSend)
        {
            Channel channel = findChannel(peerAddress);

            if (channel != null)
            {
                channel.setBound(bound, transactionID);
                packetsToSend.notifyAll();
            }
        }
    }

    /**
     * Sets the <tt>channelNumberIsConfirmed</tt> property of a <tt>Channel</tt>
     * which has attempted to allocate a specific channel number by sending a
     * specific ChannelBind <tt>Request</tt>.
     *
     * @param request the <tt>Request</tt> which has been sent to allocate a
     * specific channel number for a <tt>Channel</tt>
     * @param channelNumberIsConfirmed <tt>true</tt> if the channel number has
     * been successfully allocated; otherwise, <tt>false</tt>
     */
    private void setChannelNumberIsConfirmed(
            Request request,
            boolean channelNumberIsConfirmed)
    {
        XorPeerAddressAttribute peerAddressAttribute
            = (XorPeerAddressAttribute)
                request.getAttribute(Attribute.XOR_PEER_ADDRESS);
        byte[] transactionID = request.getTransactionID();
        TransportAddress peerAddress
            = peerAddressAttribute.getAddress(transactionID);

        synchronized (packetsToSend)
        {
            Channel channel = findChannel(peerAddress);

            if (channel != null)
            {
                channel.setChannelNumberIsConfirmed(
                        channelNumberIsConfirmed,
                        transactionID);
                packetsToSend.notifyAll();
            }
        }
    }

    /**
     * Represents a channel which relays data sent through this
     * <tt>RelayedCandidateDatagramSocket</tt> to a specific
     * <tt>TransportAddress</tt> via the TURN server associated with this
     * <tt>RelayedCandidateDatagramSocket</tt>.
     */
    private class Channel
    {
        /**
         * The time stamp in milliseconds at which {@link #bindingTransactionID}
         * has been used to bind/install this <tt>Channel</tt>.
         */
        private long bindingTimeStamp = -1;

        /**
         * The ID of the transaction with which a CreatePermission
         * <tt>Request</tt> has been sent to bind/install this <tt>Channel</tt>.
         */
        private byte[] bindingTransactionID;

        /**
         * The number of consecutive CreatePermission attempts for this
         * <tt>Channel</tt> which have failed. Used for logging.
         */
        private int consecutiveBindFailures = 0;

        /**
         * The delay in milliseconds which was applied after the latest failed
         * CreatePermission attempt, or <tt>0</tt> if there is no current
         * series of failures. Doubles on each consecutive failure up to
         * {@link #permissionRetryMaxDelay}.
         */
        private long currentRetryDelay = 0;

        /**
         * The indicator which determines whether {@link #backoffEndNanos} is
         * valid, i.e. whether a CreatePermission attempt has failed and the
         * backoff before retrying has not been observed to have elapsed yet.
         */
        private boolean inBackoff = false;

        /**
         * The value of {@link System#nanoTime()} (a monotonic clock, so wall
         * clock steps do not affect the backoff) at which the backoff after the
         * latest failed CreatePermission attempt ends. Valid only while
         * {@link #inBackoff} is <tt>true</tt>.
         */
        private long backoffEndNanos;

        /**
         * The indicator which determines whether binding/installing this
         * <tt>Channel</tt> has been given up on because the TURN server
         * rejected the permission with a permanent error.
         */
        private boolean failed = false;

        /**
         * The indication which determines whether a confirmation has been
         * received that this <tt>Channel</tt> has been bound.
         */
        private boolean bound = false;

        /**
         * The value of the <tt>data</tt> property of
         * {@link #channelDataPacket}.
         */
        private byte[] channelData;

        /**
         * The indicator which determines whether this <tt>Channel</tt> is set
         * to prefer sending <tt>DatagramPacket</tt>s using TURN ChannelData
         * messages instead of Send indications.
         */
        private boolean channelDataIsPreferred = false;

        /**
         * The <tt>DatagramPacket</tt> in which this <tt>Channel</tt> sends TURN
         * ChannelData messages through
         * {@link RelayedCandidateDatagramSocket#channelDataSocket}.
         */
        private DatagramPacket channelDataPacket;

        /**
         * The TURN channel number of this <tt>Channel</tt> which is to be or
         * has been allocated using a ChannelBind <tt>Request</tt>.
         */
        private char channelNumber = CHANNEL_NUMBER_NOT_SPECIFIED;

        /**
         * The indicator which determines whether the associated TURN server has
         * confirmed the allocation of {@link #channelNumber} by us receiving a
         * success <tt>Response</tt> to our ChannelBind <tt>Request</tt>.
         */
        private boolean channelNumberIsConfirmed;

        /**
         * The <tt>TransportAddress</tt> of the peer to which this
         * <tt>Channel</tt> provides a permission of this
         * <tt>RelayedCandidateDatagramSocket</tt> to send data to.
         */
        public final TransportAddress peerAddress;

        /**
         * Initializes a new <tt>Channel</tt> instance which is to provide this
         * <tt>RelayedCandidateDatagramSocket</tt> with a permission to send
         * to a specific peer <tt>TransportAddress</tt>.
         *
         * @param peerAddress the <tt>TransportAddress</tt> of the peer to which
         * the new instance is to provide a permission of this
         * <tt>RelayedCandidateDatagramSocket</tt> to send data to
         */
        public Channel(TransportAddress peerAddress)
        {
            this.peerAddress = peerAddress;
        }

        /**
         * Binds/installs this channel so that it provides this
         * <tt>RelayedCandidateDatagramSocket</tt> with a permission to send
         * data to the <tt>TransportAddress</tt> associated with this instance.
         *
         * @throws StunException if anything goes wrong while binding/installing
         * this channel
         */
        public void bind()
            throws StunException
        {
            byte[] createPermissionTransactionID
                = TransactionID.createNewTransactionID().getBytes();
            Request createPermissionRequest
                = MessageFactory.createCreatePermissionRequest(
                        peerAddress,
                        createPermissionTransactionID);

            createPermissionRequest.setTransactionID(
                    createPermissionTransactionID);

            /*
             * The StunStack assigns the transaction its own ID (and sets it
             * on the request), so remember the ID actually used in order to
             * be able to recognize the result of the transaction.
             */
            bindingTransactionID
                = turnCandidateHarvest.sendRequest(
                        RelayedCandidateDatagramSocket.this,
                        createPermissionRequest);
            bindingTimeStamp = System.currentTimeMillis();

            if (channelDataIsPreferred)
            {
                if (channelNumber == CHANNEL_NUMBER_NOT_SPECIFIED)
                {
                    channelNumber = getNextChannelNumber();
                    channelNumberIsConfirmed = false;
                }
                if (channelNumber != CHANNEL_NUMBER_NOT_SPECIFIED)
                {
                    byte[] channelBindTransactionID
                        = TransactionID.createNewTransactionID().getBytes();
                    Request channelBindRequest
                        = MessageFactory.createChannelBindRequest(
                                channelNumber,
                                peerAddress,
                                channelBindTransactionID);

                    channelBindRequest.setTransactionID(
                            channelBindTransactionID);

                    /*
                     * We have to be prepared to receive ChannelData messages
                     * from the TURN server as soon as we've sent the
                     * ChannelBind request and before we've received a success
                     * response to it.
                     */
                    synchronized (packetsToReceive)
                    {
                        if (!closed && (receiveChannelDataThread == null))
                            createReceiveChannelDataThread();
                    }

                    turnCandidateHarvest.sendRequest(
                            RelayedCandidateDatagramSocket.this,
                            channelBindRequest);
                }
            }
        }

        /**
         * Notifies this <tt>Channel</tt> that the CreatePermission
         * <tt>Request</tt> it is waiting for has been retried as a new
         * transaction (after a 401/438 challenge), so that the result of the
         * new transaction is recognized as the result of the binding.
         *
         * @param retryTransactionID the ID of the new transaction
         */
        public void bindingRetried(byte[] retryTransactionID)
        {
            bindingTransactionID = retryTransactionID;
            bindingTimeStamp = System.currentTimeMillis();
        }

        /**
         * Notifies this <tt>Channel</tt> that its latest CreatePermission
         * <tt>Request</tt> has failed and updates its retry state accordingly.
         *
         * @param response the error <tt>Response</tt> or <tt>null</tt> if the
         * transaction failed without a response (e.g. it timed out)
         * @param droppedPacketCount the number of queued packets to the peer
         * of this <tt>Channel</tt> which have been dropped because of the
         * failure (for logging)
         */
        public void bindFailed(Response response, int droppedPacketCount)
        {
            consecutiveBindFailures++;

            if (isPermanentCreatePermissionError(response))
            {
                failed = true;
                logger.warning(
                        "TURN server " + turnCandidateHarvest.harvester.stunServer
                            + " refused a permission for peer "
                            + peerAddress.toRedactedString()
                            + " with error "
                            + (int) ((ErrorCodeAttribute) response.getAttribute(
                                    Attribute.ERROR_CODE)).getErrorCode()
                            + ". Giving up on it and dropping packets to it"
                            + " (" + droppedPacketCount + " dropped now).");
            }
            else
            {
                currentRetryDelay
                    = (currentRetryDelay == 0)
                        ? permissionRetryInitialDelay
                        : Math.min(
                                currentRetryDelay * 2,
                                permissionRetryMaxDelay);
                inBackoff = true;
                backoffEndNanos
                    = System.nanoTime()
                        + TimeUnit.MILLISECONDS.toNanos(currentRetryDelay);

                String message
                    = "Failed to create a TURN permission on "
                        + turnCandidateHarvest.harvester.stunServer
                        + " for peer " + peerAddress.toRedactedString()
                        + " (" + consecutiveBindFailures
                        + " consecutive failures, " + droppedPacketCount
                        + " packets dropped). Will retry when a packet is"
                        + " next sent to it after " + currentRetryDelay
                        + " ms.";

                // Log the first failure of a series at INFO and the rest at
                // FINE to avoid flooding the log during an outage.
                if (consecutiveBindFailures == 1)
                    logger.info(message);
                else
                    logger.fine(message);
            }
        }

        /**
         * Determines whether a CreatePermission <tt>Request</tt> with a
         * specific transaction ID is the one this <tt>Channel</tt> is waiting
         * for a result of.
         *
         * @param transactionID the ID of the transaction to check
         * @return <tt>true</tt> if this instance is binding/installing itself
         * with the transaction identified by <tt>transactionID</tt>
         */
        public boolean isBindingWith(byte[] transactionID)
        {
            return
                (bindingTransactionID != null)
                    && Arrays.equals(bindingTransactionID, transactionID);
        }

        /**
         * Determines whether this <tt>Channel</tt> is backing off after a
         * failed CreatePermission attempt, i.e. whether it is too early to
         * attempt to bind/install it again.
         *
         * @return <tt>true</tt> if the backoff after the latest failure has
         * not elapsed yet; otherwise, <tt>false</tt>
         */
        public boolean isBackingOff()
        {
            if (inBackoff && (System.nanoTime() - backoffEndNanos >= 0))
                inBackoff = false;
            return inBackoff;
        }

        /**
         * Determines whether binding/installing this <tt>Channel</tt> has been
         * given up on.
         *
         * @return <tt>true</tt> if no further attempts to bind/install this
         * <tt>Channel</tt> are to be made and packets to its peer are to be
         * dropped
         */
        public boolean isFailed()
        {
            return failed;
        }

        /**
         * Determines whether the channel number of this <tt>Channel</tt> is
         * value equal to a specific channel number.
         *
         * @param channelNumber the channel number to be compared to the channel
         * number of this <tt>Channel</tt> for value equality
         * @return <tt>true</tt> if the specified <tt>channelNumber</tt> is
         * equal to the channel number of this <tt>Channel</tt>
         */
        public boolean channelNumberEquals(char channelNumber)
        {
            return (this.channelNumber == channelNumber);
        }

        /**
         * Gets the indicator which determines whether this <tt>Channel</tt> is
         * set to prefer sending <tt>DatagramPacket</tt>s using TURN ChannelData
         * messages instead of Send indications.
         *
         * @return the indicator which determines whether this <tt>Channel</tt>
         * is set to prefer sending <tt>DatagramPacket</tt>s using TURN
         * ChannelData messages instead of Send indications
         */
        public boolean getChannelDataIsPreferred()
        {
            return channelDataIsPreferred;
        }

        /**
         * Gets the indicator which determines whether this instance has started
         * binding/installing itself and has not received a confirmation that it
         * has succeeded in doing so yet.
         *
         * @return <tt>true</tt> if this instance has started binding/installing
         * itself and has not received a confirmation that it has succeeded in
         * doing so yet; otherwise, <tt>false</tt>
         */
        public boolean isBinding()
        {
            return (bindingTransactionID != null);
        }

        /**
         * Gets the indication which determines whether this instance is
         * currently considered bound/installed.
         *
         * @return <tt>true</tt> if this instance is currently considered
         * bound/installed; otherwise, <tt>false</tt>
         */
        public boolean isBound()
        {
            if ((bindingTimeStamp == -1)
                    || (bindingTimeStamp
                                + PERMISSION_LIFETIME
                                - PERMISSION_LIFETIME_LEEWAY)
                            < System.currentTimeMillis())
                return false;
            return (bindingTransactionID == null) && bound;
        }

        /**
         * Determines whether the <tt>peerAddress</tt> property of this instance
         * is considered by this <tt>Channel</tt> to be equal to a specific
         * <tt>TransportAddress</tt>.
         *
         * @param peerAddress the <tt>TransportAddress</tt> which is to be
         * checked for equality (as defined by this <tt>Channel</tt> and not
         * necessarily by the <tt>TransportAddress</tt> class)
         * @return <tt>true</tt> if the specified <tt>TransportAddress</tt> is
         * considered by this <tt>Channel</tt> to be equal to its
         * <tt>peerAddress</tt> property; otherwise, <tt>false</tt>
         */
        public boolean peerAddressEquals(TransportAddress peerAddress)
        {
            /*
             * CreatePermission installs a permission for the IP address and the
             * port is ignored. But ChannelBind creates a channel for the
             * peerAddress only. So if there is a chance that ChannelBind will
             * be used, have a Channel instance per peerAddress and
             * CreatePermission more often than really necessary (as a side
             * effect).
             */
            if (channelDataSocket != null)
                return this.peerAddress.equals(peerAddress);
            else
            {
                return
                    this.peerAddress.getAddress().equals(
                            peerAddress.getAddress());
            }
        }

        /**
         * Sends a specific <tt>DatagramPacket</tt> through this
         * <tt>Channel</tt> to a specific peer <tt>TransportAddress</tt>.
         *
         * @param p the <tt>DatagramPacket</tt> to be sent
         * @param peerAddress the <tt>TransportAddress</tt> of the peer to which
         * the <tt>DatagramPacket</tt> is to be sent
         * @throws StunException if anything goes wrong while sending the
         * specified <tt>DatagramPacket</tt> to the specified peer
         * <tt>TransportAddress</tt>
         */
        public void send(DatagramPacket p, TransportAddress peerAddress)
            throws StunException
        {
            byte[] pData = p.getData();
            int pOffset = p.getOffset();
            int pLength = p.getLength();
            byte[] data;

            if ((pOffset == 0) && (pLength == pData.length))
                data = pData;
            else
            {
                data = new byte[pLength];
                System.arraycopy(pData, pOffset, data, 0, pLength);
            }

            if (channelDataIsPreferred
                    && (channelNumber != CHANNEL_NUMBER_NOT_SPECIFIED)
                    && channelNumberIsConfirmed)
            {
                char length = (char) data.length;
                int channelDataLength
                    = CHANNELDATA_CHANNELNUMBER_LENGTH
                        + CHANNELDATA_LENGTH_LENGTH
                        + length;

                if ((channelData == null)
                        || (channelData.length < channelDataLength))
                {
                    channelData = new byte[channelDataLength];
                    if (channelDataPacket != null)
                        channelDataPacket.setData(channelData);
                }

                // Channel Number
                channelData[0] = (byte) (channelNumber >> 8);
                channelData[1] = (byte) (channelNumber & 0xFF);
                // Length
                channelData[2] = (byte) (length >> 8);
                channelData[3] = (byte) (length & 0xFF);
                // Application Data
                System.arraycopy(
                        data,
                        0,
                        channelData,
                        CHANNELDATA_CHANNELNUMBER_LENGTH
                            + CHANNELDATA_LENGTH_LENGTH,
                        length);

                try
                {
                    if (channelDataPacket == null)
                    {
                        channelDataPacket
                            = new DatagramPacket(
                                    channelData, 0, channelDataLength,
                                    turnCandidateHarvest.harvester.stunServer);
                    }
                    else
                        channelDataPacket.setData(channelData, 0,
                                channelDataLength);

                    channelDataSocket.send(channelDataPacket);
                }
                catch (IOException ioex)
                {
                    throw
                        new StunException(
                                StunException.NETWORK_ERROR,
                                "Failed to send TURN ChannelData message",
                                ioex);
                }
            }
            else
            {
                byte[] transactionID
                    = TransactionID.createNewTransactionID().getBytes();
                Indication sendIndication
                    = MessageFactory.createSendIndication(
                            peerAddress,
                            data,
                            transactionID);

                sendIndication.setTransactionID(transactionID);
                turnCandidateHarvest.harvester.getStunStack().sendIndication(
                        sendIndication,
                        turnCandidateHarvest.harvester.stunServer,
                        turnCandidateHarvest
                            .hostCandidate.getTransportAddress());
            }
        }

        /**
         * Sets the indicator which determines whether this <tt>Channel</tt> is
         * bound/installed.
         *
         * @param bound <tt>true</tt> if this <tt>Channel</tt> is to be marked
         * as bound/installed; otherwise, <tt>false</tt>
         * @param boundTransactionID an array of <tt>byte</tt>s which represents
         * the ID of the transaction with which the confirmation about the
         * binding/installing has arrived (currently unused)
         */
        public void setBound(boolean bound, byte[] boundTransactionID)
        {
            if (bindingTransactionID != null)
            {
                bindingTransactionID = null;
                this.bound = bound;
            }
            if (bound)
            {
                // A successful binding ends any series of failures.
                consecutiveBindFailures = 0;
                currentRetryDelay = 0;
                inBackoff = false;
            }
        }

        /**
         * Sets the indicator which determines whether this <tt>Channel</tt> is
         * set to prefer sending <tt>DatagramPacket</tt>s using TURN ChannelData
         * messages instead of Send indications.
         *
         * @param channelDataIsPreferred <tt>true</tt> if this <tt>Channel</tt>
         * is to be set to prefer sending <tt>DatagramPacket</tt>s using TURN
         * ChannelData messages instead of Send indications
         */
        public void setChannelDataIsPreferred(boolean channelDataIsPreferred)
        {
            this.channelDataIsPreferred = channelDataIsPreferred;
        }

        /**
         * Sets the indicator which determines whether the associated TURN
         * server has confirmed the allocation of the <tt>channelNumber</tt> of
         * this <tt>Channel</tt> by us receiving a success <tt>Response</tt> to
         * our ChannelBind <tt>Request</tt>.
         *
         * @param channelNumberIsConfirmed <tt>true</tt> if allocation of the
         * channel number has been confirmed by a success <tt>Response</tt> to
         * our ChannelBind <tt>Request</tt>
         * @param channelNumberIsConfirmedTransactionID an array of
         * <tt>byte</tt>s which represents the ID of the transaction with which
         * the confirmation about the allocation of the channel number has
         * arrived
         */
        public void setChannelNumberIsConfirmed(
                boolean channelNumberIsConfirmed,
                byte[] channelNumberIsConfirmedTransactionID)
        {
            this.channelNumberIsConfirmed = channelNumberIsConfirmed;
        }
    }
}
