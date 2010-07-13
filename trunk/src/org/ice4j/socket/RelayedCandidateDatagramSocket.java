/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.socket;

import java.io.*;
import java.net.*;
import java.util.*;
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
 * @author Lubomir Marinov
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
     * The lifetime in milliseconds of a TURN permission created using a
     * CreatePermission request.
     */
    private static final long PERMISSION_LIFETIME = 300 /* seconds */ * 1000L;

    /**
     * The time in milliseconds before a TURN permission expires that a
     * <tt>RelayedCandidateDatagramSocket</tt> is to try to reinstall it. 
     */
    private static final long PERMISSION_LIFETIME_LEEWAY
        = 60 /* seconds */ * 1000L;

    /**
     * The list of per-peer <tt>Channel</tt>s through which this
     * <tt>RelayedCandidateDatagramSocket</tt>s relays data send to it to
     * peer <tt>TransportAddress</tt>es.
     */
    private final List<Channel> channels = new LinkedList<Channel>();

    /**
     * The indicator which determines whether this instance has started
     * executing or has executed its {@link #close()} method.
     */
    private boolean closed = false;

    /**
     * The <tt>DatagramPacket</tt>s which are to be received through this
     * <tt>DatagramSocket</tt> upon calls to its
     * {@link #receive(DatagramPacket)} method. They have been received from the
     * TURN server in the form of Data indications.
     */
    private final List<DatagramPacket> packetsToReceive
        = new LinkedList<DatagramPacket>();

    /**
     * The <tt>DatagramSocket</tt>s which have been sent through this
     * <tt>DatagramSocket</tt> using its {@link #send(DatagramPacket)} method
     * and which are to be relayed through its associated TURN server in the
     * form of Send indications.
     */
    private final List<DatagramPacket> packetsToSend
        = new LinkedList<DatagramPacket>();

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

        this.turnCandidateHarvest.harvester.stunStack.addIndicationListener(
                this.turnCandidateHarvest.hostCandidate.getTransportAddress(),
                this);
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
        turnCandidateHarvest.harvester.stunStack.removeIndicationListener(
                turnCandidateHarvest.hostCandidate.getTransportAddress(),
                this);
        turnCandidateHarvest.close(this);
    }

    /**
     * Creates {@link #sendThread} which is to send {@link #packetsToSend} to
     * the associated TURN server.
     */
    private void createSendThread()
    {
        synchronized (packetsToSend)
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
                                    synchronized (packetsToSend)
                                    {
                                        if (sendThread
                                                == Thread.currentThread())
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
     * <tt>RelayedCandidateDatagram</tt> returns the <tt>port</tt> of its
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
        catch (SocketException sex)
        {
            packetToReceive = null;
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
        if (request.getMessageType() == Message.CREATEPERMISSION_REQUEST)
            setChannelBound(request, false);
        return false;
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
        if (request.getMessageType() == Message.CREATEPERMISSION_REQUEST)
            setChannelBound(request, true);
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
            while (true)
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
                    continue;
                }
                else
                {
                    DatagramPacket packetToReceive = packetsToReceive.remove(0);

                    MultiplexingDatagramSocket.copy(packetToReceive, p);
                    packetsToReceive.notifyAll();
                    break;
                }
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
                    int channelCount = channels.size();
                    TransportAddress peerAddress
                        = new TransportAddress(
                                packetToSend.getAddress(),
                                packetToSend.getPort(),
                                Transport.UDP);
                    Channel channel = null;

                    for (int channelIndex = 0;
                            channelIndex < channelCount;
                            channelIndex++)
                    {
                        Channel aChannel = channels.get(channelIndex);

                        if (aChannel.peerAddressEquals(peerAddress))
                        {
                            channel = aChannel;
                            break;
                        }
                    }
                    if (channel == null)
                    {
                        channel = new Channel(peerAddress);
                        channels.add(channel);
                    }

                    /*
                     * Either bind the channel or send the packetToSend through
                     * it.
                     */
                    if (channel.isBound())
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
                    else if (!channel.isBinding())
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
                packetsToSend.add(MultiplexingDatagramSocket.clone(p));

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
            int channelCount = channels.size();

            for (int channelIndex = 0;
                    channelIndex < channelCount;
                    channelIndex++)
            {
                Channel channel = channels.get(channelIndex);

                if (channel.peerAddressEquals(peerAddress))
                {
                    channel.setBound(bound, transactionID);
                    packetsToSend.notifyAll();
                    break;
                }
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
         * The indication which determines whether a confirmation has been
         * received that this <tt>Channel</tt> has been bound.
         */
        private boolean bound = false;

        /**
         * The <tt>TransportAddress</tt> of the peer to which this
         * <tt>Channel</tt> provides a permission of this
         * <tt>RelayedCandidateDatagramSocket</tt> to send data to.
         */
        private final TransportAddress peerAddress;

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
            byte[] transactionID
                = TransactionID.createNewTransactionID().getBytes();
            Request createPermissionRequest
                = MessageFactory.createCreatePermissionRequest(
                        peerAddress,
                        transactionID);

            createPermissionRequest.setTransactionID(transactionID);
            turnCandidateHarvest.sendRequest(
                    RelayedCandidateDatagramSocket.this,
                    createPermissionRequest);

            bindingTransactionID = transactionID;
            bindingTimeStamp = System.currentTimeMillis();
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
            return
                this.peerAddress.getAddress().equals(peerAddress.getAddress());
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

            byte[] transactionID
                = TransactionID.createNewTransactionID().getBytes();
            Indication sendIndication
                = MessageFactory.createSendIndication(
                        peerAddress,
                        data,
                        transactionID);

            sendIndication.setTransactionID(transactionID);
            turnCandidateHarvest.harvester.stunStack.sendIndication(
                    sendIndication,
                    turnCandidateHarvest.harvester.stunServer,
                    turnCandidateHarvest.hostCandidate.getTransportAddress());
        }

        /**
         * Sets the indicator which determines whether this <tt>Channel</tt> is
         * bound/installed.
         *
         * @param bound <tt>true</tt> if this <tt>Channel</tt> is to be marked
         * as bound/installed; otherwise, <tt>false</tt>
         * @param boundTransactionID an array of <tt>byte</tt>s which represents
         * the ID of the transaction with which the confirmation about the
         * binding/installing has arrived
         */
        public void setBound(boolean bound, byte[] boundTransactionID)
        {
            if (bindingTransactionID != null)
            {
                bindingTransactionID = null;
                this.bound = bound;
            }
        }
    }
}
