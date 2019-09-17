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
package org.ice4j.ice;

import java.io.*;
import java.net.*;

import org.ice4j.*;
import org.ice4j.socket.*;
import org.ice4j.stack.*;
import org.jitsi.utils.logging2.*;

/**
 * <tt>LocalCandidate</tt>s are obtained by an agent for every stream component
 * and are then included in outgoing offers or answers.
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 */
public abstract class LocalCandidate
    extends Candidate<LocalCandidate>
{
    /**
     * The <tt>Logger</tt> used by the <tt>LocalCandidate</tt> class for logging
     * output.
     * Note that this shouldn't be used directly by instances of
     * {@link DefaultNominator}, because it doesn't take into account the
     * per-instance log level. Instances should use {@link #logger} instead.
     */
    private static final java.util.logging.Logger classLogger
        = java.util.logging.Logger.getLogger(HostCandidate.class.getName());

    /**
     * The type of method used to discover this candidate ("host", "upnp", "stun
     * peer reflexive", "stun server reflexive", "turn relayed", "google turn
     * relayed", "google tcp turn relayed" or "jingle node").
     */
    private CandidateExtendedType extendedType = null;

    /**
     * Ufrag for the local candidate.
     */
    private String ufrag = null;

    /**
     * Whether this <tt>LocalCandidate</tt> uses SSL.
     */
    private boolean isSSL = false;

    /**
     * The {@link Logger} used by {@link LocalCandidate} instances.
     */
    private final Logger logger;

    /**
     * Creates a <tt>LocalCandidate</tt> instance for the specified transport
     * address and properties.
     *
     * @param transportAddress  the transport address that this candidate is
     * encapsulating.
     * @param parentComponent the <tt>Component</tt> that this candidate
     * belongs to.
     * @param type the <tt>CandidateType</tt> for this <tt>Candidate</tt>.
     * @param extendedType The type of method used to discover this candidate
     * ("host", "upnp", "stun peer reflexive", "stun server reflexive", "turn
     * relayed", "google turn relayed", "google tcp turn relayed" or "jingle
     * node").
     * @param relatedCandidate the relatedCandidate: null for a host candidate,
     * the base address (host candidate) for a reflexive candidate, the mapped
     * address (the mapped address of the TURN allocate response) for a relayed
     * candidate.
     */
    public LocalCandidate(TransportAddress transportAddress,
                          Component        parentComponent,
                          CandidateType    type,
                          CandidateExtendedType extendedType,
                          LocalCandidate  relatedCandidate)

    {
        super(transportAddress, parentComponent, type, relatedCandidate);
        logger = parentComponent.getLogger().createChildLogger(this.getClass().getName());
        this.extendedType = extendedType;
    }

    /**
     * Gets the <tt>DatagramSocket</tt> associated with this
     * <tt>Candidate</tt>.
     *
     * @return the <tt>DatagramSocket</tt> associated with this
     * <tt>Candidate</tt>
     *
     * @deprecated This should be used by the library only. Users of ice4j
     * should use {@link org.ice4j.ice.Component#getSocket()} instead.
     */
    @Deprecated
    public DatagramSocket getDatagramSocket()
    {
        IceSocketWrapper wrapper = getIceSocketWrapper();
        return wrapper == null ? null : wrapper.getUDPSocket();
    }

    /**
     * Gets the <tt>Socket</tt> associated with this
     * <tt>Candidate</tt>.
     *
     * @return the <tt>Socket</tt> associated with this
     * <tt>Candidate</tt>
     *
     * @deprecated This should be used by the library only. Users of ice4j
     * should use {@link org.ice4j.ice.Component#getSocket()} instead.
     */
    @Deprecated
    public Socket getSocket()
    {
        return null;
    }

    /**
     * @return the {@link IceSocketWrapper} instance of the {@link Component}
     * which owns this {@link LocalCandidate}. Note that this IS NOT an
     * instance specific to this {@link LocalCandidate}. See
     * {@link #getCandidateIceSocketWrapper()}.
     */
    protected IceSocketWrapper getIceSocketWrapper()
    {
        return getParentComponent().getSocketWrapper();
    }

    /**
     * @return the {@link IceSocketWrapper} instance, if any, associated with
     * this candidate. Note that this IS NOT the instance which should be used
     * for reading and writing by the application, and SHOULD NOT be used from
     * outside ice4j (even if a subclass exposes it as public). Also see
     * {@link #getIceSocketWrapper()}.
     */
    protected abstract IceSocketWrapper getCandidateIceSocketWrapper();

    /**
     * @return the {@link IceSocketWrapper} instance for this candidate,
     * associated with a particular remote address.
     * @param remoteAddress the remote address for which to return an
     * associated socket.
     */
    protected IceSocketWrapper getCandidateIceSocketWrapper(
        SocketAddress remoteAddress)
    {
        // The default implementation just refers to the method which doesn't
        // involve a remove address. Extenders which support multiple instances
        // mapped by remote address should override.
        return getCandidateIceSocketWrapper();
    }

    /**
     * Creates if necessary and returns a <tt>DatagramSocket</tt> that would
     * capture all STUN packets arriving on this candidate's socket. If the
     * <tt>serverAddress</tt> parameter is not <tt>null</tt> this socket would
     * only intercept packets originating at this address.
     *
     * @param serverAddress the address of the source we'd like to receive
     * packets from or <tt>null</tt> if we'd like to intercept all STUN packets.
     *
     * @return the <tt>DatagramSocket</tt> that this candidate uses when sending
     * and receiving STUN packets, while harvesting STUN candidates or
     * performing connectivity checks.
     */
    public IceSocketWrapper getStunSocket(TransportAddress serverAddress)
    {
        IceSocketWrapper hostSocket = getCandidateIceSocketWrapper();

        if (hostSocket != null
              && hostSocket.getTCPSocket() != null)
        {
            Socket tcpSocket = hostSocket.getTCPSocket();
            Socket tcpStunSocket = null;

            if (tcpSocket instanceof MultiplexingSocket)
            {
                DatagramPacketFilter stunDatagramPacketFilter
                    = createStunDatagramPacketFilter(serverAddress);
                Throwable exception = null;

                try
                {
                    tcpStunSocket
                        = ((MultiplexingSocket) tcpSocket)
                            .getSocket(stunDatagramPacketFilter);
                }
                catch (SocketException sex) //don't u just luv da name? ;)
                {
                    logger.error("Failed to acquire Socket"
                                   + " specific to STUN communication.",
                               sex);
                    exception = sex;
                }
                if (tcpStunSocket == null)
                {
                    throw
                        new IllegalStateException(
                                "Failed to acquire Socket"
                                    + " specific to STUN communication",
                                exception);
                }
            }
            else
            {
                throw
                    new IllegalStateException(
                            "The socket of "
                                + getClass().getSimpleName()
                                + " must be a MultiplexingSocket " +
                                        "instance");
            }

            IceTcpSocketWrapper stunSocket = null;
            try
            {
                stunSocket = new IceTcpSocketWrapper(tcpStunSocket);
            }
            catch(IOException e)
            {
                logger.info("Failed to create IceTcpSocketWrapper " + e);
            }

            return stunSocket;
        }
        else if (hostSocket != null
                   && hostSocket.getUDPSocket() != null)
        {
            DatagramSocket udpSocket = hostSocket.getUDPSocket();
            DatagramSocket udpStunSocket = null;

            if (udpSocket instanceof MultiplexingDatagramSocket)
            {
                DatagramPacketFilter stunDatagramPacketFilter
                    = createStunDatagramPacketFilter(serverAddress);
                Throwable exception = null;

                try
                {
                    udpStunSocket
                        = ((MultiplexingDatagramSocket) udpSocket)
                            .getSocket(stunDatagramPacketFilter);
                }
                catch (SocketException sex) //don't u just luv da name? ;)
                {
                    logger.error("Failed to acquire DatagramSocket"
                                   + " specific to STUN communication.",
                               sex);
                    exception = sex;
                }
                if (udpStunSocket == null)
                {
                    throw
                        new IllegalStateException(
                                "Failed to acquire DatagramSocket"
                                    + " specific to STUN communication",
                                exception);
                }
            }
            else
            {
                throw
                    new IllegalStateException(
                            "The socket of "
                                + getClass().getSimpleName()
                                + " must be a MultiplexingDatagramSocket " +
                                        "instance");
            }
            return new IceUdpSocketWrapper(udpStunSocket);
        }

        return null;
    }

    /**
     * Gets the <tt>StunStack</tt> associated with this <tt>Candidate</tt>.
     *
     * @return the <tt>StunStack</tt> associated with this <tt>Candidate</tt>
     */
    public StunStack getStunStack()
    {
        return
            getParentComponent()
                .getParentStream()
                    .getParentAgent()
                        .getStunStack();
    }

    /**
     * Creates a new <tt>StunDatagramPacketFilter</tt> which is to capture STUN
     * messages and make them available to the <tt>DatagramSocket</tt> returned
     * by {@link #getStunSocket(TransportAddress)}.
     *
     * @param serverAddress the address of the source we'd like to receive
     * packets from or <tt>null</tt> if we'd like to intercept all STUN packets
     * @return the <tt>StunDatagramPacketFilter</tt> which is to capture STUN
     * messages and make them available to the <tt>DatagramSocket</tt> returned
     * by {@link #getStunSocket(TransportAddress)}
     */
    protected StunDatagramPacketFilter createStunDatagramPacketFilter(
            TransportAddress serverAddress)
    {
        return new StunDatagramPacketFilter(serverAddress);
    }

    /**
     * Frees resources allocated by this candidate such as its
     * <tt>DatagramSocket</tt>, for example. The <tt>socket</tt> of this
     * <tt>LocalCandidate</tt> is closed only if it is not the <tt>socket</tt>
     * of the <tt>base</tt> of this <tt>LocalCandidate</tt>.
     */
    protected void free()
    {
        // Close the socket associated with this LocalCandidate.
        IceSocketWrapper socket = getCandidateIceSocketWrapper();

        if (socket != null)
        {
            LocalCandidate base = getBase();

            if ((base == null)
                    || (base == this)
                    || (base.getCandidateIceSocketWrapper() != socket))
            {
                //remove our socket from the stack.
                getStunStack().removeSocket(getTransportAddress());

                /*
                 * Allow this LocalCandidate implementation to not create a
                 * socket if it still hasn't created one.
                 */
                socket.close();
            }
        }
    }

    /**
     * Determines whether this <tt>Candidate</tt> is the default one for its
     * parent component.
     *
     * @return <tt>true</tt> if this <tt>Candidate</tt> is the default for its
     * parent component and <tt>false</tt> if it isn't or if it has no parent
     * Component yet.
     */
    @Override
    public boolean isDefault()
    {
        Component parentCmp = getParentComponent();

        return (parentCmp != null) && equals(parentCmp.getDefaultCandidate());
    }

    /**
     * Set the local ufrag.
     *
     * @param ufrag local ufrag
     */
    public void setUfrag(String ufrag)
    {
        this.ufrag = ufrag;
    }

    /**
     * Get the local ufrag.
     *
     * @return local ufrag
     */
    @Override
    public String getUfrag()
    {
        return ufrag;
    }

    /**
     * Returns the type of method used to discover this candidate ("host",
     * "upnp", "stun peer reflexive", "stun server reflexive", "turn relayed",
     * "google turn relayed", "google tcp turn relayed" or "jingle node").
     *
     * @return The type of method used to discover this candidate ("host",
     * "upnp", "stun peer reflexive", "stun server reflexive", "turn relayed",
     * "google turn relayed", "google tcp turn relayed" or "jingle node").
     */
    public CandidateExtendedType getExtendedType()
    {
        return this.extendedType;
    }

    /**
     * Sets the type of method used to discover this candidate ("host", "upnp",
     * "stun peer reflexive", "stun server reflexive", "turn relayed", "google
     * turn relayed", "google tcp turn relayed" or "jingle node").
     *
     * @param extendedType The type of method used to discover this candidate
     * ("host", "upnp", "stun peer reflexive", "stun server reflexive", "turn
     * relayed", "google turn relayed", "google tcp turn relayed" or "jingle
     * node").
     */
    public void setExtendedType(CandidateExtendedType extendedType)
    {
        this.extendedType = extendedType;
    }

    /**
     * Find the candidate corresponding to the address given in parameter.
     *
     * @param relatedAddress The related address:
     * - null for a host candidate,
     * - the base address (host candidate) for a reflexive candidate,
     * - the mapped address (the mapped address of the TURN allocate response)
     * for a relayed candidate.
     * - null for a peer reflexive candidate : there is no way to know the
     * related address.
     *
     * @return The related candidate corresponding to the address given in
     * parameter:
     * - null for a host candidate,
     * - the base address (host candidate) for a reflexive candidate,
     * - the mapped address (the mapped address of the TURN allocate response)
     * for a relayed candidate.
     * - null for a peer reflexive candidate : there is no way to know the
     * related address.
     */
    @Override
    protected LocalCandidate findRelatedCandidate(
            TransportAddress relatedAddress)
    {
        return getParentComponent().findLocalCandidate(relatedAddress);
    }

    /**
     * Gets the value of the 'ssl' flag.
     * @return the value of the 'ssl' flag.
     */
    public boolean isSSL()
    {
        return isSSL;
    }

    /**
     * Sets the value of the 'ssl' flag.
     * @param isSSL the value to set.
     */
    public void setSSL(boolean isSSL)
    {
        this.isSSL = isSSL;
    }
}
