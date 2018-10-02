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
package org.ice4j.ice.harvest;

import org.ice4j.*;
import org.ice4j.ice.*;
import org.ice4j.socket.*;
import org.ice4j.stack.*;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

/**
 * A harvester implementation which binds to a single <tt>DatagramSocket</tt>
 * and provides local candidates of type "host". It runs a thread
 * ({@link #thread}) which perpetually reads from the socket.
 *
 * When {@link #harvest(org.ice4j.ice.Component)} is called, this harvester
 * creates and adds to the component a
 * {@link org.ice4j.ice.harvest.SinglePortUdpHarvester.MyCandidate} instance,
 * and associates the component's local username fragment (ufrag) with this
 * candidate.
 *
 * When a STUN Binding Request with a given ufrag is received, if the ufrag
 * matches one of the registered candidates, then a new socket is created, which
 * is to receive further packets from the remote address, and the socket is
 * added to the candidate.
 *
 * @author Boris Grozev
 */
public class SinglePortUdpHarvester
        extends AbstractUdpListener
        implements CandidateHarvester
{
    /**
     * Our class logger.
     */
    private static final Logger logger
            = Logger.getLogger(SinglePortUdpHarvester.class.getName());

    /**
     * Creates a new <tt>SinglePortUdpHarvester</tt> instance for each allowed
     * IP address found on each allowed network interface, with the given port.
     *
     * @param port the UDP port number to use.
     * @return the list of created <tt>SinglePortUdpHarvester</tt>s.
     */
    public static List<SinglePortUdpHarvester> createHarvesters(int port)
    {
        List<SinglePortUdpHarvester> harvesters = new LinkedList<>();

        for (TransportAddress address
                : AbstractUdpListener.getAllowedAddresses(port))
        {
            try
            {
                harvesters.add(
                    new SinglePortUdpHarvester(address));
            }
            catch (IOException ioe)
            {
                logger.info("Failed to create SinglePortUdpHarvester for "
                                + "address " + address + ": " + ioe);
            }
        }

        return harvesters;
    }

    /**
     * The map which keeps all currently active <tt>Candidate</tt>s created by
     * this harvester. The keys are the local username fragments (ufrags) of
     * the components for which the candidates are harvested.
     */
    private final Map<String, MyCandidate> candidates
            = new ConcurrentHashMap<>();

    /**
     * Manages statistics about harvesting time.
     */
    private HarvestStatistics harvestStatistics = new HarvestStatistics();

    /**
     * Initializes a new <tt>SinglePortUdpHarvester</tt> instance which is to
     * bind on the specified local address.
     * @param localAddress the address to bind to.
     * @throws IOException if initialization fails.
     */
    public SinglePortUdpHarvester(TransportAddress localAddress)
        throws IOException
    {
        super(localAddress);
        logger.info("Initialized SinglePortUdpHarvester with address "
                            + localAddress);
    }

    /**
     * {@inheritDoc}
     */
    public HarvestStatistics getHarvestStatistics()
    {
        return harvestStatistics;
    }

    /**
     * {@inheritDoc}
     *
     * Looks for an ICE candidate registered with this harvester, which has a
     * local ufrag of {@code ufrag}, and if one is found it accepts the new
     * socket and adds it to the candidate.
     */
    protected void maybeAcceptNewSession(Buffer buf,
                                         InetSocketAddress remoteAddress,
                                         String ufrag)
    {
        MyCandidate candidate = candidates.get(ufrag);
        if (candidate == null)
        {
            // A STUN Binding Request with an unknown USERNAME. Drop it.
            return;
        }

        // This is a STUN Binding Request destined for this
        // specific Candidate/Component/Agent.
        try
        {
            // 1. Create a socket for this remote address
            // 2. Set-up de-multiplexing for future datagrams
            // with this address to this socket.
            MySocket newSocket = addSocket(remoteAddress);

            // 3. Let the candidate and its STUN stack no about the
            // new socket.
            candidate.addSocket(newSocket, remoteAddress);

            // 4. Add the original datagram to the new socket.
            newSocket.addBuffer(buf);
        }
        catch (SocketException se)
        {
            logger.info("Could not create a socket: " + se);
        }
        catch (IOException ioe)
        {
            logger.info("Failed to handle new socket: " + ioe);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<LocalCandidate> harvest(Component component)
    {
        IceMediaStream stream = component.getParentStream();
        Agent agent = stream.getParentAgent();
        String ufrag = agent.getLocalUfrag();

        if (stream.getComponentCount() != 1 || agent.getStreamCount() != 1)
        {
            /*
             * SinglePortUdpHarvester only works with streams with a
             * single component, and agents with a single stream. This is
             * because we use the local "ufrag" from an incoming STUN packet
             * to setup de-multiplexing based on remote transport address.
             */
            logger.info(
                    "More than one Component for an Agent, cannot harvest.");
            return new LinkedList<>();
        }

        MyCandidate candidate = new MyCandidate(component, ufrag);

        candidates.put(ufrag, candidate);
        component.addLocalCandidate(candidate);

        return new ArrayList<LocalCandidate>(Arrays.asList(candidate));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isHostHarvester()
    {
        return true;
    }

    /**
     * Implements a <tt>Candidate</tt> for the purposes of this
     * <tt>SinglePortUdpHarvester</tt>.
     */
    private class MyCandidate
        extends HostCandidate
    {
        /**
         * The local username fragment associated with this candidate.
         */
        private final String ufrag;

        /**
         * The flag which indicates that this <tt>MyCandidate</tt> has been
         * freed.
         */
        private boolean freed = false;

        /**
         * The collection of <tt>IceSocketWrapper</tt>s that can potentially
         * be used by the ice4j user to read/write from/to this candidate.
         * The keys are the remote addresses for each socket.
         * <p>
         * There are wrappers over <tt>MultiplexedDatagramSocket</tt>s over
         * a corresponding socket in {@link #sockets}.
         */
        private final Map<SocketAddress, IceSocketWrapper> candidateSockets
            = new HashMap<>();

        /**
         * The collection of <tt>DatagramSocket</tt>s added to this candidate.
         * The keys are the remote addresses for each socket.
         * <p>
         * These are the "raw" sockets, before any wrappers are added for
         * the STUN stack or the user of ice4j.
         */
        private final Map<SocketAddress, DatagramSocket> sockets
            = new HashMap<>();

        /**
         * Initializes a new <tt>MyCandidate</tt> instance with the given
         * <tt>Component</tt> and the given local username fragment.
         *
         * @param component the <tt>Component</tt> for which this candidate will
         * serve.
         * @param ufrag the local ICE username fragment for this candidate (and
         * its <tt>Component</tt> and <tt>Agent</tt>).
         */
        private MyCandidate(Component component, String ufrag)
        {
            super(localAddress, component);
            this.ufrag = ufrag;
        }

        /**
         * {@inheritDoc}
         * <p>
         * Closes all sockets in use by this <tt>LocalCandidate</tt>.
         */
        @Override
        public void free()
        {
            synchronized (this)
            {
                if (freed)
                    return;
                freed = true;
            }

            candidates.remove(ufrag);

            synchronized (sockets)
            {
                StunStack stunStack = getStunStack();

                for (Map.Entry<SocketAddress, DatagramSocket> e
                    : sockets.entrySet())
                {
                    DatagramSocket socket = e.getValue();

                    if (stunStack != null)
                    {
                        TransportAddress localAddress
                            = new TransportAddress(socket.getLocalAddress(),
                                                   socket.getLocalPort(),
                                                   Transport.UDP);
                        TransportAddress remoteAddress
                            = new TransportAddress(
                            (InetSocketAddress) e.getKey(),

                            Transport.UDP);

                        stunStack.removeSocket(localAddress, remoteAddress);
                    }

                    socket.close();
                }

                sockets.clear();
            }

            synchronized (candidateSockets)
            {
                for (IceSocketWrapper wrapper : candidateSockets.values())
                {
                    wrapper.close();
                }

                candidateSockets.clear();
            }

            super.free();
        }

        /**
         * Adds a new <tt>Socket</tt> to this candidate, which is associated
         * with a particular remote address.
         *
         * @param socket the socket to add.
         * @param remoteAddress the remote address for the socket.
         */
        private synchronized void addSocket(DatagramSocket socket,
                                            InetSocketAddress remoteAddress)
            throws IOException
        {
            if (freed)
            {
                throw new IOException("Candidate freed");
            }

            Component component = getParentComponent();
            if (component == null)
            {
                throw new IOException("No parent component");
            }

            IceProcessingState state
                = component.getParentStream().getParentAgent().getState();
            if (state == IceProcessingState.FAILED)
            {
                throw new IOException(
                    "Cannot add socket to an Agent in state FAILED.");
            }
            else if (state != null && state.isOver()
                && logger.isLoggable(Level.FINE))
            {
                logger.fine(
                    "Adding a socket to a completed Agent, state=" + state);
            }

            MultiplexingDatagramSocket multiplexing
                = new MultiplexingDatagramSocket(socket);

            // Socket to add to the candidate
            IceSocketWrapper candidateSocket
                = new IceUdpSocketWrapper(multiplexing);

            // STUN-only filtered socket to add to the StunStack
            IceSocketWrapper stunSocket
                = new IceUdpSocketWrapper(
                multiplexing.getSocket(new StunDatagramPacketFilter()));

            component.getParentStream().getParentAgent().getStunStack()
                .addSocket(
                    stunSocket,
                    new TransportAddress(remoteAddress, Transport.UDP));

            MergingDatagramSocket componentSocket
                = component.getComponentSocket();
            if (componentSocket != null)
            {
                componentSocket.add(multiplexing);
            }

            // XXX is this necessary?
            synchronized (candidateSockets)
            {
                IceSocketWrapper oldSocket
                    = candidateSockets.put(remoteAddress, candidateSocket);
                if (oldSocket != null)
                {
                    logger.warning("Replacing the socket for remote address "
                                       + remoteAddress);
                    oldSocket.close();
                }
            }

            // XXX is this necessary?
            synchronized (sockets)
            {
                sockets.put(remoteAddress, socket);
            }
        }
        /**
         * {@inheritDoc}
         */
        @Override
        protected IceSocketWrapper getCandidateIceSocketWrapper(
            SocketAddress remoteAddress)
        {
            return candidateSockets.get(remoteAddress);
        }

    }
}
