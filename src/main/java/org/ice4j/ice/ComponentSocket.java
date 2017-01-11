/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015-2016 Atlassian Pty Ltd
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

import org.ice4j.*;
import org.ice4j.socket.*;

import java.beans.*;
import java.net.*;
import java.util.*;
import org.ice4j.util.*; //Disambiguation

/**
 * Extends {@link MergingDatagramSocket} with functionality specific to
 * an ICE {@link Component}.
 */
public class ComponentSocket
    extends MergingDatagramSocket
    implements PropertyChangeListener
{
    /**
     * The {@link Logger} used by the {@link MergingDatagramSocket} class and
     * its instances for logging output.
     */
    private static final java.util.logging.Logger classLogger
        = java.util.logging.Logger.getLogger
                (MergingDatagramSocket.class.getName());

    /**
     * Controls access to {@link #authorizedAddresses}.
     */
    private final Object authorizedAddressesSyncRoot = new Object();

    /**
     * The set of remote addresses, which this socket is allowed to receive
     * from. These should be the addresses which we have confirmed (e.g. by
     * having received a STUN message with correct authentication fields).
     */
    private Set<SocketAddress> authorizedAddresses = new HashSet<>();

    /**
     * The owning {@link Component}.
     */
    private Component component;

    /**
     * Whether we have invoked {@link #initializeActive}.
     */
    private boolean initializedActive = false;

    /**
     * Used to synchronize access to {@link #initializedActive}.
     */
    private final Object initializedActiveSyncRoot = new Object();

    /**
     * The {@link Logger} used by {@link MergingDatagramSocket} instances.
     */
    private final Logger logger;

    /**
     * Initializes a new {@link MergingDatagramSocket} instance.
     * @throws SocketException
     */
    ComponentSocket(Component component, Logger levelDelegate)
        throws SocketException
    {
        super(levelDelegate);

        this.component = component;
        this.logger = new Logger(classLogger, levelDelegate);
        component.getParentStream().addPairChangeListener(this);
    }

    /**
     * {@inheritDoc}
     * </p>
     * Verifies that the source of the packet is an authorized remote address.
     */
    protected boolean accept(DatagramPacket p)
    {
        return authorizedAddresses.contains(p.getSocketAddress());
    }

    /**
     * Adds a specific address to the list of authorized remote addresses.
     * @param address the address to add.
     */
    private void addAuthorizedAddress(SocketAddress address)
    {
        synchronized (authorizedAddressesSyncRoot)
        {
            if (authorizedAddresses.contains(address))
            {
                return;
            }

            logger.info("Adding allowed address: " + address);

            Set<SocketAddress> newSet = new HashSet<>();
            newSet.addAll(authorizedAddresses);
            newSet.add(address);

            authorizedAddresses = newSet;
        }
    }

    /**
     * {@inheritDoc}
     * </p>
     * Handles property change events coming from ICE pairs.
     * @param event
     */
    @Override
    public void propertyChange(PropertyChangeEvent event)
    {
        if (!(event.getSource() instanceof CandidatePair))
        {
            return;
        }

        CandidatePair pair = (CandidatePair) event.getSource();
        if (!pair.getParentComponent().equals(component))
        {
            // Events are fired by the IceMediaStream, which might have
            // multiple components. Make sure that we only handle events for
            // our own component.
            return;
        }

        String propertyName = event.getPropertyName();
        if (IceMediaStream.PROPERTY_PAIR_STATE_CHANGED.equals(propertyName))
        {
            CandidatePairState newState
                = (CandidatePairState) event.getNewValue();

            if (CandidatePairState.SUCCEEDED.equals(newState))
            {
                addAuthorizedAddress(
                        pair.getRemoteCandidate().getTransportAddress());
            }
        }
        else if (IceMediaStream.PROPERTY_PAIR_NOMINATED.equals(propertyName))
        {
            synchronized (initializedActiveSyncRoot)
            {
                if (initializedActive)
                {
                    return;
                }

                // Find the remote address and the correct socket to be used by
                // the pair.
                LocalCandidate localCandidate = pair.getLocalCandidate();
                LocalCandidate base = localCandidate.getBase();
                if (base != null)
                    localCandidate = base;

                TransportAddress remoteAddress = null;
                RemoteCandidate remoteCandidate = pair.getRemoteCandidate();
                if (remoteCandidate != null)
                {
                    remoteAddress = remoteCandidate.getTransportAddress();
                }

                // The local candidate may have more than one associated socket.
                // Make sure we get the one for the remote address that we are
                // going to use.
                IceSocketWrapper socketWrapper
                    = localCandidate
                    .getCandidateIceSocketWrapper(remoteAddress);

                initializeActive(socketWrapper, remoteAddress);
                initializedActive = true;
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close()
    {
        try
        {
            super.close();
        }
        finally
        {
            Component component = this.component;
            if (component != null)
            {
                component.getParentStream().removePairStateChangeListener(this);
                this.component = null;
            }
        }
    }
}
