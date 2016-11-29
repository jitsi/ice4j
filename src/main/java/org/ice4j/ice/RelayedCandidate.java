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

import java.lang.reflect.*;
import java.net.*;

import org.ice4j.*;
import org.ice4j.ice.harvest.*;
import org.ice4j.socket.*;

/**
 * Represents a <tt>Candidate</tt> obtained by sending a TURN Allocate request
 * from a <tt>HostCandidate</tt> to a TURN server.  The relayed candidate is
 * resident on the TURN server, and the TURN server relays packets back towards
 * the agent.
 *
 * @author Lubomir Marinov
 */
public class RelayedCandidate
    extends LocalCandidate
{

    /**
     * The <tt>RelayedCandidateDatagramSocket</tt> of this
     * <tt>RelayedCandidate</tt>.
     */
    private RelayedCandidateDatagramSocket relayedCandidateDatagramSocket;

    /**
     * The application-purposed <tt>DatagramSocket</tt> associated with this
     * <tt>Candidate</tt>.
     */
    private IceSocketWrapper socket;

    /**
     * The <tt>TurnCandidateHarvest</tt> which has harvested this
     * <tt>RelayedCandidate</tt>.
     */
    private final TurnCandidateHarvest turnCandidateHarvest;

    /**
     * Initializes a new <tt>RelayedCandidate</tt> which is to represent a
     * specific <tt>TransportAddress</tt> harvested through a specific
     * <tt>HostCandidate</tt> and a TURN server with a specific
     * <tt>TransportAddress</tt>.
     *
     * @param transportAddress the <tt>TransportAddress</tt> to be represented
     * by the new instance
     * @param turnCandidateHarvest the <tt>TurnCandidateHarvest</tt> which has
     * harvested the new instance
     * @param mappedAddress the mapped <tt>TransportAddress</tt> reported by the
     * TURN server with the delivery of the replayed <tt>transportAddress</tt>
     * to be represented by the new instance
     */
    public RelayedCandidate(
            TransportAddress transportAddress,
            TurnCandidateHarvest turnCandidateHarvest,
            TransportAddress mappedAddress)
    {
        super(
            transportAddress,
            turnCandidateHarvest.hostCandidate.getParentComponent(),
            CandidateType.RELAYED_CANDIDATE,
            CandidateExtendedType.TURN_RELAYED_CANDIDATE,
            turnCandidateHarvest.hostCandidate.getParentComponent()
                .findLocalCandidate(mappedAddress));

        this.turnCandidateHarvest = turnCandidateHarvest;

        // RFC 5245: The base of a relayed candidate is that candidate itself.
        setBase(this);
        setRelayServerAddress(turnCandidateHarvest.harvester.stunServer);
        setMappedAddress(mappedAddress);
    }

    /**
     * Gets the <tt>RelayedCandidateDatagramSocket</tt> of this
     * <tt>RelayedCandidate</tt>.
     * <p>
     * <b>Note</b>: The method is part of the internal API of
     * <tt>RelayedCandidate</tt> and <tt>TurnCandidateHarvest</tt> and is not
     * intended for public use.
     * </p>
     *
     * @return the <tt>RelayedCandidateDatagramSocket</tt> of this
     * <tt>RelayedCandidate</tt>
     */
    private synchronized RelayedCandidateDatagramSocket
        getRelayedCandidateDatagramSocket()
    {
        if (relayedCandidateDatagramSocket == null)
        {
            try
            {
                relayedCandidateDatagramSocket
                    = new RelayedCandidateDatagramSocket(
                            this,
                            turnCandidateHarvest);
            }
            catch (SocketException sex)
            {
                throw new UndeclaredThrowableException(sex);
            }
        }
        return relayedCandidateDatagramSocket;
    }

    /**
     * Gets the application-purposed <tt>DatagramSocket</tt> associated with
     * this <tt>Candidate</tt>.
     *
     * @return the <tt>DatagramSocket</tt> associated with this
     * <tt>Candidate</tt>
     */
    @Override
    public synchronized IceSocketWrapper getCandidateIceSocketWrapper()
    {
        if (socket == null)
        {
            try
            {
                socket
                    = new IceUdpSocketWrapper(new MultiplexingDatagramSocket(
                            getRelayedCandidateDatagramSocket()));
            }
            catch (SocketException sex)
            {
                throw new UndeclaredThrowableException(sex);
            }
        }
        return socket;
    }
}
