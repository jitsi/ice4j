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

import org.ice4j.*;
import org.ice4j.ice.harvest.*;
import org.ice4j.socket.*;

/**
 * <tt>ServerReflexiveCandidate</tt>s are candidates whose IP address and port
 * are a binding allocated by a NAT for an agent when it sent a packet through
 * the NAT to a server. <tt>ServerReflexiveCandidate</tt>s can be learned by
 * STUN servers using the Binding Request, or TURN servers, which provides both
 * a Relayed and Server Reflexive candidate.
 * <p>
 * This class does not contain a socket itself and in order to send bytes over
 * the network, one has to retrieve the socket of its base.
 * </p>
 *
 * @author Emil Ivov
 */
public class ServerReflexiveCandidate
    extends LocalCandidate
{
    /**
     * The STUN candidate harvest.
     */
    private final StunCandidateHarvest stunHarvest;

    /**
     * Creates a <tt>ServerReflexiveCandidate</tt> for the specified transport
     * address, and base.
     *
     * @param address the {@link TransportAddress} that this <tt>Candidate</tt>
     * is representing.
     * @param base the {@link HostCandidate} that this server reflexive
     * candidate was obtained through.
     * @param stunSrvrAddr the {@link TransportAddress} of the stun server that
     * reflected this candidate.
     * @param extendedType The type of method used to discover this candidate
     * ("host", "upnp", "stun peer reflexive", "stun server reflexive", "turn
     * relayed", "google turn relayed", "google tcp turn relayed" or "jingle
     * node").
     */
    public ServerReflexiveCandidate(TransportAddress address,
                                    HostCandidate    base,
                                    TransportAddress stunSrvrAddr,
                                    CandidateExtendedType extendedType)
    {
        this(
                address,
                base,
                stunSrvrAddr,
                null,
                extendedType);
    }

    /**
     * Creates a <tt>ServerReflexiveCandidate</tt> for the specified transport
     * address, and base.
     *
     * @param address the {@link TransportAddress} that this <tt>Candidate</tt>
     * is representing.
     * @param base the {@link HostCandidate} that this server reflexive
     * candidate was obtained through.
     * @param stunSrvrAddr the {@link TransportAddress} of the stun server that
     * reflected this candidate.
     * @param stunHarvest the {@link StunCandidateHarvest}
     * @param extendedType The type of method used to discover this candidate
     * ("host", "upnp", "stun peer reflexive", "stun server reflexive", "turn
     * relayed", "google turn relayed", "google tcp turn relayed" or "jingle
     * node").
     */
    public ServerReflexiveCandidate(TransportAddress address,
                                    HostCandidate    base,
                                    TransportAddress stunSrvrAddr,
                                    StunCandidateHarvest stunHarvest,
                                    CandidateExtendedType extendedType)
    {
        super(address,
              base.getParentComponent(),
              CandidateType.SERVER_REFLEXIVE_CANDIDATE,
              extendedType,
              base);

        setBase(base);
        setStunServerAddress(stunSrvrAddr);
        this.stunHarvest = stunHarvest;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public IceSocketWrapper getCandidateIceSocketWrapper()
    {
        return getBase().getCandidateIceSocketWrapper();
    }

    /**
     * Frees resources allocated by this candidate such as its
     * <tt>DatagramSocket</tt>, for example. The <tt>socket</tt> of this
     * <tt>LocalCandidate</tt> is closed only if it is not the <tt>socket</tt>
     * of the <tt>base</tt> of this <tt>LocalCandidate</tt>.
     */
    @Override
    public void free()
    {
        super.free();

        if(stunHarvest != null)
            stunHarvest.close();
    }
}
