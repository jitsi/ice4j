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

import java.util.*;
import java.util.logging.*;

/**
 * Uses a list of addresses as a predefined static mask in order to generate
 * {@link TransportAddress}es. This harvester is meant for use in situations
 * where servers are deployed behind a NAT or in a DMZ with static port mapping.
 * <p>
 * Every time the {@link #harvest(Component)} method is called, the mapping
 * harvester will return a list of candidates that provide masked alternatives
 * for every host candidate in the component. Kind of like a STUN server.
 * <p>
 * Example: You run this on a server with address 192.168.0.1, that is behind
 * a NAT with public IP: 93.184.216.119. You allocate a host candidate
 * 192.168.0.1/UDP/5000. This harvester is going to then generate an address
 * 93.184.216.119/UDP/5000
 * <p>
 * This harvester is instant and does not introduce any harvesting latency.
 *
 * @author Emil Ivov
 */
public class MappingCandidateHarvester
    extends AbstractCandidateHarvester
{
    /**
     * The <tt>Logger</tt> used by the <tt>StunCandidateHarvester</tt> class and
     * its instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(StunCandidateHarvester.class.getName());

    /**
     * The addresses that we will use as a mask
     */
    protected TransportAddress mask;

    /**
     * The addresses that we will be masking
     */
    protected TransportAddress face;

    /**
     * Creates a mapping harvester with the specified <tt>mask</tt>
     *
     * @param mask the <tt>TransportAddress</tt>es that would be used as a mask.
     * @param face the <tt>TransportAddress</tt>es that we will be masking.
     */
    public MappingCandidateHarvester(TransportAddress mask,
                                     TransportAddress face)
    {
        this.mask = Objects.requireNonNull(mask);
        this.face = Objects.requireNonNull(face);
    }

    /**
     * Initializes a {@link MappingCandidateHarvester} instance without
     * specified addresses (only useful in subclasses which override
     * {@link #getMask()} and {@link #getFace()}).
     */
    protected MappingCandidateHarvester()
    {
    }

    /**
     * Maps all candidates to this harvester's mask and adds them to
     * <tt>component</tt>.
     *
     * @param component the {@link Component} that we'd like to map candidates
     * to.
     * @return  the <tt>LocalCandidate</tt>s gathered by this
     * <tt>CandidateHarvester</tt> or <tt>null</tt> if no mask is specified.
     */
    @Override
    public Collection<LocalCandidate> harvest(Component component)
    {
        TransportAddress mask = getMask();
        TransportAddress face = getFace();
        if (face == null || mask == null)
        {
            logger.warning("Harvester not configured: face=" + face
                           + ", mask=" + mask);
            return null;
        }

         // Report the LocalCandidates gathered by this CandidateHarvester so
         // that the harvest is sure to be considered successful.
        Collection<LocalCandidate> candidates = new HashSet<>();

        for (Candidate<?> cand : component.getLocalCandidates())
        {
            if (!(cand instanceof HostCandidate)
                || !cand.getTransportAddress().getHostAddress()
                            .equals(face.getHostAddress())
                || cand.getTransport() != face.getTransport())
            {
                continue;
            }

            HostCandidate hostCandidate = (HostCandidate) cand;
            TransportAddress mappedAddress = new TransportAddress(
                mask.getHostAddress(),
                hostCandidate.getHostAddress().getPort(),
                hostCandidate.getHostAddress().getTransport());

            ServerReflexiveCandidate mappedCandidate
                = new ServerReflexiveCandidate(
                    mappedAddress,
                    hostCandidate,
                    hostCandidate.getStunServerAddress(),
                    CandidateExtendedType.STATICALLY_MAPPED_CANDIDATE);
            if (hostCandidate.isSSL())
                mappedCandidate.setSSL(true);

            //try to add the candidate to the component and then
            //only add it to the harvest not redundant
            if( !candidates.contains(mappedCandidate)
                && component.addLocalCandidate(mappedCandidate))
            {
                candidates.add(mappedCandidate);
            }
        }

        return candidates;
    }

    /**
     * Returns the public (mask) address, or null.
     * @return the public (mask) address, or null.
     */
    public TransportAddress getMask()
    {
        return mask;
    }

    /**
     * Returns the local (face) address, or null.
     * @return the local (face) address, or null.
     */
    public TransportAddress getFace()
    {
        return face;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        TransportAddress face = getFace();
        TransportAddress mask = getMask();
        return
            this.getClass().getName()
                    + ", face=" + (face == null ? "null" : face.getAddress())
                    + ", mask=" + (mask == null ? "null" : mask.getAddress());
    }
}
