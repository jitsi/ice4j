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

import java.util.logging.*;

/**
 * A MappingCandidateHarvester which use a list of pre-configured stun servers
 * to discover its public ip address.
 *
 * @author Damian Minkov
 */
public class StunMappingCandidateHarvester
    extends MappingCandidateHarvester
{
    /**
     * The <tt>Logger</tt> used by the <tt>StunMappingCandidateHarvester</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(StunMappingCandidateHarvester.class.getName());

    /**
     * The addresses that we will use as a mask
     */
    private static TransportAddress mask;

    /**
     * The addresses that we will be masking
     */
    private static TransportAddress face;

    /**
     * Whether we have already checked and found the mapping addresses.
     */
    private static boolean addressChecked = false;

    /**
     * The list of servers we will use to discover our public address.
     */
    private static String[] stunServers;

    /**
     * Creates a mapping harvester with the specified <tt>mask</tt>
     * @param servers list of stun servers in the form address:port
     */
    public StunMappingCandidateHarvester(String[] servers)
    {
        super(null, null);

        StunMappingCandidateHarvester.stunServers = servers;

        // we have the list of addresses lets, try discovering
        obtainAddresses();
    }

    /**
     * Creates a mapping harvester with the specified <tt>mask</tt>
     */
    public StunMappingCandidateHarvester()
    {
        super(null, null);
    }

    /**
     * Uses the pre-configured list of stun servers to discover our public
     * address. Uses the first successful one and ignore the rest.
     * Learn the private (face) and public (mask) addresses of this instance.
     */
    private static synchronized void obtainAddresses()
    {
        if (addressChecked)
            return;
        addressChecked = true;

        try
        {
            for (String server : stunServers)
            {
                String[] addressAndPort = server.split(":");

                StunCandidateHarvester stunHarv = new StunCandidateHarvester(
                    new TransportAddress(
                            addressAndPort[0],
                            Integer.parseInt(addressAndPort[1]),
                            Transport.UDP));

                Agent agent = new Agent();
                agent.setTrickling(false);
                agent.addCandidateHarvester(stunHarv);

                IceMediaStream stream = agent.createMediaStream("audio");
                // local ports does not matter, just to be something
                // out of the default used range
                agent.createComponent(
                    stream, Transport.UDP, 32020, 32020, 32020 + 100);

                IceMediaStream iceMediaStream = agent.getStreams().get(0);
                TransportAddress addr = iceMediaStream
                    .getComponent(Component.RTP).getDefaultCandidate()
                    .getTransportAddress();
                mask = addr;

                Candidate<?> candidate =
                    iceMediaStream.getComponents().get(0).getDefaultCandidate();
                face = candidate.getHostAddress();

                agent.free();

                if (mask != null && face != null)
                    break;
            }

            logger.info("Detected through stun local IP: " + face);
            logger.info("Detected through stun public IP: " + mask);

        }
        catch (Exception exc)
        {
            //whatever happens, we just log and fail
            logger.log(Level.INFO, "We failed to obtain addresses "
                + "for the following reason: ", exc);
        }
    }

    /**
     * Returns the public (mask) address, or null.
     * @return the public (mask) address, or null.
     */
    public TransportAddress getMask()
    {
        if (mask == null)
        {
            obtainAddresses();
        }
        return mask;
    }

    /**
     * Returns the local (face) address, or null.
     * @return the local (face) address, or null.
     */
    public TransportAddress getFace()
    {
        if (face == null)
        {
            obtainAddresses();
        }
        return face;
    }
}
