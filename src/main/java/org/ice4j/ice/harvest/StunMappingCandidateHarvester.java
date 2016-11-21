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
import org.ice4j.socket.*;
import org.ice4j.stunclient.*;

import java.net.*;
import java.util.logging.*;

/**
 * A {@link MappingCandidateHarvester} which uses a STUN servers to discover
 * its public IP address.
 *
 * @author Damian Minkov
 * @author Boris Grozev
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
     * The list of servers we will use to discover our public address.
     */
    private TransportAddress stunServerAddress;

    /**
     * Initializes a new {@link StunMappingCandidateHarvester} instance with
     * a given local address and a STUN server address. Note that the actual
     * discovery of the public address needs to be initiated to a separate call
     * to {@link #discover()}.
     * @param localAddress The local address.
     * @param stunServerAddress The address of the STUN server.
     */
    public StunMappingCandidateHarvester(
            TransportAddress localAddress,
            TransportAddress stunServerAddress)
    {
        face = localAddress;
        this.stunServerAddress = stunServerAddress;
    }

    /**
     * Attempts to discover the the public address (mask) via the STUN server.
     * Note that this will block until we either receive a response from the
     * STUN server, or a timeout occurs.
     */
    public void discover()
    {
        try
        {
            SimpleAddressDetector sad
                = new SimpleAddressDetector(stunServerAddress);
            sad.start();

            IceSocketWrapper localSocket
                = new IceUdpSocketWrapper(new DatagramSocket(face));

            mask = sad.getMappingFor(localSocket);
            if (mask != null)
            {
                logger.info("Discovered public address " + mask
                                + " from STUN server " + stunServerAddress
                                + " using local address " + face);
            }
        }
        catch (Exception exc)
        {
            //whatever happens, we just log
            logger.log(Level.INFO, "We failed to obtain addresses "
                + "for the following reason: ", exc);
        }
    }
}
