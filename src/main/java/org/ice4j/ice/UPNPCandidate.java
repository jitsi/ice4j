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
import org.ice4j.socket.*;

import org.bitlet.weupnp.*;

/**
 * Represents a <tt>Candidate</tt> obtained via UPnP.
 *
 * @author Sebastien Vincent
 */
public class UPNPCandidate
    extends LocalCandidate
{
    /**
     * The UPnP gateway device.
     */
    private GatewayDevice device = null;

    /**
     * Creates a <tt>UPNPCandidate</tt> for the specified transport, address,
     * and base.
     *
     * @param transportAddress  the transport address that this candidate is
     * encapsulating.
     * @param base the base candidate
     * @param parentComponent the <tt>Component</tt> that this candidate
     * belongs to.
     * @param device the UPnP gateway device
     */
    public UPNPCandidate(TransportAddress transportAddress,
            LocalCandidate base, Component parentComponent,
            GatewayDevice device)
    {
        super(  transportAddress,
                parentComponent,
                CandidateType.SERVER_REFLEXIVE_CANDIDATE,
                CandidateExtendedType.UPNP_CANDIDATE,
                base);

        this.setBase(base);
        this.device = device;
        setStunServerAddress(transportAddress);
    }

    /**
     * Frees resources allocated by this candidate such as its
     * <tt>DatagramSocket</tt>, for example. The <tt>socket</tt> of this
     * <tt>LocalCandidate</tt> is closed only if it is not the <tt>socket</tt>
     * of the <tt>base</tt> of this <tt>LocalCandidate</tt>.
     */
    @Override
    protected void free()
    {
        // delete the port mapping
        try
        {
            device.deletePortMapping(getTransportAddress().getPort(), "UDP");
        }
        catch(Exception e)
        {
        }

        IceSocketWrapper socket = getCandidateIceSocketWrapper();
        if(socket != null)
        {
            socket.close();
        }

        device = null;
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
     * {@inheritDoc}
     */
    @Override
    protected IceSocketWrapper getIceSocketWrapper()
    {
        return getBase().getIceSocketWrapper();
    }
}
