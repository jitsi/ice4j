/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice.harvest;

import java.net.*;
import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.ice.*;
import org.ice4j.socket.*;

import org.bitlet.weupnp.*;

/**
 * Implements a <tt>CandidateHarvester</tt> which gathers <tt>Candidate</tt>s
 * for a specified {@link Component} using UPnP.
 *
 * @author Sebastien Vincent
 */
public class UPNPHarvester
    implements CandidateHarvester
{
    /**
     * The logger.
     */
    private static final Logger logger =
        Logger.getLogger(UPNPHarvester.class.getName());

    /**
     * Maximum port to try to allocate.
     */
    private static final int MAX_RETRIES = 5;

    /**
     * The UPnP discover.
     */
    private GatewayDiscover discover = new GatewayDiscover();

    /**
     * Constructor.
     */
    public UPNPHarvester()
    {
        try
        {
            discover.discover();
        }
        catch(Exception e)
        {
            logger.info("UPnP discovery failed: " + e);
        }
    }

    /**
     * Gathers UPnP candidates for all host <tt>Candidate</tt>s that are
     * already present in the specified <tt>component</tt>. This method relies
     * on the specified <tt>component</tt> to already contain all its host
     * candidates so that it would resolve them.
     *
     * @param component the {@link Component} that we'd like to gather candidate
     * UPnP <tt>Candidate</tt>s for
     * @return  the <tt>LocalCandidate</tt>s gathered by this
     * <tt>CandidateHarvester</tt>
     */
    public synchronized Collection<LocalCandidate> harvest(Component component)
    {
        Collection<LocalCandidate> candidates = new HashSet<LocalCandidate>();
        int retries = 0;

        try
        {
            GatewayDevice device = discover.getValidGateway();

            if(device == null)
            {
                return candidates;
            }

            InetAddress localAddress = device.getLocalAddress();
            String externalIPAddress = device.getExternalIPAddress();
            PortMappingEntry portMapping = new PortMappingEntry();

            MultiplexingDatagramSocket socket =
                new MultiplexingDatagramSocket(0, localAddress);
            int port = socket.getLocalPort();
            int externalPort = socket.getLocalPort();

            while(retries < MAX_RETRIES)
            {
                if(!device.getSpecificPortMappingEntry(port, "UDP",
                        portMapping))
                {
                    if(device.addPortMapping(
                            externalPort,
                            port,
                            localAddress.getHostAddress(),
                            "UDP",
                            "Ice4J: " + port))
                    {
                        List<LocalCandidate> cands = createUPNPCandidate(socket,
                                localAddress, externalIPAddress, externalPort,
                                component, device);

                        // we have to add the UPNPCandidate and also the base.
                        // if we don't add the base, we won't be able to add
                        // peer reflexive candidate if someone contact us on the
                        // UPNPCandidate
                        for(LocalCandidate cand : cands)
                        {
                            component.addLocalCandidate(cand);
                            candidates.add(cand);
                        }

                        break;
                    }
                    else
                    {
                        port++;
                    }
                }
                else
                {
                    port++;
                }
                retries++;
            }
        }
        catch(Throwable e)
        {
            logger.info("Exception while gathering UPnP candidates: " + e);
        }

        return candidates;
    }

    /**
     * Create a UPnP candidate.
     *
     * @param socket local socket
     * @param localAddr local host address
     * @param externalIP external IP address
     * @param port local port
     * @param cmp parent component
     * @param device the UPnP gateway device
     * @return a new <tt>UPNPCandidate</tt> instance which
     * represents the specified <tt>TransportAddress</tt>
     * @throws Exception if something goes wrong during candidate creation
     */
    public List<LocalCandidate> createUPNPCandidate(DatagramSocket socket,
            InetAddress localAddr, String externalIP, int port, Component cmp,
            GatewayDevice device)
        throws Exception
    {
        List<LocalCandidate> ret = new ArrayList<LocalCandidate>();
        TransportAddress addr = new TransportAddress(externalIP, port,
                Transport.UDP);

        HostCandidate base = new HostCandidate(socket, cmp);

        UPNPCandidate candidate = new UPNPCandidate(addr, base, cmp, device);
        DatagramSocket stunSocket = candidate.getStunSocket(null);
        candidate.getStunStack().addSocket(stunSocket);

        ret.add(candidate);
        ret.add(base);

        return ret;
    }
}
