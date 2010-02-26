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
import org.ice4j.message.*;
import org.ice4j.socket.*;

/**
 * Implements a <tt>CandidateHarvester</tt> which gathers <tt>Candidate</tt>s
 * for a specified {@link Component} using STUN as defined in RFC 5389 "Session
 * Traversal Utilities for NAT (STUN)" only.
 *
 * @author Emil Ivov
 * @author Lubomir Marinov
 */
public class StunCandidateHarvester
    extends AbstractStunCandidateHarvester
{
    /**
     * The <tt>Logger</tt> used by the <tt>StunCandidateHarvester</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(AbstractStunCandidateHarvester.class.getName());

    /**
     * The <tt>DatagramPacketFilter</tt> which accepts only STUN messages
     * defined in RFC 5389 "Session Traversal Utilities for NAT (STUN)" i.e. the
     * STUN messages of interest to <tt>StunCandidateHarvester</tt>.
     */
    private static final StunDatagramPacketFilter stunDatagramPacketFilter
        = new StunDatagramPacketFilter();

    /**
     * The list of candidates that this harvester has allocated and that it
     * needs to keep alive.
     */
    private List<ServerReflexiveCandidate> allocatedCandidates
        = new LinkedList<ServerReflexiveCandidate>();

    /**
     * Creates a new STUN harvester that will be running against the specified
     * <tt>stunServer</tt>.
     *
     * @param stunServer the address of the STUN server that we will be querying
     * for our public bindings
     */
    public StunCandidateHarvester(TransportAddress stunServer)
    {
        super(stunServer);
    }

    /**
     * Creates a new <tt>Request</tt> which is to be sent to {@link #stunServer}
     * in order to start resolving a specific <tt>HostCandidate</tt>.
     *
     * @param hostCand the <tt>HostCandidate</tt> for which a <tt>Request</tt>
     * to start resolving is to be created
     * @return a new <tt>Request</tt> which is to be sent to {@link #stunServer}
     * in order to start resolving the specified <tt>HostCandidate</tt>
     * @see AbstractStunCandidateHarvester
     * #createRequestToStartResolvingCandidate(HostCandidate)
     */
    protected Request createRequestToStartResolvingCandidate(
            HostCandidate hostCand)
    {
        return MessageFactory.createBindingRequest();
    }

    /**
     * Gets the <tt>DatagramPacketFilter</tt> which is to be associated with the
     * <tt>DatagramSocket</tt> to be used for communication with
     * {@link #stunServer} when gathering <tt>Candidate</tt>s for a specific
     * <tt>HostCandidate</tt>.
     *
     * @param hostCand the <tt>HostCandidate</tt> for which STUN
     * <tt>Candidate</tt>s are to be harvested by this <tt>CandidateHarvester</tt>
     * @return the <tt>DatagramPacketFilter</tt> which is to be associated with
     * the <tt>DatagramSocket</tt> to be used for communication with
     * {@link #stunServer} when gathering <tt>Candidate</tt>s for the specified
     * <tt>HostCandidate</tt>
     * @see AbstractStunCandidateHarvester#getStunDatagramPacketFilter(
     * HostCandidate)
     */
    protected DatagramPacketFilter getStunDatagramPacketFilter(
            HostCandidate hostCand)
    {
        return stunDatagramPacketFilter;
    }

    /**
     * reSends a binding request to our stun server through the specified
     * <tt>srflxCand</tt> candidate so that it would keep the potential NAT
     * mapping valid.
     *
     * @param srflxCand the <tt>ServerReflexiveCandidate</tt> that we'd like to
     * refresh and keep alive.
     */
    private void refreshCandidate(ServerReflexiveCandidate srflxCand)
    {
        DatagramSocket sock = srflxCand.getSocket();
        stunStack.addSocket(sock);

        try
        {
            stunStack.sendRequest( MessageFactory.createBindingRequest(),
                            stunServer, sock, this);

        }
        catch (Exception exception)
        {
            logger.log(Level.INFO, "Failed to send a refresh for a candidate",
                       exception);
        }
    }
}
