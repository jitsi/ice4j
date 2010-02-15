/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice.harvest;

import java.io.*;
import java.net.*;
import java.util.*;

import org.ice4j.*;
import org.ice4j.ice.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;

/**
 * A <tt>StunCandidateHarvester</tt> gathers STUN <tt>Candidate</tt>s for a
 * specified {@link org.ice4j.ice.Component}.
 *
 * @author Emil Ivov
 */
public class StunCandidateHarvester
    implements CandidateHarvester,
               ResponseCollector
{

    /**
     * The stack to use for STUN communication.
     */
    private final StunStack stunStack;

    /**
     * The address of the STUN server that we will be sending our requests to.
     */
    private final TransportAddress stunServer;

    /**
     * The list of candidates that we are currently resolving.
     */
    private final List<HostCandidate> resolveList
                                            = new LinkedList<HostCandidate>();

    /**
     * Creates a new STUN harvester that will be running against the specified
     * <tt>stunServer</tt>.
     *
     * @param stunServer the address of the STUN server that we will be querying
     * for our public bindings
     */
    public StunCandidateHarvester(TransportAddress stunServer)
    {
        stunStack = StunStack.getInstance();
        this.stunServer = stunServer;

        //these should be configurable.
        System.setProperty("org.ice4j.MAX_WAIT_INTERVAL", "400");
        System.setProperty("org.ice4j.MAX_RETRANSMISSIONS", "2");
    }

    /**
     * Gathers STUN candidates for all host <tt>Candidate</tt>s that are already
     * present in the specified <tt>component</tt>. This method relies on the
     * specified <tt>component</tt> to already contain all its host candidates
     * so that it would resolve them.
     *
     * @param component the {@link Component} that we'd like to gather candidate
     * STUN <tt>Candidate</tt>s for.
     */
    public void harvest(Component component)
    {
        List<Candidate> localCandidates = component.getLocalCandidates();

        for(Candidate cand : localCandidates)
        {
            if ( !(cand instanceof HostCandidate) )
                continue;

            HostCandidate hostCand = (HostCandidate)cand;

            startResolvingCandidate(hostCand);

            waitForResolutionEnd();
        }
    }

    /**
     * Sends a binding request to our stun server through the specified
     * <tt>hostCand</tt> candidate and adds it to the list of addresses still
     * waiting for resolution.
     *
     * @param hostCand the <tt>HostCandidate</tt> that we'd like to resolve.
     */
    private void startResolvingCandidate(HostCandidate hostCand)
    {
        DatagramSocket sock = hostCand.getSocket();
        stunStack.addSocket(sock);

        synchronized(resolveList)
        {
            resolveList.add(hostCand);
        }

        try
        {
            stunStack.sendRequest(MessageFactory.createBindingRequest(),
                            stunServer, sock, this);
        }
        catch (Exception e)
        {
            synchronized(resolveList)
            {
                resolveList.remove(hostCand);
            }
        }
    }

    /**
     * Blocks the current thread until all resolutions in this harverster
     * have terminated one way or another.
     */
    private void waitForResolutionEnd()
    {
        synchronized(resolveList)
        {
            if(resolveList.isEmpty())
                return;

            try
            {
                resolveList.wait();
            }
            catch (InterruptedException e){}
        }
    }

    /**
     * Try to figure out .
     *
     * @param response the response to dispatch.
     */
    public void processResponse(StunMessageEvent response)
    {
        response.getMessage().getTransactionID();
    }

    /**
     * Notify the collector that no response had been received
     * after repeated retransmissions of the original request (as described
     * by rfc3489) and that the request should be considered unanswered.
     */
    public void processTimeout()
    {

    }

    /**
     * Called when one of our requests results in a
     * <tt>PortUnreachableException</tt> ... which is actually quite rare
     * because of the oddities of the BSD and Java socket implementations, which
     * is why we currently ignore this method.
     *
     * @param exception the <tt>PortUnreachableException</tt> which signaled
     * that the destination of the request was found to be unreachable
     */
    public void processUnreachable(PortUnreachableException exception)
    {

    }
}
