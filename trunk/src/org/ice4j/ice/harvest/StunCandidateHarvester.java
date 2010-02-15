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
import org.ice4j.attribute.*;
import org.ice4j.ice.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;

import com.sun.org.apache.bcel.internal.generic.*;

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
     * Our class logger.
     */
    private final Logger logger
        = Logger.getLogger(StunCandidateHarvester.class.getName());

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
    private final Map<TransactionID, HostCandidate> resolveMap
                            = new Hashtable<TransactionID, HostCandidate>();

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
        //first of all, make sure that the STUN server and the Candidate
        //address are of the same type and that they can communicate.
        if(!hostCand.getTransportAddress().canReach(stunServer))
            return;

        DatagramSocket sock = hostCand.getSocket();
        stunStack.addSocket(sock);

        synchronized(resolveMap)
        {
            TransactionID tran;
            try
            {
                tran = stunStack.sendRequest(
                    MessageFactory.createBindingRequest(), stunServer, sock,
                        this);

            }
            catch (Exception exception)
            {
                logger.log(Level.INFO, "Failed to send a STUN Binding Request",
                                exception);
                return;
            }

            resolveMap.put(tran, hostCand);
        }
    }

    /**
     * Blocks the current thread until all resolutions in this harverster
     * have terminated one way or another.
     */
    private void waitForResolutionEnd()
    {
        synchronized(resolveMap)
        {
            if(resolveMap.isEmpty())
                return;

            try
            {
                resolveMap.wait();
            }
            catch (InterruptedException e){}
        }
    }

    /**
     * Matches the response to one of the local candidates and creates a
     * <tt>ServerReflexiveCandidate</tt> using it as a base.
     *
     * @param response the response that we've just received from a StunServer.
     */
    public void processResponse(StunMessageEvent response)
    {
        synchronized (resolveMap)
        {
            TransactionID tranID = response.getTransactionID();

            HostCandidate localCand = resolveMap.remove(tranID);

            if ( localCand != null)
            {
                createServerReflexiveCandidate(response.getMessage(),
                                               localCand);
            }

            //if this was the last candidate, we are done with the STUN
            //resolution and need to notify the waiters.
            if(resolveMap.isEmpty())
                resolveMap.notify();

            logger.finest("received a message tranid=" + tranID);
            logger.finest("localCand=" + localCand);
        }

    }

    /**
     * Notifies the collector that no response had been received
     * after repeated retransmissions of the original request (as described
     * by rfc3489) and that the request should be considered unanswered.
     *
     * @param event the <tt>StunTimeoutEvent</tt> that contains the transaction
     * which has just expired.
     */
    public void processTimeout(StunTimeoutEvent event)
    {
        processFailure(event.getTransactionID());
    }

    /**
     * Called when one of our requests results in a
     * <tt>PortUnreachableException</tt> ... which is actually quite rare
     * because of the oddities of the BSD and Java socket implementations, which
     * is why we currently ignore this method.
     *
     * @param event the <tt>StunFailureEvent</tt>
     * <tt>PortUnreachableException</tt> which signaled that the destination of
     * the request was found to be unreachable.
     */
    public void processUnreachable(StunFailureEvent event)
    {
        processFailure(event.getTransactionID());
    }

    /**
     * Removes the corresponding local candidate from the list of candidates
     * that we are waiting on in order to complete the harvest.
     *
     * @param transactionID the ID of the transaction that has just ended.
     */
    private void processFailure(TransactionID transactionID)
    {
        synchronized (resolveMap)
        {
            Candidate localCand = resolveMap.remove(transactionID);

            //if this was the last candidate, we are done with the STUN
            //resolution and need to notify the waiters.
            if(resolveMap.isEmpty())
                resolveMap.notify();

            logger.finest("a tran expired tranid=" + transactionID);
            logger.finest("localAddr=" + localCand);
        }
    }

    /**
     * Creates a <tt>ServerReflexiveCandidate</tt> using <tt>base</tt> as its
     * and the <tt>XOR-MAPPED-ADDRESS</tt> attributes in <tt>response</tt> for
     * the actual <tt>TransportAddress</tt> of the new candidate. If the message
     * is somehow malformed and does not contain the corresponding attribute
     * this method simply has no effect.
     *
     * @param response the <tt>Message</tt> that is supposed to contain the
     * address we should use for this candidate.
     * @param base the <tt>HostCandidate</tt> that we should use as a base
     * for the new <tt>ServerReflexiveCandidate</tt>.
     */
    private void createServerReflexiveCandidate(Message       response,
                                                HostCandidate base)
    {
        Attribute attribute
            = response.getAttribute(Attribute.XOR_MAPPED_ADDRESS);

        if(attribute == null
           || !(attribute instanceof XorMappedAddressAttribute))
            return;

        TransportAddress addr = ((XorMappedAddressAttribute)attribute)
            .applyXor(Message.MAGIC_COOKIE);

        ServerReflexiveCandidate srvrRflxCand
            = new ServerReflexiveCandidate(addr, base, stunServer);

        base.getParentComponent().addLocalCandidate(srvrRflxCand);
    }
}
