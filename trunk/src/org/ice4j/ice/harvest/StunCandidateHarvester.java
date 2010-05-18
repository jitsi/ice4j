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
import org.ice4j.socket.*;
import org.ice4j.stack.*;

/**
 * Implements a <tt>CandidateHarvester</tt> which gathers <tt>Candidate</tt>s
 * for a specified {@link Component} using STUN as defined in RFC 5389 "Session
 * Traversal Utilities for NAT (STUN)" only.
 *
 * @author Emil Ivov
 * @author Lubomir Marinov
 */
public class StunCandidateHarvester
    extends AbstractResponseCollector
    implements CandidateHarvester
{
    /**
     * The <tt>Logger</tt> used by the <tt>StunCandidateHarvester</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(StunCandidateHarvester.class.getName());

    /**
     * The list of candidates that this harvester has allocated and that it
     * needs to keep alive.
     */
    private List<ServerReflexiveCandidate> allocatedCandidates
        = new LinkedList<ServerReflexiveCandidate>();

    /**
     * The list of candidates that we are currently resolving.
     */
    private final Map<TransactionID, HostCandidate> resolveMap
        = new Hashtable<TransactionID, HostCandidate>();

    /**
     * The <tt>DatagramPacketFilter</tt> which accepts only STUN messages and
     * which are part of the communication with {@link #stunServer}.
     */
    private DatagramPacketFilter stunDatagramPacketFilter;

    /**
     * The address of the STUN server that we will be sending our requests to.
     */
    protected final TransportAddress stunServer;

    /**
     * The stack to use for STUN communication.
     */
    protected final StunStack stunStack = StunStack.getInstance();

    /**
     * Creates a new STUN harvester that will be running against the specified
     * <tt>stunServer</tt>.
     *
     * @param stunServer the address of the STUN server that we will be querying
     * for our public bindings
     */
    public StunCandidateHarvester(TransportAddress stunServer)
    {
        this.stunServer = stunServer;

        //these should be configurable.
        System.setProperty(StackProperties.MAX_CTRAN_RETRANS_TIMER, "400");
        System.setProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS, "3");
    }

    /**
     * Creates a new <tt>Candidate</tt> determined by a specific STUN response
     * and with a specific <tt>HostCandidate</tt> base.
     *
     * @param responseEvent a <tt>StunMessageEvent</tt> which represents the
     * STUN response which has been received
     * @param localCand the <tt>HostCandidate</tt> for which harvesting is
     * executing, the STUN response is associated with and which is to be the
     * base of the newly created <tt>Candidate</tt>
     */
    protected void createCandidate(
            StunMessageEvent responseEvent,
            HostCandidate localCand)
    {
        createServerReflexiveCandidate(responseEvent.getMessage(), localCand);
    }

    /**
     * Creates a new <tt>Request</tt> which is to be sent to {@link #stunServer}
     * in order to start resolving a specific <tt>HostCandidate</tt>.
     *
     * @param hostCand the <tt>HostCandidate</tt> for which a <tt>Request</tt>
     * to start resolving is to be created
     * @return a new <tt>Request</tt> which is to be sent to {@link #stunServer}
     * in order to start resolving the specified <tt>HostCandidate</tt>
     */
    protected Request createRequestToStartResolvingCandidate(
            HostCandidate hostCand)
    {
        return MessageFactory.createBindingRequest();
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
    protected void createServerReflexiveCandidate(Message response,
                                                  HostCandidate base)
    {
        Attribute attribute
            = response.getAttribute(Attribute.XOR_MAPPED_ADDRESS);

        if(attribute instanceof XorMappedAddressAttribute)
        {
            TransportAddress addr
                = ((XorMappedAddressAttribute) attribute)
                    .getAddress(response.getTransactionID());
            ServerReflexiveCandidate srvrRflxCand
                = createServerReflexiveCandidate(addr, base);

            if (srvrRflxCand != null)
                base.getParentComponent().addLocalCandidate(srvrRflxCand);
        }
    }

    /**
     * Creates a new <tt>ServerReflexiveCandidate</tt> instance which is to
     * represent a specific <tt>TransportAddress</tt> harvested through a
     * specific <tt>HostCandidate</tt> and the STUN server associated with this
     * instance.
     *
     * @param transportAddress the <tt>TransportAddress</tt> to be represented
     * by the new <tt>ServerReflexiveCandidate</tt> instance
     * @param base the <tt>HostCandidate</tt> through which the specified
     * <tt>TransportAddress</tt> has been harvested
     * @return a new <tt>ServerReflexiveCandidate</tt> instance which represents
     * the specified <tt>TransportAddress</tt> harvested through the specified
     * <tt>HostCandidate</tt> and the STUN server associated with this instance
     */
    protected ServerReflexiveCandidate createServerReflexiveCandidate(
            TransportAddress transportAddress,
            HostCandidate base)
    {
        return new ServerReflexiveCandidate(transportAddress, base, stunServer);
    }

    /**
     * Creates the <tt>DatagramPacketFilter</tt> which is to be associated with
     * the <tt>DatagramSocket</tt> to be used for communication with
     * {@link #stunServer} when gathering <tt>Candidate</tt>s for a specific
     * <tt>HostCandidate</tt>.
     *
     * @return the <tt>DatagramPacketFilter</tt> which is to be associated with
     * the <tt>DatagramSocket</tt> to be used for communication with
     * {@link #stunServer} when gathering <tt>Candidate</tt>s for a specific
     * <tt>HostCandidate</tt>
     */
    protected DatagramPacketFilter createStunDatagramPacketFilter()
    {
        return new StunDatagramPacketFilter(stunServer);
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
     */
    protected DatagramPacketFilter getStunDatagramPacketFilter(
            HostCandidate hostCand)
    {
        if (stunDatagramPacketFilter == null)
            stunDatagramPacketFilter = createStunDatagramPacketFilter();
        return stunDatagramPacketFilter;
    }

    /**
     * Gets the <tt>DatagramSocket</tt> to be used by this
     * <tt>CandidateHarvester</tt> for STUN communication for the purposes of
     * harvesting STUN <tt>Candidate</tt>s for a specific
     * <tt>HostCandidate</tt>.
     *
     * @param hostCand the <tt>HostCandidate</tt> for which STUN
     * <tt>Candidate</tt>s are to be harvested by this
     * <tt>CandidateHarvester</tt>
     * @return the <tt>DatagramSocket</tt> to be used by this
     * <tt>CandidateHarvester</tt> for STUN communication for the purposes of
     * harvesting STUN <tt>Candidate</tt>s for the specified
     * <tt>HostCandidate</tt>
     */
    private DatagramSocket getStunSocket(HostCandidate hostCand)
    {
        DatagramSocket hostSocket = hostCand.getSocket();
        DatagramSocket stunSocket = null;
        Throwable exception = null;

        if (hostSocket instanceof MultiplexingDatagramSocket)
            try
            {
                stunSocket
                    = ((MultiplexingDatagramSocket) hostSocket)
                        .getSocket(getStunDatagramPacketFilter(hostCand));
            }
            catch (SocketException sex)
            {
                logger.log(
                        Level.SEVERE,
                        "Failed to acquire DatagramSocket"
                            + " specific to STUN communication.",
                        sex);
                exception = sex;
            }
        if (stunSocket == null)
            throw new IllegalArgumentException("hostCand", exception);
        else
            return stunSocket;
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
        for (Candidate cand : component.getLocalCandidates())
            if (cand instanceof HostCandidate)
            {
                HostCandidate hostCand = (HostCandidate) cand;

                startResolvingCandidate(hostCand);
            }

        waitForResolutionEnd();
    }

    /**
     * Notifies this <tt>ResponseCollector</tt> that a transaction described by
     * the specified <tt>BaseStunMessageEvent</tt> has failed. The possible
     * reasons for the failure include timeouts, unreachable destination, etc.
     *
     * @param event the <tt>BaseStunMessageEvent</tt> which describes the failed
     * transaction and the runtime type of which specifies the failure reason
     * @see AbstractResponseCollector#processFailure(BaseStunMessageEvent)
     */
    protected void processFailure(BaseStunMessageEvent event)
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
     * Matches the response to one of the local candidates and creates a
     * <tt>ServerReflexiveCandidate</tt> using it as a base.
     *
     * @param response the response that we've just received from a StunServer.
     */
    public void processResponse(StunResponseEvent response)
    {
        synchronized (resolveMap)
        {
            TransactionID tranID = response.getTransactionID();
            HostCandidate localCand = resolveMap.remove(tranID);

            if (localCand != null)
                createCandidate(response, localCand);

            //if this was the last candidate, we are done with the STUN
            //resolution and need to notify the waiters.
            if (resolveMap.isEmpty())
                resolveMap.notify();

            logger.finest("received a message tranid=" + tranID);
            logger.finest("localCand=" + localCand);
        }
    }

    /**
     * Resends a binding request to our stun server through the specified
     * <tt>srflxCand</tt> candidate so that it would keep the potential NAT
     * mapping valid.
     *
     * @param srflxCand the <tt>ServerReflexiveCandidate</tt> that we'd like to
     * refresh and keep alive.
     */
    private void refreshCandidate(ServerReflexiveCandidate srflxCand)
    {
        try
        {
            stunStack.sendRequest( MessageFactory.createBindingRequest(),
                            stunServer,
                            srflxCand.getBase().getTransportAddress(),
                            this);

        }
        catch (Exception exception)
        {
            logger.log(Level.INFO, "Failed to send a refresh for a candidate",
                       exception);
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
        if (!hostCand.getTransportAddress().canReach(stunServer))
            return;

        synchronized(resolveMap)
        {
            Request request = createRequestToStartResolvingCandidate(hostCand);
            TransactionID tran;

            try
            {
                tran = stunStack.sendRequest(request, stunServer,
                                hostCand.getTransportAddress(), this);
            }
            catch (Exception exception)
            {
                logger.log(
                        Level.INFO,
                        "Failed to send "
                            + request
                            + " through " + hostCand.getTransportAddress()
                            + " to " + stunServer,
                        exception);
                return;
            }

            resolveMap.put(tran, hostCand);
        }
    }

    /**
     * Blocks the current thread until all resolutions in this harvester
     * have terminated one way or another.
     */
    private void waitForResolutionEnd()
    {
        synchronized(resolveMap)
        {
            boolean interrupted = false;

            // Handle spurious wakeups.
            while (!resolveMap.isEmpty())
                try
                {
                    resolveMap.wait();
                }
                catch (InterruptedException iex)
                {
                    interrupted = true;
                }
            // Restore the interrupted status.
            if (interrupted)
                Thread.currentThread().interrupt();
        }
    }
}
