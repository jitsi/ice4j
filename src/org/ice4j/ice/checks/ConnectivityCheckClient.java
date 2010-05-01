/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice.checks;

import java.net.*;
import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.ice.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;

/**
 * @author Emil Ivov
 */
public class ConnectivityCheckClient
    implements ResponseCollector
{
    /**
     * The <tt>Logger</tt> used by the <tt>ConnectivityCheckClient</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger = Logger
                    .getLogger(ConnectivityCheckClient.class.getName());

    /**
     * The agent that created us.
     */
    private final Agent parentAgent;

    /**
     * The stun stack that we will use for connectivity checks.
     */
    private StunStack stunStack = StunStack.getInstance();

    /**
     * The <tt>triggeredCheckQueue</tt> is a FIFO queue containing candidate
     * pairs for which checks are to be sent at the next available opportunity.
     * A pair would get into a triggered check queue as soon as we receive
     * a check on its local candidate.
     */
    private final List<CandidatePair> triggeredCheckQueue
                                          = new LinkedList<CandidatePair>();

    /**
     * Creates a new <tt>ConnectivityCheckHandler</tt> setting
     * <tt>parentAgent</tt> as the agent that will be used for retrieving
     * information such as user fragments for example.
     *
     * @param parentAgent the <tt>Agent</tt> that is creating this instance.
     */
    public ConnectivityCheckClient(Agent parentAgent)
    {
        this.parentAgent = parentAgent;
    }

    public void startChecks(CheckList checkList)
    {
        for(CandidatePair pair : checkList)
        {
            startCheckForPair(pair);
        }
    }


    private void startCheckForPair(CandidatePair pair)
    {
        //we don't need to do a canReach() verification here as it has been
        //already verified during the gathering process.
        DatagramSocket stunSocket = ((HostCandidate)pair.getLocalCandidate())
            .getStunSocket(null);

        Request request = MessageFactory.createBindingRequest();

        //priority
        PriorityAttribute priority = AttributeFactory.createPriorityAttribute(
            pair.getLocalCandidate().computePriorityForType(
                            CandidateType.PEER_REFLEXIVE_CANDIDATE));

        request.addAttribute(priority);

        //controlling controlled
        if (parentAgent.isControlling())
        {
            request.addAttribute(AttributeFactory
                            .createIceControllingAttribute(parentAgent
                                            .getTieBreaker()));
        }
        else
        {
            request.addAttribute(AttributeFactory
                            .createIceControlledAttribute(parentAgent
                                            .getTieBreaker()));
        }

        //credentials
        String localUserName = parentAgent.generateLocalUserName();
        UsernameAttribute unameAttr = AttributeFactory.createUsernameAttribute(
                        localUserName);

        request.addAttribute(unameAttr);

        //todo: do this in the stun stack so that we could do the
        //calculation once the request is ready (we'd need the transaction id
        //for example.
        //todo: also implement SASL prepare
        MessageIntegrityAttribute msgIntegrity = AttributeFactory
            .createMessageIntegrityAttribute(localUserName);


        request.addAttribute(msgIntegrity);

        TransactionID tran;

        try
        {
            tran = stunStack.sendRequest(request,
                    pair.getRemoteCandidate().getTransportAddress(), stunSocket,
                    this);

            if(logger.isLoggable(Level.FINEST))
                logger.finest("checking pair " + pair + " with tran="
                                + tran.toString());
        }
        catch (Exception exception)
        {
            logger.log( Level.INFO,
                        "Failed to send " + request + " through "
                        + stunSocket.getLocalSocketAddress(),
                        exception);
            return;
        }
    }

    public void processResponse(StunMessageEvent response)
    {
    }

    public void processTimeout(StunTimeoutEvent event)
    {
        System.out.println("timeout event=" + event);
    }

    public void processUnreachable(StunFailureEvent event)
    {
        System.out.println("failure event=" + event);
    }

    /**
     * Adds <tt>pair</tt> to the local triggered check queue unless it's already
     * there. Additionally, the method sets the pair's state to {@link
     * CandidatePairState#WAITING}.
     *
     * @param pair the pair to schedule a triggered check for.
     */
    public void scheduleTriggeredCheck(CandidatePair pair)
    {
        synchronized(triggeredCheckQueue)
        {
            if(!triggeredCheckQueue.contains(pair))
            {
                triggeredCheckQueue.add(pair);
                pair.setState(CandidatePairState.WAITING, null);
            }
        }
    }

    /**
     * The thread that actually sends the checks in the pace defined in RFC
     * 5245.
     */
    private static class PaceMaker extends Thread
    {
        public boolean isRunning = true;
        /**
         * The {@link ConnectivityCheckClient} that created us.
         */
        private final ConnectivityCheckClient parentClient;

        /**
         * Creates a new {@link PaceMaker} for the specified
         * <tt>parentClient</tt>
         *
         * @param parentClient the {@link ConnectivityCheckClient} that who's
         * checks we are going to run.
         */
        public PaceMaker(ConnectivityCheckClient parentClient)
        {
            super("ICE PaceMaker:" + parentClient.parentAgent.getLocalUfrag());
            this.parentClient = parentClient;
        }

        /**
         * Sends connectivity checks at the pace determined by the {@link
         * Agent#calculateTa()} method and using either the trigger check queue
         * or the regular check lists.
         */
        public synchronized void run()
        {
            while(isRunning)
            {
                try
                {
                    wait(parentClient.parentAgent.calculateTa());
                }
                catch (InterruptedException e)
                {
                    logger.log(Level.FINER, "PaceMake got interrupted", e);
                }
            }
        }
    }
}
