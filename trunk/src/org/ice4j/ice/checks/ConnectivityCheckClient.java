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
    private static final StunStack stunStack = StunStack.getInstance();

    /**
     * The {@link PaceMaker}s that are currently running checks in this client.
     */
    private final List<PaceMaker> paceMakers = new LinkedList<PaceMaker>();

    /**
     * Contains the system time at the moment we last started a {@link
     * PaceMaker}.
     */
    private long lastPaceMakerStarted = 0;

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
        //RFC 5245 says: Implementations SHOULD take care to spread out these
        //timers so that they do not fire at the same time for each media
        //stream.
        //Emil: so let's make sure we spread the pace makers

        System.currentTimeMillis();

        PaceMaker paceMaker = new PaceMaker(this, checkList);
        paceMakers.add(paceMaker);

        paceMaker.start();
    }


    private TransactionID startCheckForPair(CandidatePair pair)
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

            return tran;
        }
        catch (Exception exception)
        {
            logger.log( Level.INFO,
                        "Failed to send " + request + " through "
                        + stunSocket.getLocalSocketAddress(),
                        exception);

            return null;
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
     * The thread that actually sends the checks for a particular check list
     * in the pace defined in RFC 5245.
     */
    private static class PaceMaker extends Thread
    {
        public boolean isRunning = true;
        /**
         * The {@link ConnectivityCheckClient} that created us.
         */
        private final ConnectivityCheckClient parentClient;

        /**
         * The {@link CheckList} that this <tt>PaceMaker</tt> will be running
         * checks for.
         */
        private final CheckList checkList;

        /**
         * Creates a new {@link PaceMaker} for the specified
         * <tt>parentClient</tt>
         *
         * @param parentClient the {@link ConnectivityCheckClient} that who's
         * checks we are going to run.
         * @param checkList the {@link CheckList} that we'll be sending checks
         * for
         */
        public PaceMaker(ConnectivityCheckClient parentClient,
                         CheckList               checkList)
        {
            super("ICE PaceMaker:" + parentClient.parentAgent.getLocalUfrag());
            this.parentClient = parentClient;
            this.checkList = checkList;
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
                long waitFor = parentClient.parentAgent.calculateTa()
                    * parentClient.parentAgent.getActiveCheckListCount();

                if(waitFor > 0)
                {
                    //waitFor will be 0 for the first check since we won't have
                    //any active check lists at that point yet.
                    try
                    {
                        wait(parentClient.parentAgent.calculateTa()
                             * parentClient.parentAgent
                                 .getActiveCheckListCount());
                    }
                    catch (InterruptedException e)
                    {
                        logger.log(Level.FINER, "PaceMake got interrupted", e);
                    }
                }

                checkList.setState(CheckListState.RUNNING);

                CandidatePair pairToCheck = checkList.popTriggeredCheck();
                TransactionID transactionID = null;

                if(pairToCheck != null)
                    transactionID = parentClient.startCheckForPair(pairToCheck);

                pairToCheck = checkList.getNextOrdinaryPairToCheck();

                if(pairToCheck == null)
                {
                    //we are done sending checks for this list. we'll send its
                    //final state in either the processResponse()
                    //processTimeout() or processFailure() method.
                    return;
                }

                if(transactionID == null)
                    pairToCheck.setState(CandidatePairState.FAILED, null);
                else
                    pairToCheck.setState(
                            CandidatePairState.IN_PROGRESS, transactionID);

            }
        }
    }
}
