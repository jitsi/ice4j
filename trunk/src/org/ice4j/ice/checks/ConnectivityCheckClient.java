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

    /**
     * Starts client connectivity checks using <tt>checkList</tt> as the
     * {@link CheckList} of the first {@link IceMediaStream}.
     *
     * @param firstCheckList the check list that we should start our checks
     * with.
     */
    public void startChecks(CheckList firstCheckList)
    {
        PaceMaker paceMaker = new PaceMaker(this, firstCheckList);
        paceMakers.add(paceMaker);

        paceMaker.start();
    }

    /**
     * Creates a STUN {@link Request} containing the necessary PRIORITY and
     * CONTROLLING/CONTROLLED attributes. Also stores a reference to
     * <tt>candidatePair</tt> in the newly created transactionID so that we
     * could then refer back to it in subsequent response or failure events.
     *
     * @param candidatePair that {@link CandidatePair} that we'd like to start
     * a check for.
     *
     * @return a reference to the {@link TransactionID} used in the connectivity
     * check client transaction or <tt>null</tt> if sending the check has
     * failed for some reason.
     */
    private TransactionID startCheckForPair(CandidatePair candidatePair)
    {
        //we don't need to do a canReach() verification here as it has been
        //already verified during the gathering process.
        DatagramSocket stunSocket = ((HostCandidate)candidatePair
                        .getLocalCandidate()) .getStunSocket(null);

        Request request = MessageFactory.createBindingRequest();

        //the priority we'd like the remote party to use for a peer reflexive
        //candidate if one is discovered as a consequence of this check.
        PriorityAttribute priority = AttributeFactory.createPriorityAttribute(
            candidatePair.getLocalCandidate().computePriorityForType(
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

        //todo: also implement SASL prepare
        MessageIntegrityAttribute msgIntegrity = AttributeFactory
            .createMessageIntegrityAttribute(localUserName);

        request.addAttribute(msgIntegrity);

        TransactionID tran = TransactionID.createNewTransactionID();
        tran.setApplicationData(candidatePair);

        try
        {
            stunStack.sendRequest(request,
                candidatePair.getRemoteCandidate().getTransportAddress(),
                candidatePair.getLocalCandidate().getTransportAddress(),
                this, tran);

            if(logger.isLoggable(Level.FINEST))
                logger.finest("checking pair " + candidatePair + " with tran="
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

    /**
     * Handles the <tt>response</tt> as per the procedures described in RFC 5245
     * or in other words, by either changing the state of the corresponding pair
     * to FAILED, or SUCCEDED, or rescheduling a check in case of a role
     * conflict.
     *
     * @param evt the {@link StunResponseEvent} that contains the newly
     * received response.
     */
    public void processResponse(StunResponseEvent evt)
    {
        //make sure that the response came from the right place.
        if (!checkSymmetricAddresses(evt))
        {
            CandidatePair pair = ((CandidatePair)evt.getTransactionID()
                            .getApplicationData());

            logger.fine("Received a non-symmetric response for pair: "+ pair
                            +". Failing");
            pair.setState(CandidatePairState.FAILED, null);
        }

        //handle error responses.
        if(evt.getResponse().getMessageType()
                        == Response.BINDING_ERROR_RESPONSE)
        {
            if(! evt.getResponse().contains(Attribute.ERROR_CODE))
            {
                logger.fine("Received a malformed error response.");
                return; //malformed error response
            }

            processErrorResponse(evt);
        }


    }

    /**
     * Returns <tt>true</tt> if the {@link Response} in <tt>evt</tt> had a
     * source or a destination address that did not match those of the
     * {@link Request}, or <tt>false</tt> otherwise.
     * RFC 5245: The agent MUST check that the source IP address and port of
     * the response equal the destination IP address and port to which the
     * Binding request was sent, and that the destination IP address and
     * port of the response match the source IP address and port from which
     * the Binding request was sent.  In other words, the source and
     * destination transport addresses in the request and responses are
     * symmetric.  If they are not symmetric, the agent sets the state of
     * the pair to Failed.
     *
     * @param evt the {@link StunResponseEvent} that contains the {@link
     * Response} we need to examine
     *
     * @return <tt>true</tt> if the {@link Response} in <tt>evt</tt> had a
     * source or a destination address that did not match those of the
     * {@link Request}, or <tt>false</tt> otherwise.
     */
    private boolean checkSymmetricAddresses(StunResponseEvent evt)
    {
        CandidatePair pair = ((CandidatePair)evt.getTransactionID()
                        .getApplicationData());

        return pair.getLocalCandidate().equals(evt.getLocalAddress())
           && pair.getRemoteCandidate().equals(evt.getRemoteAddress());
    }

    /**
     * In case of a role conflict, changes the state of the agent and
     * reschedules the check, in all other cases sets the corresponding peer
     * state to FAILED.
     *
     * @param evt the event that delivered the error response.
     */
    private void processErrorResponse(StunResponseEvent evt)
    {
        Response response = evt.getResponse();
        Request originalRequest = evt.getRequest();

        ErrorCodeAttribute errorCode = (ErrorCodeAttribute)response
                                    .getAttribute(Attribute.ERROR_CODE);

        CandidatePair pair = ((CandidatePair)evt.getTransactionID()
                        .getApplicationData());

        logger.finest("Received error code " + errorCode.getErrorCode());

        //RESOLVE ROLE_CONFLICTS
        if(errorCode.getErrorCode() == ErrorCodeAttribute.ROLE_CONFLICT)
        {
            boolean wasControlling = originalRequest
                                .contains(Attribute.ICE_CONTROLLING);

            logger.finer("Swithing to isControlling=" + !wasControlling);
            parentAgent.setControlling(!wasControlling);

            pair.getParentComponent().getParentStream().getCheckList()
                .scheduleTriggeredCheck(pair);

            return;
        }
        else
        {
            logger.fine("Received an unrecoverable error response for pair "
                            + pair + " will mark the pair as FAILED.");
            pair.setState(CandidatePairState.FAILED, null);
        }
    }

    public void processTimeout(StunTimeoutEvent event)
    {
        System.out.println("timeout for pair=" + event.getTransactionID().getApplicationData());

    }

    /**
     * Removes the corresponding local candidate from the list of candidates
     * that we are waiting on in order to complete the harvest.
     *
     * @param transactionID the ID of the transaction that has just ended.
     */
/*
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
*/
    /**
     * The thread that actually sends the checks for a particular check list
     * in the pace defined in RFC 5245.
     */
    private static class PaceMaker extends Thread
    {
        /**
         * Indicates whether this thread is still running. Not really used at
         * this point.
         */
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
                        wait(waitFor);
                    }
                    catch (InterruptedException e)
                    {
                        logger.log(Level.FINER, "PaceMake got interrupted", e);
                    }

                    if (!isRunning)
                        return;
                }

                CandidatePair pairToCheck = checkList.popTriggeredCheck();
                TransactionID transactionID = null;

                //if there are no triggered checks, go for an ordinary one.
                if(pairToCheck == null)
                    pairToCheck = checkList.getNextOrdinaryPairToCheck();

                if(pairToCheck != null)
                    transactionID = parentClient.startCheckForPair(pairToCheck);

                if(pairToCheck == null)
                {
                    //we are done sending checks for this list. we'll send its
                    //final state in either the processResponse()
                    //processTimeout() or processFailure() method.

                    logger.finest("finished a checklist");

                    isRunning = false;
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
