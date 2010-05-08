/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.net.*;
import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;

/**
 * The class that will be generating our outgoing connectivity checks and that
 * will be handling their responses or lack thereof.
 *
 * @author Emil Ivov
 */
class ConnectivityCheckClient
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
     * Starts client connectivity checks for the first {@link IceMediaStream}
     * in our parent {@link Agent}. This method should only be called by
     * the parent {@link Agent} when connectivity establishment starts for a
     * particular check list.
     */
    public void startChecks()
    {
        CheckList firstCheckList = parentAgent.getStreams().get(0)
            .getCheckList();

        startChecks(firstCheckList);
    }

    /**
     * Starts client connectivity checks for the {@link CandidatePair}s in
     *  <tt>checkList</tt>
     *
     * @param checkList the {@link CheckList} to start client side connectivity
     * checks for.
     */
    private void startChecks(CheckList checkList)
    {
        PaceMaker paceMaker = new PaceMaker(this, checkList);
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

            //if we are the controlling agent then we need to indicate our
            //nominated pairs.
            if(candidatePair.isNominated())
                request.addAttribute(AttributeFactory
                                .createUseCandidateAttribute());
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
            pair.setStateFailed();
        }
        //handle error responses.
        else if(evt.getResponse().getMessageType()
                        == Response.BINDING_ERROR_RESPONSE)
        {
            if(! evt.getResponse().contains(Attribute.ERROR_CODE))
            {
                logger.fine("Received a malformed error response.");
                return; //malformed error response
            }

            processErrorResponse(evt);
        }
        //handle error responses.
        else if(evt.getResponse().getMessageType()
                        == Response.BINDING_SUCCESS_RESPONSE)
        {
            processSuccessResponse(evt);
        }

        CandidatePair checkedPair = ((CandidatePair)evt.getTransactionID()
                        .getApplicationData());

        //Regardless of whether the check was successful or failed, the
        //completion of the transaction may require updating of check list and
        //timer states.
        updateCheckListAndTimerStates(checkedPair);
    }

    /**
     * Updates all check list and timer states after a check has completed
     * (both if completion was successful or not). The method implements
     * section "7.1.3.3. Check List and Timer State Updates"
     *
     * @param checkedPair the pair whose check has just completed.
     */
    private void updateCheckListAndTimerStates(CandidatePair checkedPair)
    {
        IceMediaStream stream = checkedPair.getParentComponent()
            .getParentStream();
        CheckList checkList = stream.getCheckList();

        //If all of the pairs in the check list are now either in the Failed or
        //Succeeded state:
        boolean allPairsDone = true;
        synchronized(checkList)
        {
            for(CandidatePair pair : checkList)
            {
                if(pair.getState() != CandidatePairState.FAILED
                   && pair.getState() != CandidatePairState.SUCCEEDED)
                {
                    allPairsDone = false;
                }
            }
        }

        if (allPairsDone)
        {
            //If there is not a pair in the valid list for each component of the
            //media stream, the state of the check list is set to Failed.
            if ( !stream.validListContainsAllComponents())
            {
                checkList.setState(CheckListState.FAILED);
            }

            //For each frozen check list, the agent groups together all of the
            //pairs with the same foundation, and for each group, sets the
            //state of the pair with the lowest component ID to Waiting.  If
            //there is more than one such pair, the one with the highest
            //priority is used.
            List<IceMediaStream> allOtherStreams = parentAgent.getStreams();
            allOtherStreams.remove(checkList);
            for (IceMediaStream anotherStream : allOtherStreams)
            {
                CheckList anotherCheckList = anotherStream.getCheckList();
                if(anotherCheckList.isFrozen())
                {
                    anotherCheckList.computeInitialCheckListPairStates();
                    startChecks(anotherCheckList);
                }
            }
        }

        parentAgent.checkListStatesUpdated();
    }

    /**
     * Handles STUN success responses as per the rules in RFC 5245.
     *
     * @param evt the event that delivered the error response.
     */
    private void processSuccessResponse(StunResponseEvent evt)
    {
        Response response = evt.getResponse();
        Request  request  = evt.getRequest();

        CandidatePair checkedPair = ((CandidatePair)evt.getTransactionID()
                        .getApplicationData());

        if(! response.contains(Attribute.XOR_MAPPED_ADDRESS))
        {
            logger.fine("Received a success response with no "
                            +"XOR_MAPPED_ADDRESS attribute.");
            checkedPair.setStateFailed();
            return; //malformed error response
        }

        XorMappedAddressAttribute mappedAddressAttr
            = (XorMappedAddressAttribute)response
                .getAttribute(Attribute.XOR_MAPPED_ADDRESS);

        TransportAddress mappedAddress = mappedAddressAttr
            .getAddress(response.getTransactionID());

        LocalCandidate validLocalCandidate = parentAgent
                                       .findLocalCandidate(mappedAddress);
        Candidate validRemoteCandidate = checkedPair.getRemoteCandidate();

        // RFC 5245: The agent checks the mapped address from the STUN
        // response. If the transport address does not match any of the
        // local candidates that the agent knows about, the mapped address
        // represents a new candidate -- a peer reflexive candidate.
        if ( validLocalCandidate == null)
        {
            //Like other candidates, PEER-REFLEXIVE candidates have a type,
            //base, priority, and foundation.  They are computed as follows:
            //o The type is equal to peer reflexive.
            //o The base is the local candidate of the candidate
            //  pair from which the STUN check was sent.
            //o Its priority is set equal to the value of the PRIORITY attribute
            //  in the Binding request.
            PriorityAttribute prioAttr = (PriorityAttribute)request
                .getAttribute(Attribute.PRIORITY);

            LocalCandidate peerReflexiveCandidate = new PeerReflexiveCandidate(
                            mappedAddress, checkedPair.getParentComponent(),
                            checkedPair.getLocalCandidate(),
                            prioAttr.getPriority());

            peerReflexiveCandidate.setBase(checkedPair.getLocalCandidate());

            //This peer reflexive candidate is then added to the list of local
            //candidates for the media stream, so that it would be available for
            //updated offers.
            checkedPair.getParentComponent().addLocalCandidate(
                            peerReflexiveCandidate);

            //However, the peer reflexive candidate is not paired with other
            //remote candidates. This is not necessary; a valid pair will be
            //generated from it momentarily
            validLocalCandidate = peerReflexiveCandidate;
        }

        //check if the resulting valid pair was already in our check lists.
        CandidatePair existingPair = parentAgent.findCandidatePair(
                        validLocalCandidate.getTransportAddress(),
                        validRemoteCandidate.getTransportAddress());

        // RFC 5245: 7.1.3.2.2. The agent constructs a candidate pair whose
        // local candidate equals the mapped address of the response, and whose
        // remote candidate equals the destination address to which the request
        // was sent.  This is called a valid pair, since it has been validated
        // by a STUN connectivity check.
        CandidatePair validPair;
        if(existingPair != null)
        {
            validPair = existingPair;
        }
        else
        {
            validPair = new CandidatePair(validLocalCandidate,
                        validRemoteCandidate);
        }

        if(! validPair.isValid())
            parentAgent.validatePair(validPair);

        //The agent sets the state of the pair that *generated* the check to
        //Succeeded.  Note that, the pair which *generated* the check may be
        //different than the valid pair constructed above
        checkedPair.setStateSucceeded();

        //The agent changes the states for all other Frozen pairs for the
        //same media stream and same foundation to Waiting.
        IceMediaStream parentStream = checkedPair.getParentComponent()
            .getParentStream();
        CheckList parentCheckList = parentStream.getCheckList();

        for(CandidatePair pair : parentCheckList)
            if (pair.getState() == CandidatePairState.FROZEN)
                pair.setStateWaiting();

        // The agent examines the check list for all other streams in turn
        // If the check list is active, the agent changes the state of
        // all Frozen pairs in that check list whose foundation matches a
        // pair in the valid list under consideration to Waiting.
        List<IceMediaStream> allOtherStreams = parentAgent.getStreams();
        allOtherStreams.remove(parentStream);

        for (IceMediaStream stream : allOtherStreams)
        {
            CheckList checkList = stream.getCheckList();
            boolean wasFrozen = checkList.isFrozen();

            synchronized (checkList)
            {
                for(CandidatePair pair : checkList)
                {
                    if (parentStream.validListContainsFoundation(pair.getFoundation())
                        && pair.getState() == CandidatePairState.FROZEN)
                    {
                        pair.setStateWaiting();
                    }
                }
            }

            //if the checklList is still frozen after the above operations,
            //the agent groups together all of the pairs with the same
            //foundation, and for each group, sets the state of the pair with
            //the lowest component ID to Waiting.  If there is more than one
            //such pair, the one with the highest priority is used.
            if(checkList.isFrozen())
                checkList.computeInitialCheckListPairStates();

            if (wasFrozen)
                startChecks(checkList);
        }

        //If the agent was a controlling agent, and it had included a USE-
        //CANDIDATE attribute in the Binding request, the valid pair generated
        //from that check has its nominated flag set to true.
        if(parentAgent.isControlling()
                      && request.contains(Attribute.USE_CANDIDATE))
        {
            parentAgent.nominationConfirmed( validPair );
        }
        //If the agent is the controlled agent, the response may be the result
        //of a triggered check that was sent in response to a request that
        //itself had the USE-CANDIDATE attribute.  This case is described in
        //Section 7.2.1.5, and may now result in setting the nominated flag for
        //the pair learned from the original request.
        else if(checkedPair.useCandidateReceived()
                 && ! checkedPair.isNominated())
            parentAgent.nominationConfirmed( checkedPair );

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

        boolean sym = pair.getLocalCandidate().getTransportAddress()
                                        .equals(evt.getLocalAddress())
           && pair.getRemoteCandidate().getTransportAddress()
                                        .equals(evt.getRemoteAddress());

        return sym;
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
            pair.setStateFailed();
        }
    }

    /**
     * Sets the state of the corresponding {@link CandidatePair} to
     * {@link CandidatePairState#FAILED} and updates check list and timer
     * states.
     *
     * @param event the {@link StunTimeoutEvent} containing the original
     * transaction and hence {@link CandidatePair} that's being checked.
     */
    public void processTimeout(StunTimeoutEvent event)
    {
        CandidatePair pair = ((CandidatePair)event.getTransactionID()
                        .getApplicationData());
        logger.fine("timeout for pair=" + pair);

        pair.setStateFailed();
        updateCheckListAndTimerStates(pair);
    }


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
         * Returns the number milliseconds to wait before we send the next
         * check.
         *
         * @return  the number milliseconds to wait before we send the next
         * check.
         */
        private long getNextWaitInterval()
        {
            int activeCheckLists = parentClient
                    .parentAgent.getActiveCheckListCount();

            if (activeCheckLists < 1)
            {
                //don't multiply by 0. even when we no longer have active check
                //lists we may still have nomination checks to
                activeCheckLists = 1;
            }

            return parentClient.parentAgent.calculateTa() * activeCheckLists;
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
                long waitFor = getNextWaitInterval();

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
                        break;
                }

                CandidatePair pairToCheck = checkList.popTriggeredCheck();
                TransactionID transactionID = null;

                //if there are no triggered checks, go for an ordinary one.
                if(pairToCheck == null)
                {
                    pairToCheck = checkList.getNextOrdinaryPairToCheck();
                }

                if(pairToCheck != null)
                {
                    transactionID = parentClient.startCheckForPair(pairToCheck);
                }
                else
                {
                    //we are done sending checks for this list. we'll set its
                    //final state in either the processResponse()
                    //processTimeout() or processFailure() method.

                    logger.finest("will skip a check beat.");
                    continue;
                }

                if(transactionID == null)
                    pairToCheck.setStateFailed();
                else
                    pairToCheck.setStateInProgress(transactionID);

            }

            parentClient.paceMakers.remove(this);
        }
    }

    /**
     * Stops and removes all PaceMakers.
     */
    public void stop()
    {
        synchronized (paceMakers)
        {
            Iterator<PaceMaker> paceMakersIter = paceMakers.iterator();
            while(paceMakersIter.hasNext())
            {
                PaceMaker paceMaker = paceMakersIter.next();

                paceMaker.isRunning = false;
                synchronized(paceMaker)
                {

                    paceMaker.notify();
                }

                paceMakersIter.remove();
            }
        }
    }
}
