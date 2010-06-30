/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice.harvest;

import java.io.*;
import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.ice.*;
import org.ice4j.message.*;
import org.ice4j.security.*;
import org.ice4j.stack.*;

/**
 * Represents the harvesting of STUN <tt>Candidates</tt> for a specific
 * <tt>HostCandidate</tt> performed by a specific
 * <tt>StunCandidateHarvester</tt>.
 *
 * @author Lubomir Marinov
 */
public class StunCandidateHarvest
    extends AbstractResponseCollector
{

    /**
     * The <tt>Logger</tt> used by the <tt>StunCandidateHarvest</tt> class and
     * its instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(StunCandidateHarvest.class.getName());

    /**
     * The constant which defines an empty array with <tt>Candidate</tt> element
     * type. Explicitly defined in order to reduce unnecessary allocations.
     */
    private static final Candidate[] NO_CANDIDATES = new Candidate[0];

    /**
     * The list of <tt>Candidate</tt>s harvested for {@link #hostCandidate} by
     * this harvest.
     */
    private final List<Candidate> candidates = new LinkedList<Candidate>();

    /**
     * The indicator which determines whether this <tt>StunCandidateHarvest</tt>
     * has completed the harvesting of <tt>Candidate</tt>s for
     * {@link #hostCandidate}.
     */
    private boolean completedResolvingCandidate = false;

    /**
     * The <tt>StunCandidateHarvester</tt> performing the harvesting of STUN
     * <tt>Candidate</tt>s for a <tt>Component</tt> which this harvest is part
     * of.
     */
    public final StunCandidateHarvester harvester;

    /**
     * The <tt>HostCandidate</tt> the STUN harvesting of which is represented by
     * this instance.
     */
    public final HostCandidate hostCandidate;

    /**
     * The <tt>LongTermCredential</tt> used by this instance.
     */
    private LongTermCredentialSession longTermCredentialSession;

    /**
     * The STUN <tt>Request</tt>s which have been sent by this instance, have
     * not received a STUN <tt>Response</tt> yet and have not timed out. Put in
     * place to avoid a limitation of the <tt>ResponseCollector</tt> and its use
     * of <tt>StunMessageEvent</tt> which do not make the STUN <tt>Request</tt>
     * to which a STUN <tt>Response</tt> responds available though it is known
     * in <tt>StunClientTransaction</tt>.
     */
    private final Map<TransactionID, Request> requests
        = new HashMap<TransactionID, Request>();

    /**
     * Initializes a new <tt>StunCandidateHarvest</tt> which is to represent the
     * harvesting of STUN <tt>Candidate</tt>s for a specific
     * <tt>HostCandidate</tt> performed by a specific
     * <tt>StunCandidateHarvester</tt>.
     *
     * @param harvester the <tt>StunCandidateHarvester</tt> which is performing
     * the STUN harvesting
     * @param hostCandidate the <tt>HostCandidate</tt> for which STUN
     * <tt>Candidate</tt>s are to be harvested
     */
    public StunCandidateHarvest(
            StunCandidateHarvester harvester,
            HostCandidate hostCandidate)
    {
        this.harvester = harvester;
        this.hostCandidate = hostCandidate;
    }

    /**
     * Adds a specific <tt>LocalCandidate</tt> to the list of
     * <tt>LocalCandidate</tt>s harvested for {@link #hostCandidate} by this
     * harvest.
     *
     * @param candidate the <tt>LocalCandidate</tt> to be added to the list of
     * <tt>LocalCandidate</tt>s harvested for {@link #hostCandidate} by this
     * harvest
     */
    protected void addCandidate(LocalCandidate candidate)
    {
        if (!candidates.contains(candidate))
        {
            hostCandidate.getParentComponent().addLocalCandidate(candidate);
            candidates.add(candidate);
        }
    }

    /**
     * Adds the <tt>Attribute</tt>s to a specific <tt>Request</tt> which support
     * the STUN short-term credential mechanism if the mechanism in question is
     * utilized by this <tt>StunCandidateHarvest</tt> (i.e. by the associated
     * <tt>StunCandidateHarvester</tt>).
     *
     * @param request the <tt>Request</tt> to which to add the
     * <tt>Attribute</tt>s supporting the STUN short-term credential mechanism
     * if the mechanism in question is utilized by this
     * <tt>StunCandidateHarvest</tt>
     * @return <tt>true</tt> if the STUN short-term credential mechanism is
     * actually utilized by this <tt>StunCandidateHarvest</tt> for the specified
     * <tt>request</tt>; otherwise, <tt>false</tt>
     */
    protected boolean addShortTermCredentialAttributes(Request request)
    {
        String shortTermCredentialUsername
            = harvester.getShortTermCredentialUsername();

        if (shortTermCredentialUsername != null)
        {
            request.addAttribute(
                    AttributeFactory.createUsernameAttribute(
                            shortTermCredentialUsername));
            request.addAttribute(
                    AttributeFactory.createMessageIntegrityAttribute(
                            shortTermCredentialUsername));
            return true;
        }
        else
            return false;
    }

    /**
     * Completes the harvesting of <tt>Candidate</tt>s for
     * {@link #hostCandidate}. Notifies {@link #harvester} about the completion
     * of the harvesting of <tt>Candidate</tt> for <tt>hostCandidate</tt>
     * performed by this <tt>StunCandidateHarvest</tt>.
     * 
     * @param request the <tt>Request</tt> sent by this
     * <tt>StunCandidateHarvest</tt> with which the harvesting of
     * <tt>Candidate</tt>s for <tt>hostCandidate</tt> has completed
     * @param response the <tt>Response</tt> received by this
     * <tt>StunCandidateHarvest</tt>, if any, with which the harvesting of
     * <tt>Candidate</tt>s for <tt>hostCandidate</tt> has completed
     * @return <tt>true</tt> if the harvesting of <tt>Candidate</tt>s for
     * <tt>hostCandidate</tt> performed by this <tt>StunCandidateHarvest</tt>
     * has completed; otherwise, <tt>false</tt>
     */
    protected boolean completedResolvingCandidate(
            Request request,
            Response response)
    {
        if (!completedResolvingCandidate)
        {
            completedResolvingCandidate = true;
            try
            {
                if (((response == null) || !response.isSuccessResponse())
                        && (longTermCredentialSession != null))
                {
                    harvester.stunStack.getCredentialsManager().unregisterAuthority(
                            longTermCredentialSession);
                    longTermCredentialSession = null;
                }
            }
            finally
            {
                harvester.completedResolvingCandidate(this);
            }
        }
        return completedResolvingCandidate;
    }

    /**
     * Creates new <tt>Candidate</tt>s determined by a specific STUN
     * <tt>Response</tt>.
     *
     * @param response the received STUN <tt>Response</tt>
     */
    protected void createCandidates(Response response)
    {
        createServerReflexiveCandidate(response);
    }

    /**
     * Creates a new <tt>Request</tt> instance which is to be sent by this
     * <tt>StunCandidateHarvest</tt> in order to retry a specific
     * <tt>Request</tt>. For example, the long-term credential mechanism
     * dictates that a <tt>Request</tt> is first sent by the client without any
     * credential-related attributes, then it gets challenged by the server and
     * the client retries the original <tt>Request</tt> with the appropriate
     * credential-related attributes in response.
     *
     * @param request the <tt>Request</tt> which is to be retried by this
     * <tt>StunCandidateHarvest</tt>
     * @return the new <tt>Request</tt> instance which is to be sent by this
     * <tt>StunCandidateHarvest</tt> in order to retry the specified
     * <tt>request</tt>
     */
    protected Request createRequestToRetry(Request request)
    {
        switch (request.getMessageType())
        {
        case Message.BINDING_REQUEST:
            return MessageFactory.createBindingRequest();
        default:
            throw new IllegalArgumentException("request.messageType");
        }
    }

    /**
     * Creates a new <tt>Request</tt> which is to be sent to {@link #stunServer}
     * in order to start resolving {@link #hostCandidate}.
     *
     * @return a new <tt>Request</tt> which is to be sent to {@link #stunServer}
     * in order to start resolving {@link #hostCandidate}
     */
    protected Request createRequestToStartResolvingCandidate()
    {
        return MessageFactory.createBindingRequest();
    }

    /**
     * Creates a <tt>ServerReflexiveCandidate</tt> using {@link #hostCandidate}
     * as its base and the <tt>XOR-MAPPED-ADDRESS</tt> attribute in
     * <tt>response</tt> for the actual <tt>TransportAddress</tt> of the new
     * candidate. If the message is malformed and/or does not contain the
     * corresponding attribute, this method simply has no effect.
     *
     * @param response the STUN <tt>Response</tt> which is supposed to contain
     * the address we should use for the new candidate
     */
    protected void createServerReflexiveCandidate(Response response)
    {
        TransportAddress addr = getMappedAddress(response);

        if (addr != null)
        {
            ServerReflexiveCandidate srvrRflxCand
                = createServerReflexiveCandidate(addr);

            if (srvrRflxCand != null)
                addCandidate(srvrRflxCand);
        }
    }

    /**
     * Creates a new <tt>ServerReflexiveCandidate</tt> instance which is to
     * represent a specific <tt>TransportAddress</tt> harvested through
     * {@link #hostCandidate} and the STUN server associated with
     * {@link #harvester}.
     *
     * @param transportAddress the <tt>TransportAddress</tt> to be represented
     * by the new <tt>ServerReflexiveCandidate</tt> instance
     * @return a new <tt>ServerReflexiveCandidate</tt> instance which represents
     * the specified <tt>TransportAddress</tt> harvested through
     * {@link #hostCandidate} and the STUN server associated with
     * {@link #harvester}
     */
    protected ServerReflexiveCandidate createServerReflexiveCandidate(
            TransportAddress transportAddress)
    {
        return
            new ServerReflexiveCandidate(
                    transportAddress,
                    hostCandidate,
                    harvester.stunServer);
    }

    /**
     * Gets the number of <tt>Candidate</tt>s harvested for
     * {@link #hostCandidate} during this harvest.
     *
     * @return the number of <tt>Candidate</tt>s harvested for
     * {@link #hostCandidate} during this harvest
     */
    int getCandidateCount()
    {
        return candidates.size();
    }

    /**
     * Gets the <tt>Candidate</tt>s harvested for {@link #hostCandidate} during
     * this harvest.
     *
     * @return an array containing the <tt>Candidate</tt>s harvested for
     * {@link #hostCandidate} during this harvest
     */
    Candidate[] getCandidates()
    {
        return candidates.toArray(NO_CANDIDATES);
    }

    /**
     * Gets the <tt>TransportAddress</tt> specified in the XOR-MAPPED-ADDRESS
     * attribute of a specific <tt>Response</tt>.
     *
     * @param response the <tt>Response</tt> from which the XOR-MAPPED-ADDRESS
     * attribute is to be retrieved and its <tt>TransportAddress</tt> value is
     * to be returned
     * @return the <tt>TransportAddress</tt> specified in the XOR-MAPPED-ADDRESS
     * attribute of <tt>response</tt>
     */
    protected TransportAddress getMappedAddress(Response response)
    {
        Attribute attribute
            = response.getAttribute(Attribute.XOR_MAPPED_ADDRESS);

        if(attribute instanceof XorMappedAddressAttribute)
        {
            return
                ((XorMappedAddressAttribute) attribute)
                    .getAddress(response.getTransactionID());
        }
        else
            return null;
    }

    /**
     * Notifies this <tt>StunCandidateHarvest</tt> that a specific STUN
     * <tt>Request</tt> has been challenged for a long-term credential (as the
     * short-term credential mechanism does not utilize challenging) in a
     * specific <tt>realm</tt> and with a specific <tt>nonce</tt>.
     *
     * @param realm the realm in which the specified STUN <tt>Request</tt> has
     * been challenged for a long-term credential
     * @param nonce the nonce with which the specified STUN <tt>Request</tt> has
     * been challenged for a long-term credential
     * @param request the STUN <tt>Request</tt> which has been challenged for a
     * long-term credential
     * @return <tt>true</tt> if the challenge has been processed and this
     * <tt>StunCandidateHarvest</tt> is to continue processing STUN
     * <tt>Response</tt>s; otherwise, <tt>false</tt>
     * @throws StunException if anything goes wrong while processing the
     * challenge
     */
    private boolean processChallenge(
            byte[] realm,
            byte[] nonce,
            Request request)
        throws StunException
    {
        UsernameAttribute usernameAttribute
            = (UsernameAttribute) request.getAttribute(Attribute.USERNAME);

        if (usernameAttribute == null)
        {
            if (longTermCredentialSession == null)
            {
                LongTermCredential longTermCredential
                    = harvester.createLongTermCredential(this, realm);

                if (longTermCredential == null)
                {
                    // The long-term credential mechanism is not being utilized.
                    return false;
                }
                else
                {
                    longTermCredentialSession
                        = new LongTermCredentialSession(
                                longTermCredential,
                                realm);
                    harvester
                        .stunStack
                            .getCredentialsManager()
                                .registerAuthority(longTermCredentialSession);
                }
            }
            else
            {
                /*
                 * If we're going to use the long-term credential to retry the
                 * request, the long-term credential should be for the request
                 * in terms of realm.
                 */
                if (!longTermCredentialSession.realmEquals(realm))
                    return false;
            }
        }
        else
        {
            /*
             * If we sent a USERNAME in our request, then we had the long-term
             * credential at the time we sent the request in question.
             */
            if (longTermCredentialSession == null) 
                return false;
            else
            {
                /*
                 * If we're going to use the long-term credential to retry the
                 * request, the long-term credential should be for the request
                 * in terms of username.
                 */
                if (!longTermCredentialSession.usernameEquals(
                        usernameAttribute.getUsername()))
                    return false;
                else
                {
                    // And it terms of realm, of course.
                    if (!longTermCredentialSession.realmEquals(realm))
                        return false;
                }
            }
        }

        /*
         * The nonce is either becoming known for the first time or being
         * updated after the old one has gone stale.
         */
        longTermCredentialSession.setNonce(nonce);

        Request retryRequest = createRequestToRetry(request);
        TransactionID retryRequestTransactionID = null;

        if (retryRequest != null)
        {
            longTermCredentialSession.addAttributes(retryRequest);
            retryRequestTransactionID = sendRequest(retryRequest);
        }
        return (retryRequestTransactionID != null);
    }

    /**
     * Notifies this <tt>StunCandidateHarvest</tt> that a specific STUN
     * <tt>Response</tt> has been received and it challenges a specific STUN
     * <tt>Request</tt> for a long-term credential (as the short-term credential
     * mechanism does not utilize challenging).
     *
     * @param response the STUN <tt>Response</tt> which has been received
     * @param request the STUN <tt>Request</tt> to which <tt>response</tt>
     * responds and which it challenges for a long-term credential
     * @return <tt>true</tt> if the challenge has been processed and this
     * <tt>StunCandidateHarvest</tt> is to continue processing STUN
     * <tt>Response</tt>s; otherwise, <tt>false</tt>
     * @throws StunException if anything goes wrong while processing the
     * challenge
     */
    private boolean processChallenge(Response response, Request request)
        throws StunException
    {
        boolean retried = false;

        if (response.getAttributeCount() > 0)
        {
            /*
             * The response SHOULD NOT contain a USERNAME or
             * MESSAGE-INTEGRITY attribute.
             */
            char[] excludedResponseAttributeTypes
                = new char[]
                        {
                            Attribute.USERNAME,
                            Attribute.MESSAGE_INTEGRITY
                        };
            boolean challenge = true;

            for (char excludedResponseAttributeType
                    : excludedResponseAttributeTypes)
            {
                if (response.containsAttribute(excludedResponseAttributeType))
                {
                    challenge = false;
                    break;
                }
            }
            if (challenge)
            {
                // This response MUST include a REALM value.
                RealmAttribute realmAttribute
                    = (RealmAttribute) response.getAttribute(Attribute.REALM);

                if (realmAttribute == null)
                    challenge = false;
                else
                {
                    // The response MUST include a NONCE.
                    NonceAttribute nonceAttribute
                        = (NonceAttribute)
                            response.getAttribute(Attribute.NONCE);

                    if (nonceAttribute == null)
                        challenge = false;
                    else
                    {
                        retried
                            = processChallenge(
                                    realmAttribute.getRealm(),
                                    nonceAttribute.getNonce(),
                                    request);
                    }
                }
            }
        }
        return retried;
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
        TransactionID transactionID = event.getTransactionID();

        logger.finest("A transaction expired: tranid=" + transactionID);
        logger.finest("localAddr=" + hostCandidate);

        /*
         * Clean up for the purposes of the workaround which determines the STUN
         * Request to which a STUN Response responds.
         */
        Request request;

        synchronized (requests)
        {
            request = requests.remove(transactionID);
        }
        if (request == null)
        {
            Message message = event.getMessage();

            if (message instanceof Request)
                request = (Request) message;
        }
        completedResolvingCandidate(request, null);
    }

    /**
     * Notifies this <tt>ResponseCollector</tt> that a STUN response described
     * by the specified <tt>StunResponseEvent</tt> has been received.
     *
     * @param event the <tt>StunResponseEvent</tt> which describes the received
     * STUN response
     * @see ResponseCollector#processResponse(StunResponseEvent)
     */
    public void processResponse(StunResponseEvent event)
    {
        TransactionID transactionID = event.getTransactionID();

        logger.finest("Received a message: tranid= " + transactionID);
        logger.finest("localCand= " + hostCandidate);

        /*
         * Clean up for the purposes of the workaround which determines the STUN
         * Request to which a STUN Response responds.
         */
        synchronized (requests)
        {
            requests.remove(transactionID);
        }

        // At long last, do start handling the received STUN Response.
        Response response = event.getResponse();
        Request request = event.getRequest();
        boolean completedResolvingCandidate = true;

        try
        {
            if (response.isSuccessResponse())
            {
                // Authentication and Message-Integrity Mechanisms
                if (request.containsAttribute(Attribute.MESSAGE_INTEGRITY))
                {
                    MessageIntegrityAttribute messageIntegrityAttribute
                        = (MessageIntegrityAttribute)
                            response.getAttribute(Attribute.MESSAGE_INTEGRITY);

                    /*
                     * RFC 5389: If MESSAGE-INTEGRITY was absent, the response
                     * MUST be discarded, as if it was never received.
                     */
                    if (messageIntegrityAttribute == null)
                        return;

                    UsernameAttribute usernameAttribute
                        = (UsernameAttribute)
                            request.getAttribute(Attribute.USERNAME);

                    /*
                     * For a request or indication message, the agent MUST
                     * include the USERNAME and MESSAGE-INTEGRITY attributes in
                     * the message.
                     */
                    if (usernameAttribute == null)
                        return;
                    if (!harvester.stunStack.validateMessageIntegrity(
                            messageIntegrityAttribute,
                            LongTermCredential.toString(
                                    usernameAttribute.getUsername()),
                            !request.containsAttribute(Attribute.REALM)
                                && !request.containsAttribute(Attribute.NONCE),
                            event.getRawMessage()))
                        return;
                }

                createCandidates(response);
            }
            else
            {
                ErrorCodeAttribute errorCodeAttr
                    = (ErrorCodeAttribute)
                        response.getAttribute(Attribute.ERROR_CODE);
    
                if ((errorCodeAttr != null)
                        && (errorCodeAttr.getErrorClass() == 4))
                {
                    try
                    {
                        switch (errorCodeAttr.getErrorNumber())
                        {
                        case 1: // 401 Unauthorized
                            if (processUnauthorized(response, request))
                                completedResolvingCandidate = false;
                            break;
                        case 38: // 438 Stale Nonce
                            if (processStaleNonce(response, request))
                                completedResolvingCandidate = false;
                            break;
                        }
                    }
                    catch (StunException sex)
                    {
                        completedResolvingCandidate = true;
                    }
                }
            }
        }
        finally
        {
            if (completedResolvingCandidate)
                completedResolvingCandidate(request, response);
        }
    }

    /**
     * Handles a specific STUN error <tt>Response</tt> with error code
     * "438 Stale Nonce" to a specific STUN <tt>Request</tt>.
     *
     * @param response the received STUN error <tt>Response</tt> with error code
     * "438 Stale Nonce" which is to be handled
     * @param request the STUN <tt>Request</tt> to which <tt>response</tt>
     * responds
     * @return <tt>true</tt> if the specified STUN error <tt>response</tt> was
     * successfully handled; <tt>false</tt>, otherwise
     */
    private boolean processStaleNonce(Response response, Request request)
        throws StunException
    {
        /*
         * The request MUST contain USERNAME, REALM, NONCE and MESSAGE-INTEGRITY
         * attributes.
         */
        boolean challenge;

        if (request.getAttributeCount() > 0)
        {
            char[] includedRequestAttributeTypes
                = new char[]
                        {
                            Attribute.USERNAME,
                            Attribute.REALM,
                            Attribute.NONCE,
                            Attribute.MESSAGE_INTEGRITY
                        };
            challenge = true;

            for (char includedRequestAttributeType
                    : includedRequestAttributeTypes)
            {
                if (!request.containsAttribute(includedRequestAttributeType))
                {
                    challenge = false;
                    break;
                }
            }
        }
        else
            challenge = false;

        return (challenge && processChallenge(response, request));
    }

    /**
     * Handles a specific STUN error <tt>Response</tt> with error code
     * "401 Unauthorized" to a specific STUN <tt>Request</tt>.
     *
     * @param response the received STUN error <tt>Response</tt> with error code
     * "401 Unauthorized" which is to be handled
     * @param request the STUN <tt>Request</tt> to which <tt>response</tt>
     * responds
     * @return <tt>true</tt> if the specified STUN error <tt>response</tt> was
     * successfully handled; <tt>false</tt>, otherwise
     */
    private boolean processUnauthorized(Response response, Request request)
        throws StunException
    {
        /*
         * If the response is a challenge, retry the request with a new
         * transaction.
         */
        boolean challenge = true;

        /*
         * The client SHOULD omit the USERNAME, MESSAGE-INTEGRITY, REALM, and
         * NONCE attributes from the "First Request".
         */
        if (request.getAttributeCount() > 0)
        {
            char[] excludedRequestAttributeTypes
                = new char[]
                        {
                            Attribute.USERNAME,
                            Attribute.MESSAGE_INTEGRITY,
                            Attribute.REALM,
                            Attribute.NONCE
                        };

            for (char excludedRequestAttributeType
                    : excludedRequestAttributeTypes)
            {
                if (request.containsAttribute(excludedRequestAttributeType))
                {
                    challenge = false;
                    break;
                }
            }
        }

        return (challenge && processChallenge(response, request));
    }

    /**
     * Sends a specific <tt>Request</tt> to the STUN server associated with this
     * <tt>StunCandidateHarvest</tt>.
     *
     * @param request
     * @return
     * @throws StunException
     */
    protected TransactionID sendRequest(Request request)
        throws StunException
    {
        StunStack stunStack = harvester.stunStack;
        TransportAddress stunServer = harvester.stunServer;
        TransportAddress hostCandidateTransportAddress
            = hostCandidate.getTransportAddress();

        TransactionID transactionID;

        synchronized (requests)
        {
            try
            {
                transactionID
                    = stunStack
                        .sendRequest(
                            request,
                            stunServer,
                            hostCandidateTransportAddress,
                            this);
            }
            catch (IllegalArgumentException iaex)
            {
                if (logger.isLoggable(Level.INFO))
                {
                    logger.log(
                            Level.INFO,
                            "Failed to send "
                                + request
                                + " through " + hostCandidateTransportAddress
                                + " to " + stunServer,
                            iaex);
                }
                throw new StunException(
                        StunException.ILLEGAL_ARGUMENT,
                        iaex.getMessage(),
                        iaex);
            }
            catch (IOException ioex)
            {
                if (logger.isLoggable(Level.INFO))
                {
                    logger.log(
                            Level.INFO,
                            "Failed to send "
                                + request
                                + " through " + hostCandidateTransportAddress
                                + " to " + stunServer,
                            ioex);
                }
                throw new StunException(
                        StunException.NETWORK_ERROR,
                        ioex.getMessage(),
                        ioex);
            }

            requests.put(transactionID, request);
        }
        return transactionID;
    }

    /**
     * Starts the harvesting of <tt>Candidate</tt>s to be performed for
     * {@link #hostCandidate}.
     * 
     * @return <tt>true</tt> if this <tt>StunCandidateHarvest</tt> has started
     * the harvesting of <tt>Candidate</tt>s for {@link #hostCandidate};
     * otherwise, <tt>false</tt>
     * @throws Exception if anything goes wrong while starting the harvesting of
     * <tt>Candidate</tt>s to be performed for {@link #hostCandidate}
     */
    boolean startResolvingCandidate()
        throws Exception
    {
        Request requestToStartResolvingCandidate;

        if (!completedResolvingCandidate
                && ((requestToStartResolvingCandidate
                            = createRequestToStartResolvingCandidate())
                        != null))
        {
            // Short-Term Credential Mechanism
            addShortTermCredentialAttributes(requestToStartResolvingCandidate);

            sendRequest(requestToStartResolvingCandidate);
            return true;
        }
        else
            return false;
    }
}
