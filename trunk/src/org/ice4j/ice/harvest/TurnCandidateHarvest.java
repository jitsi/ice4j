/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice.harvest;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.ice.*;
import org.ice4j.message.*;

/**
 * Represents the harvesting of TURN <tt>Candidates</tt> for a specific
 * <tt>HostCandidate</tt> performed by a specific
 * <tt>TurnCandidateHarvester</tt>.
 *
 * @author Lubomir Marinov
 */
public class TurnCandidateHarvest
    extends StunCandidateHarvest
{

    /**
     * The <tt>Request</tt> created by the last call to
     * {@link #createRequestToStartResolvingCandidate()}.
     */
    private Request requestToStartResolvingCandidate;

    /**
     * Initializes a new <tt>TurnCandidateHarvest</tt> which is to represent the
     * harvesting of TURN <tt>Candidate</tt>s for a specific
     * <tt>HostCandidate</tt> performed by a specific
     * <tt>TurnCandidateHarvester</tt>.
     *
     * @param harvester the <tt>TurnCandidateHarvester</tt> which is performing
     * the TURN harvesting
     * @param hostCandidate the <tt>HostCandidate</tt> for which TURN
     * <tt>Candidate</tt>s are to be harvested
     */
    public TurnCandidateHarvest(
            TurnCandidateHarvester harvester,
            HostCandidate hostCandidate)
    {
        super(harvester, hostCandidate);
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
     * @see StunCandidateHarvest#completedResolvingCandidate(Request, Response)
     */
    @Override
    protected boolean completedResolvingCandidate(
            Request request,
            Response response)
    {
        /*
         * TODO If the Allocate request is rejected because the server lacks
         * resources to fulfill it, the agent SHOULD instead send a Binding
         * request to obtain a server reflexive candidate.
         */
        if ((response == null)
                || (!response.isSuccessResponse()
                        && (request.getMessageType()
                                == Message.ALLOCATE_REQUEST)))
        {
            try
            {
                if (startResolvingCandidate())
                    return false;
            }
            catch (Exception ex)
            {
                /*
                 * Complete the harvesting of Candidates for hostCandidate
                 * because the new attempt has just failed.
                 */
            }
        }
        return super.completedResolvingCandidate(request, response);
    }

    /**
     * Creates new <tt>Candidate</tt>s determined by a specific STUN
     * <tt>Response</tt>.
     *
     * @param response the received STUN <tt>Response</tt>
     * @see StunCandidateHarvester#createCandidates(Response)
     */
    @Override
    protected void createCandidates(Response response)
    {
        createRelayedCandidate(response);

        // Let the super create the ServerReflexiveCandidate.
        super.createCandidates(response);
    }

    /**
     * Creates a <tt>RelayedCandidate</tt> using the
     * <tt>XOR-RELAYED-ADDRESS</tt> attribute in a specific STUN
     * <tt>Response</tt> for the actual <tt>TransportAddress</tt> of the new
     * candidate. If the message is malformed and/or does not contain the
     * corresponding attribute, this method simply has no effect.
     *
     * @param response the STUN <tt>Response</tt> which is supposed to contain
     * the address we should use for the new candidate
     */
    private void createRelayedCandidate(Response response)
    {
        Attribute attribute
            = response.getAttribute(Attribute.XOR_RELAYED_ADDRESS);

        if (attribute instanceof XorRelayedAddressAttribute)
        {
            TransportAddress relayedAddress
                = ((XorRelayedAddressAttribute) attribute).getAddress(
                        response.getTransactionID());
            RelayedCandidate relayedCandidate
                = createRelayedCandidate(
                        relayedAddress,
                        getMappedAddress(response));

            if (relayedCandidate != null)
                addCandidate(relayedCandidate);
        }
    }

    /**
     * Creates a new <tt>RelayedCandidate</tt> instance which is to represent a
     * specific <tt>TransportAddress</tt> harvested through
     * {@link #hostCandidate} and the TURN server associated with
     * {@link #harvester}.
     *
     * @param transportAddress the <tt>TransportAddress</tt> to be represented
     * by the new <tt>RelayedCandidate</tt> instance
     * @param mappedAddress the mapped <tt>TransportAddress</tt> reported by the
     * TURN server with the delivery of the relayed <tt>transportAddress</tt> to
     * be represented by the new <tt>RelayedCandidate</tt> instance
     * @return a new <tt>RelayedCandidate</tt> instance which represents the
     * specified <tt>TransportAddress</tt> harvested through
     * {@link #hostCandidate} and the TURN server associated with
     * {@link #harvester}
     */
    protected RelayedCandidate createRelayedCandidate(
            TransportAddress transportAddress,
            TransportAddress mappedAddress)
    {
        return
            new RelayedCandidate(
                    transportAddress,
                    this,
                    mappedAddress);
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
     * @see StunCandidateHarvest#createRequestToRetry(Request)
     */
    @Override
    protected Request createRequestToRetry(Request request)
    {
        switch (request.getMessageType())
        {
        case Message.ALLOCATE_REQUEST:
            RequestedTransportAttribute requestedTransportAttribute
                = (RequestedTransportAttribute)
                    request.getAttribute(Attribute.REQUESTED_TRANSPORT);
            int requestedTransport
                = (requestedTransportAttribute == null)
                    ? 17 /* User Datagram Protocol */
                    : requestedTransportAttribute.getRequestedTransport();
            EvenPortAttribute evenPortAttribute
                = (EvenPortAttribute) request.getAttribute(Attribute.EVEN_PORT);
            boolean rFlag
                = (evenPortAttribute == null)
                    ? false
                    : evenPortAttribute.isRFlag();

            return
                MessageFactory.createAllocateRequest(
                        (byte) requestedTransport,
                        rFlag);
        default:
            return super.createRequestToRetry(request);
        }
    }

    /**
     * Creates a new <tt>Request</tt> which is to be sent to {@link #stunServer}
     * in order to start resolving {@link #hostCandidate}.
     *
     * @return a new <tt>Request</tt> which is to be sent to {@link #stunServer}
     * in order to start resolving {@link #hostCandidate}
     * @see StunCandidateHarvest#createRequestToStartResolvingCandidate()
     */
    @Override
    protected Request createRequestToStartResolvingCandidate()
    {
        if (requestToStartResolvingCandidate == null)
        {
            requestToStartResolvingCandidate
                = MessageFactory.createAllocateRequest(
                        (byte) 17 /* User Datagram Protocol */,
                        false);
            return requestToStartResolvingCandidate;
        }
        else if (requestToStartResolvingCandidate.getMessageType()
                == Message.ALLOCATE_REQUEST)
        {
            requestToStartResolvingCandidate
                = super.createRequestToStartResolvingCandidate();
            return requestToStartResolvingCandidate;
        }
        else
            return null;
    }
}
