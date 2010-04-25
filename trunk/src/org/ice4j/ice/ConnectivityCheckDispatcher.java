/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.net.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.message.*;
import org.ice4j.socket.*;
import org.ice4j.stack.*;

/**
 * @author Emil Ivov
 */
public class ConnectivityCheckDispatcher
    implements ResponseCollector, RequestListener
{
    /**
     * The <tt>Logger</tt> used by the <tt>ConnectivityCheckClient</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger = Logger
                    .getLogger(ConnectivityCheckDispatcher.class.getName());

    private final Agent parentAgent;

    /**
     * The stun stack that we will use for connectivity checks.
     */
    StunStack stunStack = StunStack.getInstance();

    /**
     * The <tt>DatagramPacketFilter</tt> that only accepts STUN messages.
     */
    private DatagramPacketFilter stunDatagramPacketFilter;

    public ConnectivityCheckDispatcher(Agent parentAgent)
    {
        stunStack.addRequestListener(this);
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
        UsernameAttribute unameAttr = AttributeFactory.createUsernameAttribute(
                        parentAgent.generateLocalUserName());

        request.addAttribute(unameAttr);

        //todo: do this in the stun stack so that we could do the
        //calculation once the request is ready (we'd need the transaction id
        //for example.
        //todo: also implement SASL prepare
        MessageIntegrityAttribute msgIntegrity
            = AttributeFactory.createMessageIntegrityAttribute(
                            parentAgent.getPassword().getBytes());


        request.addAttribute(msgIntegrity);

        TransactionID tran;

        try
        {


            tran = stunStack.sendRequest(request,
                    pair.getRemoteCandidate().getTransportAddress(), stunSocket,
                    this);

System.out.println("checking pair " + pair + " with tran=" + tran.toString());
        }
        catch (Exception exception)
        {
            logger.log(
                    Level.INFO,
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

    int i;
    public void requestReceived(StunMessageEvent evt)
    {
        Response response = MessageFactory.createBindingResponse(
                            (Request)evt.getMessage(), evt.getRemoteAddress());

        try
        {
            stunStack.sendResponse(evt.getTransactionID().getTransactionID(),
                response, evt.getLocalAddress(), evt.getRemoteAddress());
        }
        catch (Exception e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
