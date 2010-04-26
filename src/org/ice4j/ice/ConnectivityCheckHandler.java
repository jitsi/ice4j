/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.io.*;
import java.net.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.message.*;
import org.ice4j.security.*;
import org.ice4j.socket.*;
import org.ice4j.stack.*;

/**
 * @author Emil Ivov
 */
public class ConnectivityCheckHandler
    implements ResponseCollector,
               RequestListener,
               CredentialsAuthority
{
    /**
     * The <tt>Logger</tt> used by the <tt>ConnectivityCheckClient</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger = Logger
                    .getLogger(ConnectivityCheckHandler.class.getName());

    /**
     * The agent that created us.
     */
    private final Agent parentAgent;

    /**
     * The stun stack that we will use for connectivity checks.
     */
    StunStack stunStack = StunStack.getInstance();

    /**
     * The <tt>DatagramPacketFilter</tt> that only accepts STUN messages.
     */
    private DatagramPacketFilter stunDatagramPacketFilter;

    /**
     * Creates a new <tt>ConnectivityCheckHandler</tt> setting
     * <tt>parentAgent</tt> as the agent that will be used for retrieving
     * information such as user fragments for example.
     *
     * @param parentAgent the <tt>Agent</tt> that is creating this instance.
     */
    public ConnectivityCheckHandler(Agent parentAgent)
    {
        this.parentAgent = parentAgent;
        stunStack.addRequestListener(this);
        stunStack.getCredentialsManager().registerAuthority(this);
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
                            parentAgent.getRemotePassword().getBytes());


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

    public void requestReceived(StunMessageEvent evt)
    {
        Request request = (Request)evt.getMessage();

        //check the user name
        if(! checkUserName(request))
            return;

        //check message integrity.

        Response response = MessageFactory.createBindingResponse(
                        request, evt.getRemoteAddress());
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

    /**
     * Verifies whether <tt>request</tt> comes with the proper username and
     * returns <tt>true</tt> if it does and <tt>false</tt> otherwise.
     *
     * @param request the <tt>Request</tt> that we'd like to check for a
     * proper username.
     *
     * @return <tt>true</tt> if the <tt>request</tt> contains the proper user
     * name and false otherwise.
     */
    public boolean checkUserName(Request request)
    {
        UsernameAttribute unameAttr
            = (UsernameAttribute)request.getAttribute(Attribute.USERNAME);

        if (unameAttr == null)
        {
            if(logger.isLoggable(Level.FINE))
            {
                logger.log(Level.FINE, "Received a request without a USERNAME");
            }
            return false;
        }

        String username = new String(unameAttr.getUsername());
        int colon = username.indexOf(":");
        if( username.length() < 1
            || colon < 1)
        {
            if(logger.isLoggable(Level.FINE))
            {
                logger.log(Level.FINE, "Received a request with an improperly "
                            +"formatted username");
            }
            return false;
        }

        String lfrag = username.substring(0, colon);

        if( !lfrag.equals(parentAgent.getLocalUfrag()))
        {
            if(logger.isLoggable(Level.FINE))
            {
                logger.log(Level.FINE, "Remote peer using a wrong user name: "
                                       + username);
            }
            return false;
        }

        return true;
    }

    /**
     * Implements the {@link CredentialsAuthority#getKey(String)} method in a
     * way that would return this handler's parent agent password if
     * <tt>username</tt> is either the local ufrag or the username that the
     * agent's remote peer was expected to use.
     *
     * @param username the local ufrag that we should return a password for.
     *
     * @return this handler's parent agent local password if <tt>username</tt>
     * equals the local ufrag and <tt>null</tt> otherwise.
     */
    public byte[] getKey(String username)
    {
        //support both the case where username is the local fragment or the
        //entire user name.
        int colon = username.indexOf(":");
        if( colon < 0)
        {
            //caller gave us a ufrag
            if (username.equals(parentAgent.getLocalUfrag()))
                return parentAgent.getLocalPassword().getBytes();
        }
        else
        {
            //caller gave us the entire username.
            if (username.equals(parentAgent.generateRemoteUserName()))
                return parentAgent.getLocalPassword().getBytes();
        }

        return null;
    }
}
