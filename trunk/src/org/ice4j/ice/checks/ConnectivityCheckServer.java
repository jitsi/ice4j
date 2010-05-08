/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice.checks;

import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.ice.*;
import org.ice4j.message.*;
import org.ice4j.security.*;
import org.ice4j.stack.*;
/**
 * @author Emil Ivov
 */
public class ConnectivityCheckServer
    implements RequestListener,
               CredentialsAuthority
{
    /**
     * The <tt>Logger</tt> used by the <tt>ConnectivityCheckServer</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger = Logger
                    .getLogger(ConnectivityCheckServer.class.getName());

    /**
     * The agent that created us.
     */
    private final Agent parentAgent;

    /**
     * The {@link IncomingCheckProcessor} that we should notify when we notice
     * new remote transport addresses.
     */
    private final IncomingCheckProcessor addressHandler;

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
                                          = new Vector<CandidatePair>();

    /**
     * Creates a new <tt>ConnectivityCheckServer</tt> setting
     * <tt>parentAgent</tt> as the agent that will be used for retrieving
     * information such as user fragments for example.
     *
     * @param parentAgent the <tt>Agent</tt> that is creating this instance.
     * @param addressHandler the handler that
     */
    public ConnectivityCheckServer(Agent                parentAgent,
                                   IncomingCheckProcessor addressHandler)
    {
        this.parentAgent = parentAgent;
        this.addressHandler = addressHandler;
        stunStack.addRequestListener(this);
        stunStack.getCredentialsManager().registerAuthority(this);
    }

    /**
     * Handles the {@link Request} delivered in <tt>evt</tt> by possibly
     * queueing a triggered check and sending a success or or error response
     * depending on how processing goes.
     *
     * @param evt the {@link StunMessageEvent} containing the {@link Request}
     * that we need to process.
     *
     * @throws IllegalArgumentException if the request is malformed and the
     * stack needs to reply with a 400 Bad Request response.
     */
    public void processRequest(StunMessageEvent evt)
        throws IllegalArgumentException
    {
        Request request = (Request)evt.getMessage();

        //ignore incoming requests that are not meant for the local user.
        //normally the stack will get rid of faulty user names but we could
        //still see messages not meant for this server if both peers or running
        //on this same instance of the stack.
        UsernameAttribute uname = (UsernameAttribute)request
            .getAttribute(Attribute.USERNAME);

        if(uname == null
           || !checkLocalUserName(new String(uname.getUsername())))
        {
            return;
        }

        String username = new String(uname.getUsername());
        int colon = username.indexOf(":");

        //caller gave us the entire username.
        String remoteUfrag = username.substring(0, colon);

        //make sure we have a priority attribute and ignore otherwise.
        PriorityAttribute priorityAttr
            = (PriorityAttribute)request.getAttribute(Attribute.PRIORITY);

        //extract priority
        if(priorityAttr == null)
        {
            if(logger.isLoggable(Level.FINE))
            {
                logger.log(Level.FINE, "Received a connectivity ckeck with"
                            +"no PRIORITY attribute. Discarting.");
            }

            throw new IllegalArgumentException("Missing PRIORITY attribtue!");
        }

        long priority = priorityAttr.getPriority();

        //tell our address handler we saw a new remote address;
        addressHandler.incomingCheckReceived(evt.getRemoteAddress(),
                                         evt.getLocalAddress(),
                                         priority, remoteUfrag);

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
     * Verifies whether <tt>username</tt> is currently known to this server
     * and returns <tt>true</tt> if so. Returns <tt>false</tt> otherwise.
     *
     * @param username the user name whose validity we'd like to check.
     *
     * @return <tt>true</tt> if <tt>username</tt> is known to this
     * <tt>ConnectivityCheckServer</tt> and <tt>false</tt> otherwise.
     */
    public boolean checkLocalUserName(String username)
    {
        boolean accept = false;
        int colon = username.indexOf(":");
        if( colon < 0)
        {
            //caller gave us a ufrag
            if(username.equals(parentAgent.getLocalUfrag()))
                accept = true;
        }
        else
        {
            //caller gave us the entire username.
            if(username.substring(0, colon).equals(parentAgent.getLocalUfrag()))
                accept = true;
        }
        return accept;
    }

    /**
     * Implements the {@link CredentialsAuthority#getLocalKey(String)} method in a
     * way that would return this handler's parent agent password if
     * <tt>username</tt> is either the local ufrag or the username that the
     * agent's remote peer was expected to use.
     *
     * @param username the local ufrag that we should return a password for.
     *
     * @return this handler's parent agent local password if <tt>username</tt>
     * equals the local ufrag and <tt>null</tt> otherwise.
     */
    public byte[] getLocalKey(String username)
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
            if(username.substring(0, colon).equals(parentAgent.getLocalUfrag()))
                return parentAgent.getLocalPassword().getBytes();
        }

        return null;
    }

    /**
     * Implements the {@link CredentialsAuthority#getRemoteKey(String)} method
     * in a way that would return this handler's parent agent remote password if
     * <tt>username</tt> is either the remote ufrag or the username that we
     * are expected to use when querying the remote peer.
     *
     * @param username the remote ufrag that we should return a password for.
     *
     * @return this handler's parent agent remote password if <tt>username</tt>
     * equals the remote ufrag and <tt>null</tt> otherwise.
     */
    public byte[] getRemoteKey(String username)
    {
        //support both the case where username is the local fragment or the
        //entire user name.
        int colon = username.indexOf(":");
        if( colon < 0)
        {
            //caller gave us a ufrag
            if (username.equals(parentAgent.getRemoteUfrag()))
                return parentAgent.getRemotePassword().getBytes();
        }
        else
        {
            //caller gave us the entire username.
            if (username.equals(parentAgent.generateLocalUserName()))
                return parentAgent.getRemotePassword().getBytes();
        }

        return null;
    }
}
