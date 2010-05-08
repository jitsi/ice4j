/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

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
     * The stun stack that we will use for connectivity checks.
     */
    private StunStack stunStack = StunStack.getInstance();

    /**
     * Creates a new <tt>ConnectivityCheckServer</tt> setting
     * <tt>parentAgent</tt> as the agent that will be used for retrieving
     * information such as user fragments for example.
     *
     * @param parentAgent the <tt>Agent</tt> that is creating this instance.
     */
    public ConnectivityCheckServer(Agent                parentAgent)
    {
        this.parentAgent = parentAgent;
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

        //detect role conflicts
        if( ( parentAgent.isControlling()
                        && request.contains(Attribute.ICE_CONTROLLING))
            || ( ! parentAgent.isControlling()
                            && request.contains(Attribute.ICE_CONTROLLED)))
        {
            repairRoleConflict(evt);
            return;
        }

        long priority = extractPriority(request);
        boolean useCandidate = request.contains(Attribute.USE_CANDIDATE);

        //tell our address handler we saw a new remote address;
        parentAgent.incomingCheckReceived(evt.getRemoteAddress(),
            evt.getLocalAddress(), priority, remoteUfrag, useCandidate);

        Response response = MessageFactory.createBindingResponse(
                        request, evt.getRemoteAddress());

        try
        {
            stunStack.sendResponse(evt.getTransactionID().getBytes(),
                response, evt.getLocalAddress(), evt.getRemoteAddress());
        }
        catch (Exception e)
        {
            //try to trigger a 500 response although if this one failed,
            //then chances are the 500 will fail too.
            throw new RuntimeException("Failed to send a response", e);
        }
    }

    /**
     * Returns the value of the {@link PriorityAttribute} in <tt>request</tt> if
     * there is one or throws an <tt>IllegalArgumentException</tt> with the
     * corresponding message.
     *
     * @param request the {@link Request} whose priority we'd like to obtain.
     *
     * @return the value of the {@link PriorityAttribute} in <tt>request</tt> if
     * there is one
     *
     * @throws IllegalArgumentException if the request does not contain a
     * PRIORITY attribute and the stack needs to respond with a 400 Bad Request
     * {@link Response}.
     */
    private long extractPriority(Request request)
        throws IllegalArgumentException
    {
        //make sure we have a priority attribute and ignore otherwise.
        PriorityAttribute priorityAttr
            = (PriorityAttribute)request.getAttribute(Attribute.PRIORITY);

        //apply tie-breaking

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

        return priorityAttr.getPriority();
    }

    /**
     * Resolves a role conflicts by either sendinf a <tt>487 Role Conflict</tt>
     * response or by changing this server's parent agent role.
     *
     * @param evt the {@link StunMessageEvent} containing the
     * <tt>ICE-CONTROLLING</tt> or <tt>ICE-CONTROLLED</tt> attribute that
     * allowed us to detect the role conflict.
     */
    private void repairRoleConflict(StunMessageEvent evt)
    {
        Message req = evt.getMessage();
        long ourTieBreaker = parentAgent.getTieBreaker();

        // If the agent is in the controlling role, and the
        // ICE-CONTROLLING attribute is present in the request:
        if(parentAgent.isControlling()
                        && req.contains(Attribute.ICE_CONTROLLING))
        {
            IceControllingAttribute controlling = (IceControllingAttribute)
                req.getAttribute(Attribute.ICE_CONTROLLING);

            long theirTieBreaker = controlling.getTieBreaker();

            // If the agent's tie-breaker is larger than or equal to the
            // contents of the ICE-CONTROLLING attribute, the agent generates
            // a Binding error response and includes an ERROR-CODE attribute
            // with a value of 487 (Role Conflict) but retains its role.
            if( ourTieBreaker >= theirTieBreaker)
            {
                Response response = MessageFactory.createBindingErrorResponse(
                                ErrorCodeAttribute.ROLE_CONFLICT);

                try
                {
                    StunStack.getInstance().sendResponse(
                                evt.getTransactionID().getBytes(),
                                response, evt.getLocalAddress(),
                                evt.getRemoteAddress());
                }
                catch(Exception exc)
                {
                    //rethrow so that we would send a 500 response instead.
                    throw new RuntimeException("Failed to send a 487", exc);
                }
            }
            //If the agent's tie-breaker is less than the contents of the
            //ICE-CONTROLLING attribute, the agent switches to the controlled
            //role.
            else
            {
                logger.finest(
                        "Swithing to controlled because theirTieBreaker="
                        + theirTieBreaker + " and ourTieBreaker="
                        + ourTieBreaker);
                parentAgent.setControlling(false);
            }
        }
        // If the agent is in the controlled role, and the ICE-CONTROLLED
        // attribute is present in the request:
        else if(!parentAgent.isControlling()
                        && req.contains(Attribute.ICE_CONTROLLED))
        {
            IceControllingAttribute controlled = (IceControllingAttribute)
                req.getAttribute(Attribute.ICE_CONTROLLED);

            long theirTieBreaker = controlled.getTieBreaker();

            //If the agent's tie-breaker is larger than or equal to the
            //contents of the ICE-CONTROLLED attribute, the agent switches to
            //the controlling role.
            if(ourTieBreaker >= theirTieBreaker)
            {
                logger.finest(
                        "Swithing to controlling because theirTieBreaker="
                        + theirTieBreaker + " and ourTieBreaker="
                        + ourTieBreaker);
                parentAgent.setControlling(true);
            }
            // If the agent's tie-breaker is less than the contents of the
            // ICE-CONTROLLED attribute, the agent generates a Binding error
            // response and includes an ERROR-CODE attribute with a value of
            // 487 (Role Conflict) but retains its role.
            else
            {
                Response response = MessageFactory.createBindingErrorResponse(
                            ErrorCodeAttribute.ROLE_CONFLICT);

                try
                {
                    StunStack.getInstance().sendResponse(
                                    evt.getTransactionID().getBytes(),
                                    response, evt.getLocalAddress(),
                                    evt.getRemoteAddress());
                }
                catch(Exception exc)
                {
                    //rethrow so that we would send a 500 response instead.
                    throw new RuntimeException("Failed to send a 487", exc);
                }
            }
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
