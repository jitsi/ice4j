/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ice4j.ice;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.message.*;
import org.ice4j.security.*;
import org.ice4j.stack.*;
import org.jitsi.utils.logging2.*;

/**
 * The class that would be handling and responding to incoming connectivity
 * checks.
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 */
class ConnectivityCheckServer
    implements RequestListener,
               CredentialsAuthority
{
    /**
     * The agent that created us.
     */
    private final Agent parentAgent;

    /**
     * The indicator which determines whether this
     * <tt>ConnectivityCheckServer</tt> is currently started.
     */
    private boolean started = false;

    /**
     * The <tt>StunStack </tt> that we will use for connectivity checks.
     */
    private final StunStack stunStack;

    /**
     * A flag that determines whether we have received a STUN request or not.
     */
    private boolean alive = false;

    /**
     * The {@link Logger} used by {@link ConnectivityCheckServer} instances.
     */
    private Logger logger;

    /**
     * Creates a new <tt>ConnectivityCheckServer</tt> setting
     * <tt>parentAgent</tt> as the agent that will be used for retrieving
     * information such as user fragments for example.
     *
     * @param parentAgent the <tt>Agent</tt> that is creating this instance.
     */
    public ConnectivityCheckServer(Agent parentAgent)
    {
        this.parentAgent = parentAgent;
        logger = parentAgent.getLogger().createChildLogger(this.getClass().getName());

        stunStack = this.parentAgent.getStunStack();
        stunStack.getCredentialsManager().registerAuthority(this);

        start();
    }

    /**
     * Returns a boolean value indicating whether we have received a STUN
     * request or not.
     *
     * Note that this should NOT be taken as an indication that the negotiation
     * has succeeded, it merely indicates that we have received ANY STUN
     * request, even invalid ones (e.g. with the wrong username or ufrag). It is
     * completely unrelated/independent from the ICE spec and it's only meant to
     * be used for debugging purposes.
     *
     * @return a boolean value indicating whether we have received a STUN
     * request or not.
     */
    boolean isAlive()
    {
        return alive;
    }

    /**
     * Handles the {@link Request} delivered in <tt>evt</tt> by possibly
     * queuing a triggered check and sending a success or an error response
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
        logger.trace(() -> "Received request " + evt);

        alive = true;

        Request request = (Request)evt.getMessage();

        //ignore incoming requests that are not meant for the local user.
        //normally the stack will get rid of faulty user names but we could
        //still see messages not meant for this server if both peers or running
        //on this same instance of the stack.
        UsernameAttribute uname = (UsernameAttribute)request
            .getAttribute(Attribute.USERNAME);

        if(   uname == null
           ||  !checkLocalUserName(new String(uname.getUsername())))
        {
            return;
        }

        //detect role conflicts
        if( ( parentAgent.isControlling()
                    && request.containsAttribute(Attribute.ICE_CONTROLLING))
            || ( ! parentAgent.isControlling()
                        && request.containsAttribute(Attribute.ICE_CONTROLLED)))
        {
            if (!repairRoleConflict(evt))
                return;
        }

        long priority = 0;
        boolean useCandidate
            = request.containsAttribute(Attribute.USE_CANDIDATE);
        String username = new String(uname.getUsername());
        //caller gave us the entire username.
        String remoteUfrag = null;
        String localUFrag = null;

        priority = extractPriority(request);
        int colon = username.indexOf(":");
        remoteUfrag = username.substring(0, colon);

        //tell our address handler we saw a new remote address;
        parentAgent.incomingCheckReceived(evt.getRemoteAddress(),
                evt.getLocalAddress(), priority, remoteUfrag, localUFrag,
                useCandidate);

        Response response = MessageFactory.createBindingResponse(
                        request, evt.getRemoteAddress());

        /* add USERNAME and MESSAGE-INTEGRITY attribute in the response */

        /* The responses utilize the same usernames and passwords as the
         * requests
         */
        Attribute usernameAttribute =
            AttributeFactory.createUsernameAttribute(uname.getUsername());
        response.putAttribute(usernameAttribute);

        Attribute messageIntegrityAttribute =
            AttributeFactory.createMessageIntegrityAttribute(
                    new String(uname.getUsername()));
        response.putAttribute(messageIntegrityAttribute);

        try
        {
            stunStack.sendResponse(evt.getTransactionID().getBytes(),
                    response, evt.getLocalAddress(), evt.getRemoteAddress());
        }
        catch (Exception e)
        {
            logger.info("Failed to send " + response
                        + " through " + evt.getLocalAddress() + "\n" +
                        e.toString());
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
            logger.debug(() -> "Received a connectivity check with"
                    + "no PRIORITY attribute. Discarding.");

            throw new IllegalArgumentException("Missing PRIORITY attribute!");
        }

        return priorityAttr.getPriority();
    }

    /**
     * Resolves a role conflicts by either sending a <tt>487 Role Conflict</tt>
     * response or by changing this server's parent agent role. The method
     * returns <tt>true</tt> if the role conflict is silently resolved and
     * processing can continue. It returns <tt>false</tt> if we had to reply
     * with a 487 and processing needs to stop until a repaired request is
     * received.
     *
     * @param evt the {@link StunMessageEvent} containing the
     * <tt>ICE-CONTROLLING</tt> or <tt>ICE-CONTROLLED</tt> attribute that
     * allowed us to detect the role conflict.
     *
     * @return <tt>true</tt> if the role conflict is silently resolved and
     * processing can continue and <tt>false</tt> otherwise.
     */
    private boolean repairRoleConflict(StunMessageEvent evt)
    {
        final Message req = evt.getMessage();
        final boolean selfIceControlling = parentAgent.isControlling();

        // If the agent is in the controlling role, and the
        // ICE-CONTROLLING attribute is present in the request:
        final boolean bothControllingConflict = selfIceControlling &&
            req.containsAttribute(Attribute.ICE_CONTROLLING);

        // If the agent is in the controlled role, and the ICE-CONTROLLED
        // attribute is present in the request:
        final boolean bothControlledConflict = !selfIceControlling &&
            req.containsAttribute(Attribute.ICE_CONTROLLED);

        if (!(bothControllingConflict || bothControlledConflict)) {
            // we don't have a role conflict
            return true;
        }

        final long selfTieBreaker = parentAgent.getTieBreaker();

        final IceControlAttribute theirIceControl = bothControllingConflict
            ? (IceControlAttribute)req.getAttribute(Attribute.ICE_CONTROLLING)
            : (IceControlAttribute)req.getAttribute(Attribute.ICE_CONTROLLED);

        final long theirTieBreaker = theirIceControl.getTieBreaker();

        // If the agent's tie-breaker is larger than or equal to the
        // contents of the ICE control attribute, the agent generates
        // a Binding error response and includes an ERROR-CODE attribute
        // with a value of 487 (Role Conflict) but retains its role.
        if (Long.compareUnsigned(selfTieBreaker, theirTieBreaker) >= 0)
        {
            final UsernameAttribute requestUserName = (UsernameAttribute)req
                .getAttribute(Attribute.USERNAME);

            final Response response =
                MessageFactory.createBindingErrorResponse(
                    ErrorCodeAttribute.ROLE_CONFLICT);

            final Attribute messageIntegrityAttribute =
                AttributeFactory.createMessageIntegrityAttribute(
                    new String(requestUserName.getUsername()));
            response.putAttribute(messageIntegrityAttribute);

            try
            {
                stunStack.sendResponse(
                    evt.getTransactionID().getBytes(),
                    response,
                    evt.getLocalAddress(),
                    evt.getRemoteAddress());
                return false;
            }
            catch(Exception exc)
            {
                //rethrow so that we would send a 500 response instead.
                throw new RuntimeException("Failed to send a 487", exc);
            }
        }
        //If the agent's tie-breaker is less than the contents of the
        //ICE control attribute, the agent toggles its ICE control role.
        else
        {
            final String selfNextControlState
                = selfIceControlling ? "controlled" : "controlling";
            logger.trace(() ->
                "Switching to " + selfNextControlState + " because " +
                " theirTieBreaker= " + theirTieBreaker + " and " +
                "selfTieBreaker= " + selfTieBreaker);
            parentAgent.setControlling(!selfIceControlling);
            return true;
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
        String ufrag = null;

        int colon = username.indexOf(":");

        if (colon < 0)
        {
            //caller gave us a ufrag
            ufrag = username;
        }
        else
        {
            //caller gave us the entire username.
            ufrag = username.substring(0, colon);
        }

        return ufrag.equals(parentAgent.getLocalUfrag());
    }

    /**
     * Implements the {@link CredentialsAuthority#getLocalKey(String)} method in
     * a way that would return this handler's parent agent password if
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
        return
            checkLocalUserName(username)
                ? parentAgent.getLocalPassword().getBytes()
                : null;
    }

    /**
     * Implements the {@link CredentialsAuthority#getRemoteKey(String, String)}
     * method in a way that would return this handler's parent agent remote
     * password if <tt>username</tt> is either the remote ufrag or the username
     * that we are expected to use when querying the remote peer.
     *
     * @param username the remote ufrag that we should return a password for.
     * @param media the media name that we want to get remote key.
     *
     * @return this handler's parent agent remote password if <tt>username</tt>
     * equals the remote ufrag and <tt>null</tt> otherwise.
     */
    public byte[] getRemoteKey(String username, String media)
    {
        IceMediaStream stream = parentAgent.getStream(media);
        if(stream == null)
        {
            return null;
        }

        //support both the case where username is the local fragment or the
        //entire user name.
        int colon = username.indexOf(":");

        if (colon < 0)
        {
            //caller gave us a ufrag
            if (username.equals(stream.getRemoteUfrag()))
                return stream.getRemotePassword().getBytes();
        }
        else
        {
            //caller gave us the entire username.
            if (username.equals(parentAgent.generateLocalUserName(media)))
            {
                if(stream.getRemotePassword() != null)
                    return stream.getRemotePassword().getBytes();
            }
        }
        return null;
    }

    /**
     * Starts this <tt>ConnectivityCheckServer</tt>. If it is not currently
     * running, does nothing.
     */
    public void start()
    {
        if (!started)
        {
            stunStack.addRequestListener(this);
            started = true;
        }
    }

    /**
     * Stops this <tt>ConnectivityCheckServer</tt>. A stopped
     * <tt>ConnectivityCheckServer</tt> can be restarted by calling
     * {@link #start()} on it.
     */
    public void stop()
    {
        stunStack.removeRequestListener(this);
        started = false;
    }
}
