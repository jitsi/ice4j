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
    StunStack stunStack = StunStack.getInstance();

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
        stunStack.addRequestListener(this);
        stunStack.getCredentialsManager().registerAuthority(this);
    }

    public void requestReceived(StunMessageEvent evt)
    {
        Request request = (Request)evt.getMessage();

        //ignore incoming requests that are not meant for the local user.
        //normally the stack will get rid of faulty user names but we could
        //still see messages not meant for this server if both peers or running
        //on this same instance of the stack.
        UsernameAttribute uname = (UsernameAttribute)request
            .getAttribute(Attribute.USERNAME);

        if(uname == null
           || !checkUserName(new String(uname.getUsername())))
        {
            return;
        }

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
     * Verifies whether <tt>username</tt> is currently known to this server
     * and returns <tt>true</tt> if so. Returns <tt>false</tt> otherwise.
     *
     * @param username the user name whose validity we'd like to check.
     *
     * @return <tt>true</tt> if <tt>username</tt> is known to this
     * <tt>ConnectivityCheckServer</tt> and <tt>false</tt> otherwise.
     */
    public boolean checkUserName(String username)
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
