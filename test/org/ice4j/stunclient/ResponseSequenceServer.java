/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.stunclient;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.message.*;
import org.ice4j.socket.*;
import org.ice4j.stack.*;

/**
 * This class implements a programmable STUN server that sends predefined
 * sequences of responses. It may be used to test whether a STUN client
 * behaves correctly in different use cases.
 *
 *
 * <p>Organisation: <p> Louis Pasteur University, Strasbourg, France</p>
 * <p>Network Research Team (http://www-r2.u-strasbg.fr)</p></p>
 * @author Emil Ivov
 * @version 0.1
 */
public class ResponseSequenceServer
    implements RequestListener
{
    private static final Logger logger =
        Logger.getLogger(ResponseSequenceServer.class.getName());
    /**
     * The sequence of responses to send.
     */
    private Vector<Object> messageSequence = new Vector<Object>();

    private StunStack    stunStack    = null;

    private TransportAddress serverAddress = null;
    private DatagramSocket localSocket = null;

    public ResponseSequenceServer(TransportAddress bindAddress)
    {
        this.serverAddress = bindAddress;
    }

    /**
     * Initializes the underlying stack
     * @throws StunException if something else fails
     * @throws IOException if we fail to bind a local socket.
     */
    public void start()
        throws IOException, StunException
    {
        stunStack    = StunStack.getInstance();

        localSocket = new SafeCloseDatagramSocket(serverAddress);

        stunStack.addSocket(localSocket);
        stunStack.addRequestListener(serverAddress, this);

    }

    /**
     * Resets the server (deletes the sequence and stops the stack)
     */
    public void shutDown()
    {
        stunStack.removeSocket(serverAddress);
        messageSequence.removeAllElements();
        localSocket.close();

        stunStack    = null;
    }

    /**
     * Adds the specified response to this sequence or marks a pause (i.e. do
     * not respond) if response is null.
     * @param response the response to add or null to mark a pause
     */
    public void addMessage(Response response)
    {
        if (response == null)
        {
            //leave a mark to skip a message
            messageSequence.add(new Boolean(false));
        }
        else
            messageSequence.add(response);
    }

    /**
     * Completely ignores the event that is passed and just sends the next
     * message from the sequence - or does nothing if there's something
     * different from a Response on the current position.
     * @param evt the event being dispatched
     */
    public void requestReceived(StunMessageEvent evt)
    {
        if(messageSequence.isEmpty())
            return;
        Object obj = messageSequence.remove(0);

        if( !(obj instanceof Response) )
            return;

        Response res = (Response)obj;

        try
        {
            stunStack.sendResponse(evt.getMessage().getTransactionID(),
                res, serverAddress, evt.getRemoteAddress());
        }
        catch (Exception ex)
        {
            logger.log(Level.WARNING, "failed to send a response", ex);
        }

    }

    /**
     * Returns a string representation of this Server.
     * @return the ip address and port where this server is bound
     */
    public String toString()
    {
        return serverAddress == null?"null":serverAddress.toString();
    }

}
