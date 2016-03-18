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
package org.ice4j.stunclient;

import java.io.*;
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
 * @author Emil Ivov
 */
public class ResponseSequenceServer
    implements RequestListener
{
    /**
     * The <tt>Logger</tt> used by the <tt>ResponseSequenceServer</tt> class and
     * its instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(ResponseSequenceServer.class.getName());

    /**
     * The sequence of responses to send.
     */
    private Vector<Object> messageSequence = new Vector<>();

    /**
     * The <tt>StunStack</tt> used by this instance for the purposes of STUN
     * communication.
     */
    private final StunStack stunStack;

    private TransportAddress serverAddress = null;
    private IceSocketWrapper localSocket = null;

    /**
     * Initializes a new <tt>ResponseSequenceServer</tt> instance with a
     * specific <tt>StunStack</tt> to be used for the purposes of STUN
     * communication.
     *
     * @param stunStack the <tt>StunStack</tt> to be used by the new instance
     * for the purposes of STUN communication
     * @param bindAddress
     */
    public ResponseSequenceServer(
            StunStack stunStack,
            TransportAddress bindAddress)
    {
        this.stunStack = stunStack;
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
        localSocket = new IceUdpSocketWrapper(
            new SafeCloseDatagramSocket(serverAddress));

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
            messageSequence.add(false);
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
    public void processRequest(StunMessageEvent evt)
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
