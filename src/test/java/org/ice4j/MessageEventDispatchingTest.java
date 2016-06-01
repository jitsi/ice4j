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
package org.ice4j;

import java.util.*;

import junit.framework.*;

import org.ice4j.message.*;
import org.ice4j.socket.*;
import org.ice4j.stack.*;

/**
 * Test event dispatching for both client and server.
 *`
 * @author Emil Ivov
 */
public class MessageEventDispatchingTest extends TestCase
{
    /**
     * The stack that we are using for the tests.
     */
    StunStack stunStack = null;

    /**
     * The address of the client.
     */
    TransportAddress clientAddress
        = new TransportAddress("127.0.0.1", 5216, Transport.UDP);

    /**
     * The Address of the server.
     */
    TransportAddress serverAddress
        = new TransportAddress("127.0.0.1", 5255, Transport.UDP);

    /**
     * The address of the second server.
     */
    TransportAddress serverAddress2
        = new TransportAddress("127.0.0.1", 5259, Transport.UDP);

    /**
     * The socket that the client is using.
     */
    IceSocketWrapper  clientSock = null;

    /**
     * The socket that the server is using
     */
    IceSocketWrapper  serverSock = null;

    /**
     * The second server socket.
     */
    IceSocketWrapper serverSock2 = null;

    /**
     * The request that we will be sending in this test.
     */
    Request  bindingRequest = null;

    /**
     * The response that we will be sending in response to the above request.
     */
    Response bindingResponse = null;

    /**
     * The request collector that we use to wait for requests.
     */
    PlainRequestCollector requestCollector = null;

    /**
     * The responses collector that we use to wait for responses.
     */
    PlainResponseCollector responseCollector = null;

    /**
     * junit setup method.
     *
     * @throws Exception if anything goes wrong.
     */
    protected void setUp() throws Exception
    {
        super.setUp();

        stunStack = new StunStack();

        clientSock = new IceUdpSocketWrapper(
            new SafeCloseDatagramSocket(clientAddress));
        serverSock = new IceUdpSocketWrapper(
            new SafeCloseDatagramSocket(serverAddress));
        serverSock2 = new IceUdpSocketWrapper(
            new SafeCloseDatagramSocket(serverAddress2));

        stunStack.addSocket(clientSock);
        stunStack.addSocket(serverSock);
        stunStack.addSocket(serverSock2);

        bindingRequest = MessageFactory.createBindingRequest();
        bindingResponse = MessageFactory.create3489BindingResponse(
            clientAddress, clientAddress, serverAddress);

        requestCollector = new PlainRequestCollector();
        responseCollector = new PlainResponseCollector();

    }

    /**
     * junit tear down method.
     *
     * @throws Exception if anything goes wrong.
     */
    protected void tearDown() throws Exception
    {
        stunStack.removeSocket(clientAddress);
        stunStack.removeSocket(serverAddress);
        stunStack.removeSocket(serverAddress2);

        clientSock.close();
        serverSock.close();
        serverSock2.close();

        requestCollector = null;
        responseCollector = null;

        super.tearDown();
    }

    /**
     * Test timeout events.
     *
     * @throws Exception upon a stun failure
     */
    public void testClientTransactionTimeouts() throws Exception
    {
        String oldRetransValue = System.getProperty(
                        StackProperties.MAX_CTRAN_RETRANSMISSIONS);
        System.setProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS, "1");
        stunStack.sendRequest(bindingRequest, serverAddress, clientAddress,
                        responseCollector);
        responseCollector.waitForTimeout();

        assertEquals(
            "No timeout was produced upon expiration of a client transaction",
            responseCollector.receivedResponses.size(), 1);

        assertEquals(
            "No timeout was produced upon expiration of a client transaction",
            responseCollector.receivedResponses.get(0), "timeout");

        //restore the retransmissions prop in case others are counting on
        //defaults.
        if(oldRetransValue != null)
            System.getProperty( StackProperties.MAX_CTRAN_RETRANSMISSIONS,
                                oldRetransValue);
        else
            System.clearProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS);
    }

    /**
     * Test reception of Message events.
     *
     * @throws java.lang.Exception upon any failure
     */
    public void testEventDispatchingUponIncomingRequests() throws Exception
    {
        //prepare to listen
        stunStack.addRequestListener(requestCollector);
        //send
        stunStack.sendRequest(bindingRequest, serverAddress, clientAddress,
                                            responseCollector);
        //wait for retransmissions
        requestCollector.waitForRequest();

        //verify
        assertTrue("No MessageEvents have been dispatched",
            requestCollector.receivedRequests.size() == 1);
    }

    /**
     * Test that reception of Message events is only received for accesspoints
     * that we have been registered for.
     *
     * @throws java.lang.Exception upon any failure
     */
    public void testSelectiveEventDispatchingUponIncomingRequests()
        throws Exception
    {
        //prepare to listen
        stunStack.addRequestListener(serverAddress, requestCollector);

        PlainRequestCollector requestCollector2 = new PlainRequestCollector();
        stunStack.addRequestListener(serverAddress2, requestCollector2);

        //send
        stunStack.sendRequest(bindingRequest, serverAddress2, clientAddress,
                                            responseCollector);
        //wait for retransmissions
        requestCollector.waitForRequest();
        requestCollector2.waitForRequest();

        //verify
        assertTrue(
            "A MessageEvent was received by a non-interested selective listener",
            requestCollector.receivedRequests.size() == 0);
        assertTrue(
            "No MessageEvents have been dispatched for a selective listener",
            requestCollector2.receivedRequests.size() == 1);
    }


    /**
     * Makes sure that we receive response events.
     * @throws Exception if we screw up.
     */
    public void testServerResponseRetransmissions() throws Exception
    {
        //prepare to listen
        stunStack.addRequestListener(serverAddress, requestCollector);
        //send
        stunStack.sendRequest(bindingRequest, serverAddress, clientAddress,
                                            responseCollector);

        //wait for the message to arrive
        requestCollector.waitForRequest();

        StunMessageEvent evt = requestCollector.receivedRequests.get(0);
        byte[] tid = evt.getMessage().getTransactionID();
        stunStack.sendResponse(tid, bindingResponse, serverAddress,
                                             clientAddress);

        //wait for retransmissions
        responseCollector.waitForResponse();

        //verify that we got the response.
        assertTrue(
            "There were no retransmissions of a binding response",
            responseCollector.receivedResponses.size() == 1 );
    }

    /**
     * A utility class we use to collect incoming requests.
     */
    private class PlainRequestCollector implements RequestListener
    {
        /** all requests we've received so far. */
        public final Vector<StunMessageEvent> receivedRequests = new Vector<>();

        /**
         * Stores incoming requests.
         *
         * @param evt the event containing the incoming request.
         */
        public void processRequest(StunMessageEvent evt)
        {
            synchronized (this)
            {
                receivedRequests.add(evt);
                notifyAll();
            }
        }

        public void waitForRequest()
        {
            synchronized(this)
            {
                if (receivedRequests.size() > 0)
                    return;
                try
                {
                    wait(50);
                }
                catch (InterruptedException e)
                {}
            }
        }
    }

    /**
     * A utility class to collect incoming responses.
     */
    private static class PlainResponseCollector
        extends AbstractResponseCollector
    {
        public final Vector<Object> receivedResponses = new Vector<>();

        /**
         * Notifies this <tt>ResponseCollector</tt> that a transaction described by
         * the specified <tt>BaseStunMessageEvent</tt> has failed. The possible
         * reasons for the failure include timeouts, unreachable destination, etc.
         *
         * @param event the <tt>BaseStunMessageEvent</tt> which describes the failed
         * transaction and the runtime type of which specifies the failure reason
         * @see AbstractResponseCollector#processFailure(BaseStunMessageEvent)
         */
        protected synchronized void processFailure(BaseStunMessageEvent event)
        {
            String receivedResponse;

            if (event instanceof StunFailureEvent)
                receivedResponse = "unreachable";
            else if (event instanceof StunTimeoutEvent)
                receivedResponse = "timeout";
            else
                receivedResponse = "failure";
            receivedResponses.add(receivedResponse);
            notifyAll();
        }

        /**
         * Stores incoming responses.
         *
         * @param response a <tt>StunMessageEvent</tt> which describes the
         * received STUN <tt>Response</tt>
         */
        public synchronized void processResponse(StunResponseEvent response)
        {
            receivedResponses.add(response);
            notifyAll();
        }

        /**
         * Waits for a short period of time for a response to arrive
         */
        public synchronized void waitForResponse()
        {
            try
            {
                if (receivedResponses.size() == 0)
                    wait(50);
            }
            catch (InterruptedException e)
            {
            }
        }

        /**
         * Waits for a long period of time for a timeout trigger to fire.
         */
        public synchronized void waitForTimeout()
        {
            try
            {
                if (receivedResponses.size() == 0)
                    wait(12000);
            }
            catch (InterruptedException e)
            {
            }
        }
    }
}
