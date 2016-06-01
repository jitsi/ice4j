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
 * Test how client and server behave, how they recognize/adopt messages and
 * how they both handle retransmissions (i.e. client transactions should make
 * them and server transactions should hide them)
 *
 * @author Emil Ivov
 */
public class TransactionSupportTests extends TestCase
{
    /**
     * The client address we use for this test.
     */
    TransportAddress clientAddress
        = new TransportAddress("127.0.0.1", 5216, Transport.UDP);

    /**
     * The client address we use for this test.
     */
    TransportAddress serverAddress
        = new TransportAddress("127.0.0.1", 5255, Transport.UDP);

    /**
     * The socket the client uses in this test.
     */
    IceSocketWrapper clientSock = null;

    /**
     * The socket the server uses in this test.
     */
    IceSocketWrapper serverSock = null;

    /**
     * The <tt>StunStack</tt> used by this <tt>TransactionSupportTests</tt>.
     */
    private StunStack stunStack;

    /**
     * The request we send in this test.
     */
    Request  bindingRequest = null;

    /**
     * The response we send in this test.
     */
    Response bindingResponse = null;

    /**
     * The tool that collects requests.
     */
    PlainRequestCollector requestCollector = null;

    /**
     * The tool that collects responses.
     */
    PlainResponseCollector responseCollector = null;

    /**
     * Inits sockets.
     *
     * @throws Exception if something goes bad.
     */
    protected void setUp()
        throws Exception
    {
        super.setUp();

        clientSock = new IceUdpSocketWrapper(
            new SafeCloseDatagramSocket(clientAddress));
        serverSock = new IceUdpSocketWrapper(
            new SafeCloseDatagramSocket(serverAddress));

        stunStack = new StunStack();
        stunStack.addSocket(clientSock);
        stunStack.addSocket(serverSock);

        bindingRequest = MessageFactory.createBindingRequest();
        bindingResponse = MessageFactory.create3489BindingResponse(
            clientAddress, clientAddress, serverAddress);

        requestCollector = new PlainRequestCollector();
        responseCollector = new PlainResponseCollector();

        System.setProperty(
                StackProperties.PROPAGATE_RECEIVED_RETRANSMISSIONS,
                "false");
        System.setProperty(
                StackProperties.KEEP_CRANS_AFTER_A_RESPONSE,
                "false");
        System.setProperty(
                StackProperties.MAX_CTRAN_RETRANSMISSIONS,
                "");
        System.setProperty(
                StackProperties.MAX_CTRAN_RETRANS_TIMER,
                "");
        System.setProperty(
                StackProperties.FIRST_CTRAN_RETRANS_AFTER,
                "");
    }

    /**
     * Frees all sockets that we are currently using.
     *
     * @throws Exception if something does not go as planned.
     */
    protected void tearDown()
        throws Exception
    {
        stunStack.removeSocket(clientAddress);
        stunStack.removeSocket(serverAddress);

        clientSock.close();
        serverSock.close();

        requestCollector = null;
        responseCollector = null;

        System.setProperty(
                StackProperties.PROPAGATE_RECEIVED_RETRANSMISSIONS,
                "false");
        System.setProperty(
                StackProperties.KEEP_CRANS_AFTER_A_RESPONSE,
                "false");
        System.setProperty(
                StackProperties.MAX_CTRAN_RETRANSMISSIONS,
                "");
        System.setProperty(
                StackProperties.MAX_CTRAN_RETRANS_TIMER,
                "");
        System.setProperty(
                StackProperties.FIRST_CTRAN_RETRANS_AFTER,
                "");

        super.tearDown();
    }

    /**
     * Test that requests are retransmitted if no response is received
     *
     * @throws java.lang.Exception upon any failure
     */
    public void testClientRetransmissions() throws Exception
    {
        String oldRetransValue = System.getProperty(
                                     StackProperties.MAX_CTRAN_RETRANSMISSIONS);
        String oldMaxWaitValue = System.getProperty(
                                     StackProperties.MAX_CTRAN_RETRANS_TIMER);

        System.setProperty(StackProperties.MAX_CTRAN_RETRANS_TIMER, "100");
        System.setProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS, "2");

        //prepare to listen
        System.setProperty(StackProperties.PROPAGATE_RECEIVED_RETRANSMISSIONS,
                           "true");

        stunStack.addRequestListener(serverAddress, requestCollector);
        //send
        stunStack.sendRequest(
                bindingRequest,
                serverAddress,
                clientAddress,
                responseCollector);

        //wait for retransmissions
        Thread.sleep(1000);

        //verify
        Vector<StunMessageEvent> reqs
            = requestCollector.getRequestsForTransaction(
                                bindingRequest.getTransactionID());

        assertTrue("No retransmissions of the request have been received",
            reqs.size() > 1);
        assertTrue("The binding request has been retransmitted more than it "
                        +"should have!",
                    reqs.size() >= 3);

        //restore the retransmissions prop in case others are counting on
        //defaults.
        if(oldRetransValue != null)
            System.getProperty( StackProperties.MAX_CTRAN_RETRANSMISSIONS,
                                oldRetransValue);
        else
            System.clearProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS);

        if(oldMaxWaitValue != null)
            System.getProperty( StackProperties.MAX_CTRAN_RETRANS_TIMER,
                                oldRetransValue);
        else
            System.clearProperty(StackProperties.MAX_CTRAN_RETRANS_TIMER);
    }

    /**
     * Make sure that retransmissions are not seen by the server user and that
     * it only gets a single request.
     *
     * @throws Exception if anything goes wrong.
     */
    public void testServerRetransmissionHiding() throws Exception
    {
        String oldRetransValue = System.getProperty(
                StackProperties.MAX_CTRAN_RETRANSMISSIONS);
        System.setProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS, "2");
        //prepare to listen
        stunStack.addRequestListener(serverAddress, requestCollector);
        //send
        stunStack.sendRequest(
                bindingRequest,
                serverAddress,
                clientAddress,
                responseCollector);

        //wait for retransmissions
        Thread.sleep(1000);

        //verify
        Vector<StunMessageEvent> reqs
            = requestCollector.getRequestsForTransaction(
                bindingRequest.getTransactionID());

        assertTrue(
            "Retransmissions of a binding request were propagated "
            + "to the server", reqs.size() <= 1 );

        //restore the retransmissions prop in case others are counting on
        //defaults.
        if(oldRetransValue != null)
            System.getProperty( StackProperties.MAX_CTRAN_RETRANSMISSIONS,
                                oldRetransValue);
        else
            System.clearProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS);
    }

    /**
     * Makes sure that once a request has been answered by the server,
     * retransmissions of this request are not propagated to the UA and are
     * automatically handled with a retransmission of the last seen response
     *
     * @throws Exception if we screw up.
     */
    public void testServerResponseRetransmissions() throws Exception
    {
        String oldRetransValue = System.getProperty(
            StackProperties.MAX_CTRAN_RETRANSMISSIONS);
        System.setProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS, "2");
        System.setProperty(StackProperties.MAX_CTRAN_RETRANS_TIMER, "100");

        //prepare to listen
        System.setProperty(
                StackProperties.KEEP_CRANS_AFTER_A_RESPONSE,
                "true");
        stunStack.addRequestListener(serverAddress, requestCollector);
        //send
        stunStack.sendRequest(
                bindingRequest,
                serverAddress,
                clientAddress,
                responseCollector);

        //wait for the message to arrive
        requestCollector.waitForRequest();

        Vector<StunMessageEvent> reqs = requestCollector
            .getRequestsForTransaction( bindingRequest.getTransactionID());

        StunMessageEvent evt = reqs.get(0);

        byte[] tid = evt.getMessage().getTransactionID();

        stunStack.sendResponse(
                tid,
                bindingResponse,
                serverAddress,
                clientAddress);

        //wait for retransmissions
        Thread.sleep(500);

        //verify that we received a fair number of retransmitted responses.
        assertTrue(
            "There were too few retransmissions of a binding response: "
                        +responseCollector.receivedResponses.size(),
            responseCollector.receivedResponses.size() < 3 );

        //restore the retransmissions prop in case others are counting on
        //defaults.
        if(oldRetransValue != null)
            System.getProperty( StackProperties.MAX_CTRAN_RETRANSMISSIONS,
                                oldRetransValue);
        else
            System.clearProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS);

        System.clearProperty(StackProperties.MAX_CTRAN_RETRANS_TIMER);
    }

    /**
     * A (very) weak test, verifying that transaction IDs are unique.
     * @throws Exception in case we feel like it.
     */
    public void testUniqueIDs() throws Exception
    {
        stunStack.addRequestListener(serverAddress, requestCollector);
        //send req 1
        stunStack.sendRequest(
                bindingRequest,
                serverAddress,
                clientAddress,
                responseCollector);

        //wait for retransmissions
        requestCollector.waitForRequest();

        Vector<StunMessageEvent> reqs1 = requestCollector
            .getRequestsForTransaction( bindingRequest.getTransactionID());

        StunMessageEvent evt1 = reqs1.get(0);

        //send a response to make the other guy shut up
        byte[] tid = evt1.getMessage().getTransactionID();

        stunStack.sendResponse(
                tid,
                bindingResponse,
                serverAddress,
                clientAddress);

        //send req 2
        stunStack.sendRequest(
                bindingRequest,
                serverAddress,
                clientAddress,
                responseCollector);

        //wait for retransmissions
        Thread.sleep(1000);

        Vector<StunMessageEvent> reqs2
            = requestCollector.getRequestsForTransaction(
                bindingRequest.getTransactionID());

        StunMessageEvent evt2 = reqs2.get(0);

        assertFalse(
            "Consecutive requests were assigned the same transaction id",
            Arrays.equals( evt1.getMessage().getTransactionID(),
                           evt2.getMessage().getTransactionID()));
    }

    /**
     * Tests whether the properties for configuring the maximum number of
     * retransmissions in a transaction are working properly.
     *
     * @throws Exception if the gods so decide.
     */
    public void testClientTransactionMaxRetransmisssionsConfigurationParameter()
        throws Exception
    {
        //MAX_RETRANSMISSIONS

        System.setProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS, "2");
        //make sure we see retransmissions so that we may count them
        System.setProperty(
                StackProperties.PROPAGATE_RECEIVED_RETRANSMISSIONS,
                "true");
        stunStack.addRequestListener(
                        serverAddress, requestCollector);
        //send
        stunStack.sendRequest(
                bindingRequest,
                serverAddress,
                clientAddress,
                responseCollector);
        //wait for retransmissions
        Thread.sleep(1600);

        //verify
        Vector<StunMessageEvent> reqs
            = requestCollector.getRequestsForTransaction(
                bindingRequest.getTransactionID());

        assertTrue("No retransmissions of the request have been received",
            reqs.size() > 1);
        assertEquals(
            "The MAX_RETRANSMISSIONS param was not taken into account!",
            reqs.size(),
            3);

    }

    /**
     * Tests whether the properties for configuring the minimum transaction
     * wait interval is working properly.
     *
     * @throws Exception if we are having a bad day.
     */
    public void testMinWaitIntervalConfigurationParameter()
        throws Exception
    {
        //MAX_RETRANSMISSIONS
        System.setProperty(StackProperties.FIRST_CTRAN_RETRANS_AFTER, "50");
        //make sure we see retransmissions so that we may count them
        System.setProperty(
                StackProperties.PROPAGATE_RECEIVED_RETRANSMISSIONS,
                "true");
        stunStack.addRequestListener(serverAddress, requestCollector);
        //send
        stunStack.sendRequest(
                bindingRequest,
                serverAddress,
                clientAddress,
                responseCollector);

        //wait a while
        requestCollector.waitForRequest();

        //verify
        Vector<?> reqs = requestCollector.getRequestsForTransaction(
                                bindingRequest.getTransactionID());
        assertTrue("A retransmissions of the request was sent too early",
            reqs.size() < 2);

        //wait for a send
        Thread.sleep(110);

        reqs = requestCollector.getRequestsForTransaction(
                                bindingRequest.getTransactionID());

        //verify
        assertEquals("A retransmissions of the request was not sent",
                     2, reqs.size());
    }

    /**
     * Tests whether the properties for configuring the maximum transaction
     * wait interval is working properly.
     *
     * @throws Exception if the gods so decide.
     */
    public void testMaxWaitIntervalConfigurationParameter()
        throws Exception
    {
        //MAX_RETRANSMISSIONS
        System.setProperty(StackProperties.MAX_CTRAN_RETRANS_TIMER,
                           "100");
        //make sure we see retransmissions so that we may count them
        System.setProperty(StackProperties.PROPAGATE_RECEIVED_RETRANSMISSIONS,
                           "true");
        System.setProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS,
                           "11");
        stunStack.addRequestListener(serverAddress, requestCollector);
        //send
        stunStack.sendRequest(
                bindingRequest,
                serverAddress,
                clientAddress,
                responseCollector);

        //wait a while
        Thread.sleep(1200);

        //verify
        Vector<StunMessageEvent> reqs
            = requestCollector.getRequestsForTransaction(
                                bindingRequest.getTransactionID());
        assertEquals("Not all retransmissions were made for the expected period "
                   +"of time",
                   12,
                   reqs.size());

        //wait for a send
        Thread.sleep(1800);

        //verify
        reqs = requestCollector.getRequestsForTransaction(
                                bindingRequest.getTransactionID());
        assertEquals("A retransmissions of the request was sent, while not "
                    +"supposed to",
                    12,
                    reqs.size());
    }

    /**
     * A simply utility for asynchronous collection of requests.
     */
    private class PlainRequestCollector
        implements RequestListener
    {
        /**
         *
         */
        private Vector<StunMessageEvent> receivedRequestsVector
            = new Vector<>();

        /**
         * Logs the newly received request.
         *
         * @param evt the {@link StunMessageEvent} to log.
         */
        public void processRequest(StunMessageEvent evt)
        {

            synchronized(this)
            {
                receivedRequestsVector.add(evt);
                notifyAll();
            }
        }

        /**
         * Only return requests from the specified tran because we might have
         * capture others too.
         *
         * @param tranid the transaction that we'd like to get requests for.
         *
         * @return a Vector containing all request that we have received and
         * that match <tt>tranid</tt>.
         */
        public Vector<StunMessageEvent> getRequestsForTransaction(byte[] tranid)
        {
            Vector<StunMessageEvent> newVec = new Vector<>();

            for (StunMessageEvent evt : receivedRequestsVector)
            {
                Message msg = evt.getMessage();
                if( Arrays.equals(tranid, msg.getTransactionID()))
                    newVec.add(evt);
            }

            return newVec;
        }

        /**
         * Blocks until a request arrives or 50 ms pass.
         */
        public void waitForRequest()
        {
            synchronized(this)
            {
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
     * A simple utility for asynchronously collecting responses.
     */
    private static class PlainResponseCollector
        extends AbstractResponseCollector
    {
        /**
         * The responses we've collected so far.
         */
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
        protected void processFailure(BaseStunMessageEvent event)
        {
            String receivedResponse;

            if (event instanceof StunFailureEvent)
                receivedResponse = "unreachable";
            else if (event instanceof StunTimeoutEvent)
                receivedResponse = "timeout";
            else
                receivedResponse = "failure";
            receivedResponses.add(receivedResponse);
        }

        /**
         * Logs the received <tt>response</tt>
         *
         * @param response the event to log.
         */
        public void processResponse(StunResponseEvent response)
        {
            receivedResponses.add(response);
        }
    }
}
