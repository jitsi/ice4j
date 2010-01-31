/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j;

import java.net.*;
import java.util.*;

import junit.framework.*;

import org.ice4j.message.*;
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
        = new TransportAddress("127.0.0.2", 5255, Transport.UDP);

    /**
     * The address of the second server.
     */
    TransportAddress serverAddress2
        = new TransportAddress("127.0.0.2", 5259, Transport.UDP);

    /**
     * The socket that the client is using.
     */
    DatagramSocket  clientSock = null;

    /**
     * The socket that the server is using
     */
    DatagramSocket  serverSock = null;

    /**
     * The second server socket.
     */
    DatagramSocket serverSock2 = null;

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

        stunStack = StunStack.getInstance();

        clientSock = new DatagramSocket(clientAddress);
        serverSock = new DatagramSocket(clientAddress);
        serverSock = new DatagramSocket(serverAddress2);

        stunStack.addSocket(clientSock);
        stunStack.addSocket(serverSock);
        stunStack.addSocket(serverSock2);

        bindingRequest = MessageFactory.createBindingRequest();
        bindingResponse = MessageFactory.createBindingResponse(
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
        clientSock.close();
        serverSock.close();
        serverSock.close();

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

        stunStack.getProvider().sendRequest(bindingRequest,
                                            serverAddress,
                                            clientAddress,
                                            responseCollector);
        Thread.sleep(12000);

        assertEquals(
            "No timeout was produced upon expiration of a client transaction",
            responseCollector.receivedResponses.size(), 1);

        assertEquals(
            "No timeout was produced upon expiration of a client transaction",
            responseCollector.receivedResponses.get(0), "timeout");
    }

    /**
     * Test reception of Message events.
     *
     * @throws java.lang.Exception upon any failure
     */
    public void testEventDispatchingUponIncomingRequests() throws Exception
    {
        //prepare to listen
        stunStack.getProvider().addRequestListener(requestCollector);
        //send
        stunStack.getProvider().sendRequest(bindingRequest,
                                            serverAddress,
                                            clientAddress,
                                            responseCollector);
        //wait for retransmissions
        Thread.sleep(50);

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
        stunStack.getProvider().addRequestListener(serverAddress,
                                                   requestCollector);

        PlainRequestCollector requestCollector2 = new PlainRequestCollector();
        stunStack.getProvider().addRequestListener(serverAddress2,
                                                   requestCollector2);

        //send
        stunStack.getProvider().sendRequest(bindingRequest,
                                            serverAddress2,
                                            clientAddress,
                                            responseCollector);
        //wait for retransmissions
        Thread.sleep(50);

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
        stunStack.getProvider().addRequestListener(serverAddress,
                                                   requestCollector);
        //send
        stunStack.getProvider().sendRequest(bindingRequest,
                                            serverAddress,
                                            clientAddress,
                                            responseCollector);

        //wait for the message to arrive
        Thread.sleep(50);

        StunMessageEvent evt = requestCollector.receivedRequests.get(0);
        byte[] tid = evt.getMessage().getTransactionID();
        stunStack.getProvider().sendResponse(tid,
                                             bindingResponse,
                                             serverAddress,
                                             clientAddress);

        //wait for retransmissions
        Thread.sleep(50);

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
        public Vector<StunMessageEvent> receivedRequests
            = new Vector<StunMessageEvent>();

        /**
         * Stores incoming requests.
         *
         * @param evt the event containing the incoming request.
         */
        public void requestReceived(StunMessageEvent evt)
        {
            receivedRequests.add(evt);
        }
    }

    /**
     * A utility class we use to collect incoming responses.
     */
    private class PlainResponseCollector implements ResponseCollector
    {
        /**
         *
         */
        public Vector<Object> receivedResponses = new Vector<Object>();

        /**
         * Stores incoming requests.
         *
         * @param responseEvt the event containing the incoming request.
         */
        public void processResponse(StunMessageEvent responseEvt)
        {
            receivedResponses.add(responseEvt);
        }

        /**
         * Indicates that no response has been received.
         */
        public void processTimeout()
        {
            receivedResponses.add(new String("timeout"));
        }

    }
}
