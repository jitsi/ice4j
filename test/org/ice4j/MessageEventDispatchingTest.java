package org.ice4j;

import junit.framework.*;

import java.util.*;

import org.ice4j.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;

/**
 * Test event dispatching for both client and server.
 * <p>Company: Net Research Team, Louis Pasteur University</p>
 * @author Emil Ivov
 */
public class MessageEventDispatchingTest extends TestCase
{
    StunStack stunStack = null;

    TransportAddress clientAddress = new TransportAddress("127.0.0.1", 5216);
    TransportAddress serverAddress = new TransportAddress("127.0.0.2", 5255);
    TransportAddress serverAddress2 = new TransportAddress("127.0.0.2", 5259);

    NetAccessPointDescriptor  clientAccessPoint = null;
    NetAccessPointDescriptor  serverAccessPoint = null;
    NetAccessPointDescriptor  serverAccessPoint2 = null;

    Request  bindingRequest = null;
    Response bindingResponse = null;

    PlainRequestCollector requestCollector = null;
    PlainResponseCollector responseCollector = null;

    protected void setUp() throws Exception
    {
        super.setUp();

        stunStack = StunStack.getInstance();

        clientAccessPoint = new NetAccessPointDescriptor(clientAddress);
        serverAccessPoint = new NetAccessPointDescriptor(serverAddress);
        serverAccessPoint2 = new NetAccessPointDescriptor(serverAddress2);

        stunStack.installNetAccessPoint(clientAccessPoint);
        stunStack.installNetAccessPoint(serverAccessPoint);
        stunStack.installNetAccessPoint(serverAccessPoint2);

        bindingRequest = MessageFactory.createBindingRequest();
        bindingResponse = MessageFactory.createBindingResponse(
            clientAddress, clientAddress, serverAddress);

        requestCollector = new PlainRequestCollector();
        responseCollector = new PlainResponseCollector();

    }

    protected void tearDown() throws Exception
    {
        clientAccessPoint = null;
        serverAccessPoint = null;
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
                                            clientAccessPoint,
                                            responseCollector);
        Thread.currentThread().sleep(12000);

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
                                            clientAccessPoint,
                                            responseCollector);
        //wait for retransmissions
        Thread.currentThread().sleep(500);

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
        stunStack.getProvider().addRequestListener(serverAccessPoint,
                                                   requestCollector);

        PlainRequestCollector requestCollector2 = new PlainRequestCollector();
        stunStack.getProvider().addRequestListener(serverAccessPoint2,
                                                   requestCollector2);

        //send
        stunStack.getProvider().sendRequest(bindingRequest,
                                            serverAddress2,
                                            clientAccessPoint,
                                            responseCollector);
        //wait for retransmissions
        Thread.currentThread().sleep(500);

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
        stunStack.getProvider().addRequestListener(serverAccessPoint,
                                                   requestCollector);
        //send
        stunStack.getProvider().sendRequest(bindingRequest,
                                            serverAddress,
                                            clientAccessPoint,
                                            responseCollector);

        //wait for the message to arrive
        Thread.currentThread().sleep(500);

        StunMessageEvent evt = requestCollector.receivedRequests.get(0);
        byte[] tid = evt.getMessage().getTransactionID();
        stunStack.getProvider().sendResponse(tid,
                                             bindingResponse,
                                             serverAccessPoint,
                                             clientAddress);

        //wait for retransmissions
        Thread.currentThread().sleep(500);

        //verify that we got the response.
        assertTrue(
            "There were no retransmissions of a binding response",
            responseCollector.receivedResponses.size() == 1 );
    }

    private class PlainRequestCollector implements RequestListener{
        public Vector<StunMessageEvent> receivedRequests = new Vector<StunMessageEvent>();

        public void requestReceived(StunMessageEvent evt){
            receivedRequests.add(evt);
        }
    }

    private class PlainResponseCollector implements ResponseCollector{

        public Vector<Object> receivedResponses = new Vector<Object>();

        public void processResponse(StunMessageEvent responseEvt)
        {
            receivedResponses.add(responseEvt);
        }

        public void processTimeout()
        {
            receivedResponses.add(new String("timeout"));
        }

    }
}
