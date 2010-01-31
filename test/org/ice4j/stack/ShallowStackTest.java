/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
 package org.ice4j.stack;

import java.net.*;
import java.util.*;
import java.util.logging.*;

import junit.framework.*;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * All unit stack tests should be provided later. I just don't have the time now.
 *
 * @author Emil Ivov
 */
public class ShallowStackTest extends TestCase {

    private static final Logger logger =
        Logger.getLogger(ShallowStackTest.class.getName());

    private StunProvider stunProvider = null;
    private StunStack    stunStack  = null;
    private MsgFixture   msgFixture = null;

    private TransportAddress dummyServerAddress = null;
    private TransportAddress localAddress = null;

    private DatagramCollector dgramCollector = new DatagramCollector();

    private DatagramSocket   localSock = null;

    private DatagramSocket dummyServerSocket = null;
    private DatagramPacket bindingRequestPacket
                                    = new DatagramPacket(new byte[4096], 4096);

    public ShallowStackTest(String name) {
        super(name);
    }

    protected void setUp()
        throws Exception
    {
        super.setUp();
        msgFixture = new MsgFixture();
        msgFixture.setUp();
        //Addresses
        dummyServerAddress = new TransportAddress(
                    "127.0.0.1", 6004, Transport.UDP);
        localAddress = new TransportAddress(
                    "127.0.0.1", 5004, Transport.UDP);

        //init the stack
        stunStack    = StunStack.getInstance();
        stunProvider = stunStack.getProvider();

System.out.println("binding 1!!!");
        //access point
        localSock = new DatagramSocket(localAddress);

        stunStack.addSocket(localSock);
System.out.println("binding 2!!!");

        //init the dummy server
        dummyServerSocket = new DatagramSocket( dummyServerAddress );
    }

    protected void tearDown()
        throws Exception
    {
        msgFixture.tearDown();
System.out.println("tearing down!!!");
        stunStack.removeSocket(localAddress);

System.out.println("unbinding 1!!!");
        localSock.close();

System.out.println("unbinding 2!!!");
        dummyServerSocket.close();


        msgFixture = null;
        super.tearDown();
    }

    /**
     * Sends a binding request using the stack to a bare socket, and verifies
     * that it is received and that the contents of the datagram corresponds to
     * the request that was sent.
     *
     * @throws java.lang.Exception if we fail
     */
    public void testSendRequest()
        throws Exception
    {
        Request bindingRequest = MessageFactory.createBindingRequest();
System.out.println("test 1!!!");
        dgramCollector.startListening(dummyServerSocket);
System.out.println("test 2!!!");
        stunProvider.sendRequest(bindingRequest,
                                 dummyServerAddress,
                                 localAddress,
                                 new SimpleResponseCollector());
System.out.println("test 3!!!");
        //wait for its arrival
        dgramCollector.waitForPacket();
System.out.println("test 4!!!");
        DatagramPacket receivedPacket = dgramCollector.collectPacket();
System.out.println("test 5!!!");
        assertTrue("The stack did not properly send a Binding Request",
                   (receivedPacket.getLength() > 0));
System.out.println("test 6!!!");
        Request receivedRequest =
                        (Request)Request.decode(receivedPacket.getData(),
                                            (char)0,
                                            (char)receivedPacket.getLength());
        assertEquals("The received request did not match the "
                     +"one that was sent.",
                     bindingRequest, //expected
                     receivedRequest); // actual
System.out.println("test 7!!!");
        //wait for retransmissions

        dgramCollector.startListening(dummyServerSocket);
System.out.println("test 8!!!");
        dgramCollector.waitForPacket();
System.out.println("test 9!!!");
        receivedPacket = dgramCollector.collectPacket();

        assertTrue("The stack did not retransmit a Binding Request",
                   (receivedPacket.getLength() > 0));

        receivedRequest = (Request)Request.decode(
            receivedPacket.getData(),
            (char)0,
            (char)receivedPacket.getLength());
        assertEquals("The retransmitted request did not match the original.",
                     bindingRequest, //expected
                     receivedRequest); // actual



    }

    /**
     * Sends a byte array containing a bindingRequest, through a datagram socket
     * and verifies that the stack receives it alright.
     *
     * @throws java.lang.Exception if we fail
     */
    public void testReceiveRequest()
        throws Exception
    {
        SimpleRequestCollector requestCollector = new SimpleRequestCollector();
        stunProvider.addRequestListener(requestCollector);

        dummyServerSocket.send(new DatagramPacket(
            msgFixture.bindingRequest2,
            msgFixture.bindingRequest2.length,
            localAddress));

        //wait for the packet to arrive
        try{ Thread.sleep(50); }catch (InterruptedException ex){}

        Request collectedRequest = requestCollector.collectedRequest;

        assertNotNull("No request has been received", collectedRequest);

        byte expectedReturn[] = msgFixture.bindingRequest2;
        byte actualReturn[]   = collectedRequest.encode();
        assertTrue("Received request was not the same as the one that was sent",
                   Arrays.equals(expectedReturn, actualReturn));
    }

    /**
     * Sends a byte array containing a bindingRequest, through a datagram socket,
     * verifies that the stack receives it properly and then sends a response
     * using the stack. Finally, the response is expected at the other end and
     * compared with the sent one.
     *
     * @throws java.lang.Exception if we fail
     */
    public void testSendResponse()
        throws Exception
    {
        //---------- send & receive the request --------------------------------
        SimpleRequestCollector requestCollector = new SimpleRequestCollector();
        stunProvider.addRequestListener(requestCollector);

        dummyServerSocket.send(new DatagramPacket(
                                            msgFixture.bindingRequest,
                                            msgFixture.bindingRequest.length,
                                            localAddress));

        //wait for the packet to arrive
        try{
            synchronized(this)
            {
                wait(50);
            }
        }catch (InterruptedException ex){}

        Request collectedRequest = requestCollector.collectedRequest;

        byte expectedReturn[] = msgFixture.bindingRequest;
        byte actualReturn[]   = collectedRequest.encode();
        assertTrue("Received request was not the same as the one that was sent",
                   Arrays.equals(expectedReturn, actualReturn));

        //---------- create the response ---------------------------------------
        Response bindingResponse = MessageFactory.createBindingResponse(
            new TransportAddress( msgFixture.ADDRESS_ATTRIBUTE_ADDRESS,
                 msgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP ),
            new TransportAddress( msgFixture.ADDRESS_ATTRIBUTE_ADDRESS_2,
                 msgFixture.ADDRESS_ATTRIBUTE_PORT_2, Transport.UDP),
            new TransportAddress( msgFixture.ADDRESS_ATTRIBUTE_ADDRESS_3,
                 msgFixture.ADDRESS_ATTRIBUTE_PORT_3, Transport.UDP));

        //---------- send & receive the response -------------------------------
        dgramCollector.startListening(dummyServerSocket);

        stunProvider.sendResponse(collectedRequest.getTransactionID(),
                                 bindingResponse,
                                 localAddress,
                                 dummyServerAddress);

        //wait for its arrival
        try{ Thread.sleep(50); }catch (InterruptedException ex){}

        DatagramPacket receivedPacket = dgramCollector.collectPacket();

        assertTrue("The stack did not properly send a Binding Request",
                   (receivedPacket.getLength() > 0));

        Response receivedResponse =
            (Response) Response.decode(receivedPacket.getData(),
                                       (char) 0,
                                       (char) receivedPacket.getLength());
        assertEquals(
            "The received request did not match the one that was sent.",
            bindingResponse, //expected
            receivedResponse); // actual
    }

    public void testReceiveResponse()
        throws Exception
    {
        SimpleResponseCollector collector = new SimpleResponseCollector();
        //--------------- send the original request ----------------------------
        Request bindingRequest = MessageFactory.createBindingRequest();

        stunProvider.sendRequest(bindingRequest,
                                 dummyServerAddress,
                                 localAddress,
                                 collector);

        //wait for its arrival
        try{ Thread.sleep(50); }catch (InterruptedException ex){}

        //create the right response
        byte response[] = new byte[msgFixture.bindingResponse.length];
        System.arraycopy(msgFixture.bindingResponse, 0, response, 0,
                         response.length);

        //Set the valid tid.
        System.arraycopy(bindingRequest.getTransactionID(),
                         0,
                         response,
                         8,
                         12);

        //send the response

        dummyServerSocket.send(new DatagramPacket(response,
                                                response.length,
                                                localAddress));

        //wait for the packet to arrive
        try{ Thread.sleep(50); }catch (InterruptedException ex){}

        Response collectedResponse = collector.collectedResponse;

        byte expectedReturn[] = response;
        byte actualReturn[]   = collectedResponse.encode();
        assertTrue("Received request was not the same as the one that was sent",
                   Arrays.equals(expectedReturn, actualReturn));
    }

    //--------------------------------------- listener implementations ---------
    public class SimpleResponseCollector
        implements ResponseCollector
    {
        Response collectedResponse = null;
        public void processResponse(StunMessageEvent evt)
        {
            collectedResponse = (Response)evt.getMessage();
            logger.info("Received response.");
        }

        public void processTimeout()
        {
            logger.info("Timeout");
        }
    }

    public class SimpleRequestCollector
        implements RequestListener
    {
        private Request collectedRequest = null;
        public void requestReceived(StunMessageEvent evt)
        {
            collectedRequest = (Request)evt.getMessage();
            stunProvider.removeRequestListener(this);
            logger.info("Received request.");
        }
    }
/*
    public static Test suite()
    {
        TestSuite suite = new TestSuite();
        suite.addTest(new ShallowStackTest(
            "testSendResponse"));
        suite.addTest(new ShallowStackTest(
            "testSendResponse"));
        suite.addTest(new ShallowStackTest(
            "testSendResponse"));
        suite.addTest(new ShallowStackTest(
            "testSendResponse"));
        return suite;
    }
*/
}
