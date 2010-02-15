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
import org.ice4j.socket.*;

/**
 * All unit stack tests should be provided later. I just don't have the time now.
 *
 * @author Emil Ivov
 */
public class ShallowStackTest extends TestCase {

    private static final Logger logger =
        Logger.getLogger(ShallowStackTest.class.getName());

    private StunStack    stunStack  = null;
    private MsgFixture   msgFixture = null;

    private TransportAddress dummyServerAddress = null;
    private TransportAddress localAddress = null;

    private DatagramCollector dgramCollector = new DatagramCollector();

    private DatagramSocket   localSock = null;

    private DatagramSocket dummyServerSocket = null;
    private DatagramPacket bindingRequestPacket
                                    = new DatagramPacket(new byte[4096], 4096);

    public ShallowStackTest(String name)
    {
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

        //access point
        localSock = new SafeCloseDatagramSocket(localAddress);
        stunStack.addSocket(localSock);

        //init the dummy server
        dummyServerSocket = new DatagramSocket( dummyServerAddress );
    }

    protected void tearDown()
        throws Exception
    {
        stunStack.removeSocket(localAddress);

        localSock.close();

        dummyServerSocket.close();

        msgFixture.tearDown();
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

        dgramCollector.startListening(dummyServerSocket);

        stunStack.sendRequest(bindingRequest,
                              dummyServerAddress,
                              localAddress,
                              new SimpleResponseCollector());

        //wait for its arrival
        dgramCollector.waitForPacket();

        DatagramPacket receivedPacket = dgramCollector.collectPacket();

        assertTrue("The stack did not properly send a Binding Request",
                   (receivedPacket.getLength() > 0));

        Request receivedRequest =
                        (Request)Request.decode(receivedPacket.getData(),
                                            (char)0,
                                            (char)receivedPacket.getLength());
        assertEquals("The received request did not match the "
                     +"one that was sent.",
                     bindingRequest, //expected
                     receivedRequest); // actual

        //wait for retransmissions

        dgramCollector.startListening(dummyServerSocket);

        dgramCollector.waitForPacket();

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
        stunStack.addRequestListener(requestCollector);

        dummyServerSocket.send(new DatagramPacket(
            msgFixture.bindingRequest2,
            msgFixture.bindingRequest2.length,
            localAddress));

        //wait for the packet to arrive
        requestCollector.waitForRequest();

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
        stunStack.addRequestListener(requestCollector);

        dummyServerSocket.send(new DatagramPacket(
                                            msgFixture.bindingRequest,
                                            msgFixture.bindingRequest.length,
                                            localAddress));

        //wait for the packet to arrive
        requestCollector.waitForRequest();

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

        stunStack.sendResponse(collectedRequest.getTransactionID(),
                               bindingResponse,
                               localAddress,
                               dummyServerAddress);

        //wait for its arrival
        dgramCollector.waitForPacket();

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

        stunStack.sendRequest(bindingRequest,
                              dummyServerAddress,
                              localAddress,
                              collector);

        //wait for its arrival
        collector.waitForResponse();

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
        collector.waitForResponse();

        Response collectedResponse = collector.collectedResponse;

        byte expectedReturn[] = response;
        byte actualReturn[]   = collectedResponse.encode();
        assertTrue("Received request was not the same as the one that was sent",
                   Arrays.equals(expectedReturn, actualReturn));
    }

    //--------------------------------------- listener implementations ---------
    /**
     * A simple utility that allows us to asynchronously collect messages.
     */
    public class SimpleResponseCollector
        implements ResponseCollector
    {

        /**
         * The response that we've just collected or <tt>null</tt> if none
         * arrived while we were waiting.
         */
        Response collectedResponse = null;

        /**
         * Logs the received response and notifies the wait method.
         */
        public synchronized void processResponse(StunMessageEvent evt)
        {
            collectedResponse = (Response)evt.getMessage();
            logger.finest("Received response.");
            notifyAll();
        }

        /**
         * Logs the timeout event for later use.
         *
         * @param evt the timeout event that has just occurred.
         */
        public synchronized void processTimeout(StunTimeoutEvent evt)
        {
            logger.info("Timeout");
            notifyAll();
        }

        /**
         * Notifies this collector that the destination of the request has been
         * determined to be unreachable and that the request should be
         * considered unanswered.
         *
         * @param exception the <tt>PortUnreachableException</tt> which signaled
         * that the destination of the request was found to be unreachable
         * @see ResponseCollector#processUnreachable(PortUnreachableException)
         */
        public synchronized void processUnreachable(
                PortUnreachableException exception)
        {
            logger.info("Unreachable");
            notifyAll();
        }

        /**
         * Blocks until a request arrives or 50 ms pass.
         */
        public synchronized void waitForResponse()
        {
            try
            {
                if (collectedResponse == null)
                    wait(50);
            }
            catch (InterruptedException e)
            {
                logger.log(Level.INFO, "oops", e);
            }
        }
    }

    /**
     * A utility class for asynchronously collecting requests.
     */
    public class SimpleRequestCollector
        implements RequestListener
    {
        /**
         * The one request that this collector has received or <tt>null</tt> if
         * none arrived while we were waiting.
         */
        private Request collectedRequest = null;

        /**
         * Indicates that a <tt>StunRequest</tt> has just been received.
         *
         * @param evt the <tt>StunMessageEvent</tt> containing the details of
         * the newly received request.
         */
        public void requestReceived(StunMessageEvent evt)
        {
            synchronized(this)
            {
                collectedRequest = (Request)evt.getMessage();
                stunStack.removeRequestListener(this);
                logger.finest("Received request.");
                notifyAll();
            }
        }

        /**
         * Blocks until a request arrives or 50 ms pass.
         */
        public void waitForRequest()
        {
            synchronized(this)
            {
                if (collectedRequest != null)
                    return;

                try
                {
                    wait(50);
                }
                catch (InterruptedException e)
                {
                    logger.log(Level.INFO, "oops", e);
                }
            }
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
