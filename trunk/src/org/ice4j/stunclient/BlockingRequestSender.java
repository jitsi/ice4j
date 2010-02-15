/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.stunclient;

import java.io.*;
import java.net.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;

/**
 * A utility used to flatten the multi-thread architecture of the Stack
 * and execute the discovery process in a synchronized manner. Roughly what
 * happens here is:
 * <code>
 * ApplicationThread:
 *     sendMessage()
 *        wait();
 *
 * StackThread:
 *     processMessage/Timeout()
 *     {
 *          saveMessage();
 *          notify();
 *     }
 *</code>
 *
 * @author Emil Ivov
 */
class BlockingRequestSender
    implements ResponseCollector
{
    /**
     * Our class logger
     */
    private static final Logger logger
        = Logger.getLogger(BlockingRequestSender.class.getName());

    /**
     * The stack that we are using to send requests through.
     */
    private final StunStack stunStack;

    /**
     * The transport address that we are bound on.
     */
    private final TransportAddress localAddress;

    /**
     * The <tt>StunMessageEvent</tt> that contains the response matching our
     * request.
     */
    private StunMessageEvent responseEvent = null;

    /**
     * Determines whether this request sender has completed its course.
     */
    private boolean ended = false;

    /**
     * A lock object that we are using to synchronize sending.
     */
    private final Object sendLock = new Object();

    /**
     * Creates a new request sender.
     * @param stunStack the stack that the sender should send requests
     * through.
     * @param localAddress the <tt>TransportAddress</tt> that requests should be
     * leaving from.
     */
    BlockingRequestSender(StunStack        stunStack,
                          TransportAddress localAddress)
    {
        this.stunStack = stunStack;
        this.localAddress = localAddress;
    }

    /**
     * Saves the message event and notifies the discoverer thread so that
     * it may resume.
     * @param evt the newly arrived message event.
     */
    public synchronized void processResponse(StunMessageEvent evt)
    {
        synchronized(sendLock){
            this.responseEvent = evt;
            ended = true;
            notifyAll();
        }
    }

    /**
     * Notifies the discoverer thread when a message has timeout-ed so that
     * it may resume and consider it as unanswered.
     *
     * @param evt the <tt>StunTimeoutEvent</tt> containing the transaction that
     * has just expired.
     */
    public synchronized void processTimeout(StunTimeoutEvent evt)
    {
        synchronized(sendLock){
            ended = true;
            notifyAll();
        }
    }

    /**
     * Notifies this collector that the destination of the request has been
     * determined to be unreachable and that the request should be considered
     * unanswered.
     *
     * @param event the <tt>StunFailureEvent</tt> that contains the
     * <tt>PortUnreachableException</tt> which signaled that the destination of
     * the request was found to be unreachable
     * @see ResponseCollector#processUnreachable(StunFailureEvent)
     */
    public synchronized void processUnreachable(
                    StunFailureEvent event)
    {
        synchronized(sendLock)
        {
            ended = true;
            notifyAll();
        }
    }

    /**
     * Sends the specified request and blocks until a response has been
     * received or the request transaction has timed out.
     * @param request the request to send
     * @param serverAddress the request destination address
     * @return the event encapsulating the response or null if no response
     * has been received.
     *
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws StunException if message encoding fails,
     */
    public synchronized StunMessageEvent sendRequestAndWaitForResponse(
                                                Request request,
                                                TransportAddress serverAddress)
            throws StunException,
                   IOException
    {
        synchronized(sendLock){
            stunStack.sendRequest(request, serverAddress, localAddress,
                                     BlockingRequestSender.this);
        }

        ended = false;
        while(!ended){
            try
            {
                wait();
            }
            catch (InterruptedException ex)
            {
                logger.log(Level.WARNING, "Interrupted", ex);
            }
        }
        StunMessageEvent res = responseEvent;
        responseEvent = null; //prepare for next message

        return res;
    }
}
