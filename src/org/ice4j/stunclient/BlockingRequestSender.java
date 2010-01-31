/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.stunclient;

import java.io.*;
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
     * The provider that we are using to send requests through.
     */
    private StunProvider stunProvider  = null;

    /**
     * The transport address that we are bound on.
     */
    private TransportAddress localAddress  = null;

    /**
     * The <tt>StunMessageEvent</tt> that contains the response matching our
     * request.
     */
    private StunMessageEvent responseEvent = null;

    /**
     * Determines whether this request sender has comleted its coarse.
     */
    private boolean ended = false;

    /**
     * A lock object that we are using to synchronize sending.
     */
    private Object sendLock = new Object();

    /**
     * Creates a new request sender.
     * @param stunProvider the provider that the sender should send requests
     * through.
     * @param localAddress the <tt>TransportAddress</tt> that requests should be
     * leaving from.
     */
    BlockingRequestSender(StunProvider     stunProvider,
                          TransportAddress localAddress)
    {
        this.stunProvider = stunProvider;
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
     */
    public synchronized void processTimeout()
    {
        synchronized(sendLock){
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
            stunProvider.sendRequest(request, serverAddress, localAddress,
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
