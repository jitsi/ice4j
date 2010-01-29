/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.stunclient;

import java.util.logging.*;
import java.io.*;

import org.ice4j.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;

/**
 * A utility used to flatten the multithreaded architecture of the Stack
 * and execute the discovery process in a synchronized manner. Roughly what
 * happens here is:
 *
 * ApplicationThread:
 *     sendMessage()
 * 	   wait();
 *
 * StackThread:
 *     processMessage/Timeout()
 *     {
 *          saveMessage();
 *          notify();
 *     }
 *
 *
 * <p>Organisation: <p> Louis Pasteur University, Strasbourg, France</p>
 * <p>Network Research Team (http://www-r2.u-strasbg.fr)</p></p>
 * @author Emil Ivov
 * @version 0.1
 */
class BlockingRequestSender
    implements ResponseCollector
{
    private static final Logger logger =
        Logger.getLogger(BlockingRequestSender.class.getName());

    private StunProvider             stunProvider  = null;
    private NetAccessPointDescriptor apDescriptor  = null;

    StunMessageEvent responseEvent = null;

    private boolean ended = false;
    private Object  sendLock = new Object();

    BlockingRequestSender(StunProvider             stunProvider,
                          NetAccessPointDescriptor apDescriptor)
    {
        this.stunProvider = stunProvider;
        this.apDescriptor = apDescriptor;
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
     * Notifies the discoverer thread when a message has timeouted so that
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
     * @param request the reuqest to send
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
            stunProvider.sendRequest(request, serverAddress, apDescriptor,
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
