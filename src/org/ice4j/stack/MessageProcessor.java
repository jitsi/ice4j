/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.stack;

import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * The class is used to parse and dispatch incoming messages in a multi-thread
 * manner.
 *
 * @author Emil Ivov
 */
class MessageProcessor
    implements Runnable
{
    /**
     * Our class logger.
     */
    private static final Logger logger
        = Logger.getLogger(MessageProcessor.class.getName());

    /**
     * The queue where we store incoming messages until they are collected.
     */
    private MessageQueue messageQueue = null;

    /**
     * The listener that will be retrieving <tt>MessageEvent</tt>s
     */
    private MessageEventHandler messageHandler = null;

    /**
     * The listener that will be collecting error notifications.
     */
    private ErrorHandler errorHandler  = null;

    /**
     * The flag that indicates whether we are still running.
     */
    private boolean isRunning = false;

    /**
     * A reference to the thread that we use to execute ourselves.
     */
    private Thread runningThread = null;

    /**
     * Creates a Message processor.
     *
     * @param queue the <tt>MessageQueue</tt> where we'll be storing incoming
     * messages.
     * @param messageHandler MessageEventHandler
     * @param errorHandler the <tt>ErrorHandler</tt> that should handle
     * exceptions in this processor
     *
     * @throws IllegalArgumentException if either of the parameters is null.
     */
    MessageProcessor(MessageQueue           queue,
                     MessageEventHandler    messageHandler,
                     ErrorHandler           errorHandler)
        throws IllegalArgumentException
    {
        if(queue == null)
            throw new IllegalArgumentException(
                "The message queue may not be " + null);

        if(messageHandler == null)
            throw new IllegalArgumentException(
                "The message handler may not be " + null);

        if(errorHandler == null)
            throw new IllegalArgumentException(
                "The error handler may not be " + null);

        this.messageQueue    = queue;
        this.messageHandler  = messageHandler;
        this.errorHandler    = errorHandler;
    }

    /**
     * Does the message parsing.
     */
    public void run()
    {
        //add an extra try/catch block that handles uncatched errors and helps
        //avoid having dead threads in our pools.
        try
        {
            while (isRunning)
            {
                RawMessage rawMessage;
                try
                {
                    rawMessage = messageQueue.remove();
                }
                catch (InterruptedException ex)
                {
                    if(isRunning())
                        logger.log(Level.WARNING,
                                "A net access point has gone useless: ", ex);
                    //nothing to do here since we test whether we are running
                    //just beneath ...
                    rawMessage = null;
                }

                // were we asked to stop?
                if (!isRunning())
                    return;
                //anything to parse?
                if (rawMessage == null)
                    continue;

                Message stunMessage = null;
                try
                {
                    stunMessage
                        = Message.decode(rawMessage.getBytes(),
                                         (char) 0,
                                         (char) rawMessage.getMessageLength());
                }
                catch (StunException ex)
                {
                    errorHandler.handleError("Failed to decode a stun mesage!",
                                             ex);
                    continue; //let this one go and for better luck next time.
                }

                logger.finest("Dispatching a StunMessageEvent.");

                StunMessageEvent stunMessageEvent =
                    new StunMessageEvent(
                        rawMessage.getLocalAddress(),
                        stunMessage,
                        rawMessage.getRemoteAddress());

                messageHandler.handleMessageEvent(stunMessageEvent);
            }
        }
        catch(Throwable err)
        {
            //notify and bail
            errorHandler.handleFatalError(this, "Unexpected Error!", err);
        }
    }

    /**
     * Start the message processing thread.
     */
    void start()
    {
        this.isRunning = true;

        runningThread = new Thread(this, "Stun4J Message Processor");
        runningThread.setDaemon(true);
        runningThread.start();
    }


    /**
     * Shut down the message processor.
     */
    void stop()
    {
        this.isRunning = false;
        runningThread.interrupt();
    }

    /**
     * Determines whether the processor is still running;
     *
     * @return true if the processor is still authorized to run, and false
     * otherwise.
     */
    boolean isRunning()
    {
        return isRunning;
    }
}
