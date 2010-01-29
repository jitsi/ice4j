/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.stack;

import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * The class is used to parse and dispatch incoming messages in a multithreaded
 * manner.
 *
 * <p>Organisation: Louis Pasteur University, Strasbourg, France</p>
 *                  <p>Network Research Team (http://www-r2.u-strasbg.fr)</p></p>
 * @author Emil Ivov
 * @version 0.1
 */

class MessageProcessor
    implements Runnable
{
    private static final Logger logger =
        Logger.getLogger(MessageProcessor.class.getName());

    private MessageQueue           messageQueue     = null;
    private MessageEventHandler    messageHandler   = null;
    private ErrorHandler           errorHandler     = null;

    private boolean                isRunning	    = false;
    private Thread                 runningThread    = null;

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
        this.messageHandler    = messageHandler;
        this.errorHandler    = errorHandler;
    }

    /**
     * Does the message parsing.
     */
    public void run()
    {
        //add an extra try/catch block that handles uncatched errors and helps avoid
        //having dead threads in our pools.
        try
        {
            while (isRunning)
            {
                RawMessage rawMessage = null;
                try
                {
                    rawMessage = messageQueue.remove();
                }
                catch (InterruptedException ex)
                {
                    if(isRunning())
                        logger.log(Level.WARNING,
                                "A net access point has gone useless:",
                                    ex);
                    //nothing to do here since we test whether we are running
                    //just beneath ...
                }

                // were we asked to stop?
                if (!isRunning()){
                    return;
                }
                //anything to parse?
                if (rawMessage == null)
                    continue;

                Message stunMessage = null;
                try
                {
                    stunMessage =
                        Message.decode(rawMessage.getBytes(),
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
                        rawMessage.getNetAccessPoint(),
                        stunMessage,
                        new TransportAddress(
                            rawMessage.getRemoteAddress().getAddress(),
                            rawMessage.getRemoteAddress().getPort() ));
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
     * @return true if the processor is still authorised to run, and false
     * otherwise.
     */
    boolean isRunning()
    {
        return isRunning;
    }
}
