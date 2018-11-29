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
package org.ice4j.stack;

import java.util.concurrent.atomic.*;
import java.util.function.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * The class is used to parse and dispatch incoming messages by being
 * executed by concurrent {@link java.util.concurrent.ExecutorService}.
 * To reduce memory allocation this class is designed to be suitable for
 * usage with pooling, the instance of this type is mutable such that
 * <tt>RawMessage</tt> can be updated and instance can be reused and
 * scheduled with new <tt>RawMessage</tt>
 *
 * @author Emil Ivov
 * @author Yura Yaroshevich
 */
class MessageProcessingTask
    implements Runnable
{
    /**
     * Our class logger.
     */
    private static final Logger logger
        = Logger.getLogger(MessageProcessingTask.class.getName());

    /**
     * Indicates that <tt>MessageProcessingTask</tt> is cancelled and should not
     * process <tt>RawMessage</tt> anymore.
     */
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    /**
     * The <tt>NetAccessManager</tt> which has created this instance and which
     * is its owner.
     */
    private final NetAccessManager netAccessManager;

    /**
     * The listener that will be collecting error notifications.
     */
    private final ErrorHandler errorHandler;

    /**
     * The listener that will be retrieving <tt>MessageEvent</tt>s
     */
    private final MessageEventHandler messageEventHandler;

    /**
     * Raw message which is being processed
     */
    private RawMessage rawMessage;

    /**
     * Callback which is invoked when this <tt>MessageProcessingTask</tt>
     * processed it's {@link #rawMessage}
     */
    private Consumer<MessageProcessingTask> rawMessageProcessedHandler;

    /**
     * Creates a Message processor.
     *
     * @param netAccessManager the <tt>NetAccessManager</tt> which is creating
     * the new instance, is going to be its owner, specifies the
     * <tt>MessageEventHandler</tt> and represents the <tt>ErrorHandler</tt> to
     * handle exceptions in the new instance
     * @throws IllegalArgumentException if any of the mentioned properties of
     * <tt>netAccessManager</tt> are <tt>null</tt>
     */
    MessageProcessingTask(NetAccessManager netAccessManager)
        throws IllegalArgumentException
    {
        if (netAccessManager == null)
        {
            throw new NullPointerException("netAccessManager");
        }

        MessageEventHandler messageEventHandler
            = netAccessManager.getMessageEventHandler();

        if (messageEventHandler == null)
        {
            throw new IllegalArgumentException(
                "The message event handler may not be null");
        }

        this.netAccessManager = netAccessManager;
        this.messageEventHandler = messageEventHandler;
        this.errorHandler = netAccessManager;
    }

    /**
     * Assigns the <tt>RawMessage</tt> that will be processed
     * by this <tt>MessageProcessingTask</tt> on executor's thread.
     * @param message RawMessage to be processed
     * @param onProcessed callback which will be invoked when processing
     * of {@link #rawMessage} is completed
     */
    void setMessage(
        RawMessage message,
        Consumer<MessageProcessingTask> onProcessed)
    {
        if (message == null)
        {
            throw new IllegalArgumentException("The message may not be null");
        }
        rawMessage = message;
        rawMessageProcessedHandler = onProcessed;
    }

    /**
     * Performs proper reset of internal state of pooled instance.
     */
    void resetState()
    {
        cancelled.set(false);
        rawMessage = null;
        rawMessageProcessedHandler = null;
    }

    /**
     * Attempts to cancel processing of {@link #rawMessage}
     */
    public void cancel()
    {
        cancelled.set(true);
    }

    /**
     * Does the message parsing.
     */
    @Override
    public void run()
    {
        final Consumer<MessageProcessingTask> onProcessed
            = rawMessageProcessedHandler;
        final RawMessage message = rawMessage;
        //add an extra try/catch block that handles uncatched errors
        try
        {
            if (message == null)
            {
                return;
            }
            rawMessage = null;
            rawMessageProcessedHandler = null;

            if (cancelled.get())
            {
                return;
            }

            StunStack stunStack = netAccessManager.getStunStack();

            Message stunMessage;
            try
            {
                stunMessage
                    = Message.decode(message.getBytes(),
                                     (char) 0,
                                     (char) message.getMessageLength());
            }
            catch (StunException ex)
            {
                errorHandler.handleError(
                    "Failed to decode a stun message!",
                    ex);
                    return;
            }

            logger.finest("Dispatching a StunMessageEvent.");

            StunMessageEvent stunMessageEvent
                = new StunMessageEvent(stunStack, message, stunMessage);

            messageEventHandler.handleMessageEvent(stunMessageEvent);
        }
        catch (Throwable err)
        {
            errorHandler.handleFatalError(
                Thread.currentThread(),
                "Unexpected Error!", err);
        }
        finally
        {
            // On processed callback must be invoked in all cases, even when
            // cancellation or early exist happen, otherwise
            // NetAccessManager internal tracking of pooled and active
            // message processors will missbehave.
            if (onProcessed != null)
            {
                onProcessed.accept(this);
            }
        }
    }
}
