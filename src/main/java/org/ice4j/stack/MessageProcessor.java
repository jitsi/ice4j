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

import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * The class is used to parse and dispatch incoming messages by being
 * executed by concurrent {@link java.util.concurrent.ExecutorService}
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
     * The <tt>NetAccessManager</tt> which has created this instance and which
     * is its owner.
     */
    private final NetAccessManager netAccessManager;

    /**
     * Ram message which is being processed
     */
    private final RawMessage rawMessage;

    /**
     * The listener that will be collecting error notifications.
     */
    private final ErrorHandler errorHandler;

    /**
     * The listener that will be retrieving <tt>MessageEvent</tt>s
     */
    private final MessageEventHandler messageEventHandler;

    /**
     * Creates a Message processor.
     *
     * @param netAccessManager the <tt>NetAccessManager</tt> which is creating
     * the new instance, is going to be its owner, specifies the
     * <tt>MessageEventHandler</tt> and represents the <tt>ErrorHandler</tt> to
     * handle exceptions in the new instance
     * @param message the <tt>RawMessage</tt> to be asynchronously processed by
     * this MessageProcessor
     * @throws IllegalArgumentException if any of the mentioned properties of
     * <tt>netAccessManager</tt> are <tt>null</tt>
     */
    MessageProcessor(
        NetAccessManager netAccessManager,
        RawMessage message)
        throws IllegalArgumentException
    {
        if (netAccessManager == null)
        {
            throw new NullPointerException("netAccessManager");
        }

        if (message == null)
        {
            throw new IllegalArgumentException("The message may not be null");
        }

        MessageEventHandler messageEventHandler
            = netAccessManager.getMessageEventHandler();

        if(messageEventHandler == null)
        {
            throw new IllegalArgumentException(
                "The message event handler may not be null");
        }

        this.netAccessManager = netAccessManager;
        this.messageEventHandler = messageEventHandler;
        this.errorHandler = netAccessManager;
        this.rawMessage = message;
    }

    /**
     * Does the message parsing.
     */
    public void run()
    {
        //add an extra try/catch block that handles uncatched errors
        try
        {
            StunStack stunStack = netAccessManager.getStunStack();

            Message stunMessage;
            try
            {
                stunMessage
                    = Message.decode(rawMessage.getBytes(),
                                     (char) 0,
                                     (char) rawMessage.getMessageLength());
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
                = new StunMessageEvent(stunStack, rawMessage, stunMessage);

            messageEventHandler.handleMessageEvent(stunMessageEvent);
        }
        catch(Throwable err)
        {
            errorHandler.handleFatalError(this, "Unexpected Error!", err);
        }
    }
}
