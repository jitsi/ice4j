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

import java.util.*;
import java.util.logging.Logger;

/**
 * The class is used as a part of the stack's thread pooling strategy. Method
 * access is synchronized and message delivery ( remove() ) is blocking in the
 * case of an empty queue.
 *
 * @author Emil Ivov
 */
class MessageQueue
{
    /**
     * The <tt>Logger</tt> used by the <tt>MessageQueue</tt> and its instances
     * for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(MessageQueue.class.getName());

    // not sure whether Vector is the best choice here since we explicitly
    //sync all methods ... review later
    private Vector<RawMessage> queue = new Vector<RawMessage>();

    //keep a copy of the fifo size and make it accessible for concurrent
    // queries.
    private int    size  = 0;

    /**
     * Create an empty MessageFIFO
     */
    MessageQueue()
    {
    }

    /**
     * Returns the number of messages currently in the queue.
     * @return the number of messages in the queue.
     */
    public int getSize()
    {
        return size;
    }

    /**
     * Determines whether the FIFO is currently empty.
     * @return true if the FIFO is currently empty and false otherwise.
     */
    public boolean isEmpty()
    {
        return (size == 0);
    }

    /**
     * Adds the specified message to the queue.
     *
     * @param rawMessage the message to add.
     */
    public synchronized void add(RawMessage rawMessage)
    {
        logger.finest("Adding raw message to queue.");
        queue.add(rawMessage);
        size++;

        notifyAll();
    }

    /**
     * Removes and returns the oldest message from the fifo. If there are
     * currently no messages in the queue the method block until there is at
     * least one message.
     *
     *
     * @return the oldest message in the fifo.
     * @throws java.lang.InterruptedException if an InterruptedException is
     * thrown wail waiting for a new message to be added.
     */
    public synchronized RawMessage remove()
        throws InterruptedException
    {
        waitWhileEmpty();
        RawMessage rawMessage = queue.remove(0);

        size--;
        return rawMessage;
    }

    /**
     * Blocks until there is at least one message in the queue.
     *
     * @throws java.lang.InterruptedException if an InterruptedException is
     * thrown wail waiting for a new message to be added.
     */
    public synchronized void waitWhileEmpty()
        throws InterruptedException
    {
        while (isEmpty())
            wait();
    }
}
