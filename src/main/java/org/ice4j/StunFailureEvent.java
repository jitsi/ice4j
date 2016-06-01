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
package org.ice4j;

import org.ice4j.message.*;
import org.ice4j.stack.*;

/**
 * The class is used to dispatch events that occur when a STUN transaction
 * fails asynchronously for reasons like a port unreachable exception for
 * example.
 *
 * @author Emil Ivov
 */
public class StunFailureEvent
    extends BaseStunMessageEvent
{
    /**
     * Serial version UID for this Serializable class.
     */
    private static final long serialVersionUID = 41232541L;

    /**
     * The <tt>Exception</tt> that caused this failure.
     */
    private final Throwable cause;

    /**
     * Constructs a <tt>StunFailureEvent</tt> according to the specified
     * message.
     * 
     * @param stunStack the <tt>StunStack</tt> to be associated with the new
     * instance
     * @param message the message itself
     * @param localAddress the local address that the message was sent from.
     * @param cause the <tt>Exception</tt> that caused this failure or
     * <tt>null</tt> if there's no <tt>Exception</tt> associated with this
     * failure
     */
    public StunFailureEvent(
            StunStack stunStack,
            Message message,
            TransportAddress localAddress,
            Throwable cause)
    {
        super(stunStack, localAddress, message);

        this.cause = cause;
    }

    /**
     * Returns the <tt>TransportAddress</tt> that the message was supposed to
     * leave from.
     *
     * @return the <tt>TransportAddress</tt> that the message was supposed to
     * leave from.
     */
    public TransportAddress getLocalAddress()
    {
        return getSourceAddress();
    }

    /**
     * Returns the <tt>Exception</tt> that cause this failure or <tt>null</tt>
     * if the failure is not related to an <tt>Exception</tt>.
     *
     * @return the <tt>Exception</tt> that cause this failure or <tt>null</tt>
     * if the failure is not related to an <tt>Exception</tt>.
     */
    public Throwable getCause()
    {
        return cause;
    }

    /**
     * Returns a <tt>String</tt> representation of this event, containing the
     * corresponding message, and local address.
     *
     * @return a <tt>String</tt> representation of this event, containing the
     * corresponding message, and local address.
     */
    @Override
    public String toString()
    {
        StringBuffer buff = new StringBuffer("StunFailureEvent:\n\tMessage=");

        buff.append(getMessage());
        buff.append(" localAddr=").append(getLocalAddress());

        return buff.toString();
    }
}
