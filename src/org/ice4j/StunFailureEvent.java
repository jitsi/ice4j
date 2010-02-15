/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j;

import java.util.*;

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
    extends EventObject
{
    /**
     * Serial version UID for this Serializable class.
     */
    private static final long serialVersionUID = 41232541L;

    /**
     * The message that the corresponding transaction was about.
     */
    private final Message message;

    /**
     * The <tt>TransactionID</tt> of the transaction that the source message
     * is related to.
     */
    private final TransactionID transactionID;

    /**
     * The <tt>Exception</tt> that caused this failure.
     */
    private final Throwable cause;

    /**
     * Constructs a <tt>StunFailureEvent</tt> according to the specified
     * message.
     *
     * @param message the message itself
     * @param localAddress the local address that the message was sent from.
     * @param cause the <tt>Exception</tt> that caused this failure or
     * <tt>null</tt> if there's no <tt>Exception</tt> associated with this
     * failure
     */
    public StunFailureEvent(Message          message,
                            TransportAddress localAddress,
                            Throwable        cause)
    {
        super(localAddress);
        this.message = message;
        this.transactionID = TransactionID.createTransactionID(message
                                                        .getTransactionID());

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
        return (TransportAddress)getSource();
    }

    /**
     * Returns the <tt>Message</tt> whose transaction has just failed.
     *
     * @return the <tt>Message</tt> whose transaction has just failed.
     */
    public Message getMessage()
    {
        return message;
    }

    /**
     * Returns the id of the transaction that has just failed.
     *
     * @return the <tt>TransactionID</tt> of the transaction that has just
     * failed.
     */
    public TransactionID getTransactionID()
    {
        return transactionID;
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
    public String toString()
    {
        StringBuffer buff = new StringBuffer("StunTimeoutEvent:\n\tMessage=");

        buff.append(getMessage());
        buff.append(" localAddr=").append(getLocalAddress());

        return buff.toString();
    }
}
