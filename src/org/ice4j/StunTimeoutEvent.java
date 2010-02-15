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
 * expires.
 *
 * @author Emil Ivov
 */
public class StunTimeoutEvent
    extends EventObject
{
    /**
     * Serial version UID for this Serializable class.
     */
    private static final long serialVersionUID = 41267841L;

    /**
     * The message that the corresponding transaction was about.
     */
    private Message message = null;

    /**
     * The <tt>TransactionID</tt> of the transaction that the source message
     * is related to.
     */
    private final TransactionID transactionID;

    /**
     * Constructs a <tt>StunTimeoutEvent</tt> according to the specified
     * message.
     *
     * @param message the message itself
     * @param localAddress the local address that the message was sent from.
     */
    public StunTimeoutEvent(Message          message,
                            TransportAddress localAddress)
    {
        super(localAddress);
        this.message = message;
        this.transactionID = TransactionID.createTransactionID(message
                                                        .getTransactionID());
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
     * Returns the <tt>Message</tt> whose transaction has just expired.
     *
     * @return the <tt>Message</tt> whose transaction has just expired.
     */
    public Message getMessage()
    {
        return message;
    }

    /**
     * Returns the id of the transaction that has just expired.
     *
     * @return the <tt>TransactionID</tt> of the transaction that has just
     * expired.
     */
    public TransactionID getTransactionID()
    {
        return transactionID;
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
