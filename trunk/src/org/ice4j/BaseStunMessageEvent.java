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
 * Represents an <tt>EventObject</tt> which notifies of an event associated with
 * a specific STUN <tt>Message</tt>.
 *
 * @author Lubomir Marinov
 */
public class BaseStunMessageEvent
    extends EventObject
{
    /**
     * A dummy version UID to suppress warnings.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The STUN <tt>Message</tt> associated with this event.
     */
    private final Message message;

    /**
     * The ID of the transaction related to {@link #message}.
     */
    private TransactionID transactionID;

    /**
     * Initializes a new <tt>BaseStunMessageEvent</tt> associated with a
     * specific STUN <tt>Message</tt>.
     *
     * @param sourceAddress the <tt>TransportAddress</tt> which is to be
     * reported as the source of the new event
     * @param message the STUN <tt>Message</tt> associated with the new event
     */
    public BaseStunMessageEvent(TransportAddress sourceAddress, Message message)
    {
        super(sourceAddress);

        this.message = message;
    }

    /**
     * Gets the STUN <tt>Message</tt> associated with this event.
     *
     * @return the STUN <tt>Message</tt> associated with this event
     */
    public Message getMessage()
    {
        return message;
    }

    /**
     * Gets the <tt>TransportAddress</tt> which is the source of this event.
     *
     * @return the <tt>TransportAddress</tt> which is the source of this event
     */
    protected TransportAddress getSourceAddress()
    {
        return (TransportAddress) getSource();
    }

    /**
     * Gets the ID of the transaction related to the STUN <tt>Message</tt>
     * associated with this event.
     *
     * @return the ID of the transaction related to the STUN <tt>Message</tt>
     * associated with this event
     */
    public TransactionID getTransactionID()
    {
        if (transactionID == null)
            transactionID
                = TransactionID
                    .createTransactionID(getMessage().getTransactionID());
        return transactionID;
    }
}
