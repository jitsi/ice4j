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
 * The class is used to dispatch incoming stun messages. Apart from the message
 * itself one could also obtain the address from where the message is coming
 * (used by a server implementation to determine the mapped address)
 * as well as the Descriptor of the NetAccessPoint that received it (In case the
 * stack is used on more than one ports/addresses).
 *
 * @author Emil Ivov
 */
public class StunMessageEvent
    extends EventObject
{
    /**
     * Serial version UID for this Serializable class.
     */
    private static final long serialVersionUID = 41267843L;

    /**
     * The message itself.
     */
    private Message message = null;

    /**
     * The sending address.
     */
    private TransportAddress remoteAddress = null;

    /**
     * The <tt>TransactionID</tt> of the transaction that the source message
     * is related to.
     */
    private final TransactionID transactionID;

    /**
     * Constructs a StunMessageEvent according to the specified message.
     * @param sourceAddress the access point that received the message
     * @param message the message itself
     * @param remoteAddress the address that sent the message
     */
    public StunMessageEvent(TransportAddress sourceAddress,
                            Message          message,
                            TransportAddress remoteAddress)
    {
        super(sourceAddress);
        this.message = message;
        this.remoteAddress  = remoteAddress;
        this.transactionID = TransactionID.createTransactionID(message
                                                        .getTransactionID());
    }

    /**
     * Returns a <tt>TransportAddress</tt> referencing the access point where
     * the message was received.
     * @return a descriptor of the access point where the message arrived.
     */
    public TransportAddress getLocalAddress()
    {
        return (TransportAddress)getSource();
    }

    /**
     * Returns the message being dispatched.
     * @return the message that caused the event.
     */
    public Message getMessage()
    {
        return message;
    }

    /**
     * Returns the address that sent the message.
     * @return the address that sent the message.
     */
    public TransportAddress getRemoteAddress()
    {
        return remoteAddress;
    }

    /**
     * Returns the id of the transaction associated with the message that
     * triggered this event.
     *
     * @return the id of the transaction associated with the message that
     * triggered this event.
     */
    public TransactionID getTransactionID()
    {
        return transactionID;
    }

    /**
     * Returns a <tt>String</tt> representation of this event, containing the
     * corresponding message, remote and local addresses.
     *
     * @return a <tt>String</tt> representation of this event, containing the
     * corresponding message, remote and local addresses.
     */
    public String toString()
    {
        StringBuffer buff = new StringBuffer("StunMessageEvent:\n\tMessage=");

        buff.append(getMessage());
        buff.append(" remoteAddr=").append(getRemoteAddress());
        buff.append(" localAddr=").append(getLocalAddress());

        return buff.toString();
    }
}
