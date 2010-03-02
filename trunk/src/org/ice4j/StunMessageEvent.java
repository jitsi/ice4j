/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j;

import org.ice4j.message.*;

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
    extends BaseStunMessageEvent
{
    /**
     * Serial version UID for this Serializable class.
     */
    private static final long serialVersionUID = 41267843L;

    /**
     * The sending address.
     */
    private final TransportAddress remoteAddress;

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
        super(sourceAddress, message);

        this.remoteAddress  = remoteAddress;
    }

    /**
     * Returns a <tt>TransportAddress</tt> referencing the access point where
     * the message was received.
     * @return a descriptor of the access point where the message arrived.
     */
    public TransportAddress getLocalAddress()
    {
        return getSourceAddress();
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
     * Returns a <tt>String</tt> representation of this event, containing the
     * corresponding message, remote and local addresses.
     *
     * @return a <tt>String</tt> representation of this event, containing the
     * corresponding message, remote and local addresses.
     */
    @Override
    public String toString()
    {
        StringBuffer buff = new StringBuffer("StunMessageEvent:\n\tMessage=");

        buff.append(getMessage());
        buff.append(" remoteAddr=").append(getRemoteAddress());
        buff.append(" localAddr=").append(getLocalAddress());

        return buff.toString();
    }
}
