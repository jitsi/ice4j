/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j;

import java.util.EventObject;
import java.net.InetSocketAddress;

import org.ice4j.message.*;
import org.ice4j.stack.*;


/**
 * The class is used to dispatch incoming stun messages. Apart from the message
 * itself one could also obtain the address from where the message is coming
 * (used by a server implementation to determine the mapped address)
 * as well as the Descriptor of the NetAccessPoint that received it (In case the
 * stack is used on more than one ports/addresses).
 *
 * <p>Organisation: <p> Louis Pasteur University, Strasbourg, France</p>
 * <p>Network Research Team (http://www-r2.u-strasbg.fr)</p></p>
 * @author Emil Ivov
 * @version 0.1
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
    private Message                  message       = null;

    /**
     * The sending address.
     */
    private TransportAddress        remoteAddress = null;

    /**
     * Constructs a StunMessageEvent according to the specified message.
     * @param source the access point that received the message
     * @param message the message itself
     * @param remoteAddress the address that sent the message
     */
    public StunMessageEvent(NetAccessPointDescriptor source,
                            Message                  message,
                            TransportAddress        remoteAddress)
    {
        super(source);
        this.message = message;
        this.remoteAddress  = remoteAddress;
    }

    /**
     * Returns a NetAccessPointDescriptor referencing the access point where the
     * message was received.
     * @return a descriptor of the access point where the message arrived.
     */
    public NetAccessPointDescriptor getSourceAccessPoint()
    {
        return (NetAccessPointDescriptor)getSource();
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
}
