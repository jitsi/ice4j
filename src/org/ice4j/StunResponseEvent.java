/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j;

import org.ice4j.message.*;
import org.ice4j.stack.*;

/**
 * The class is used to dispatch incoming STUN {@link Response}s. Apart from
 * the {@link Response} itself this event also carries a reference to the
 * {@link Request} that started the corresponding transaction as well as other
 * useful things.
 *
 * @author Emil Ivov
 */
public class StunResponseEvent
    extends StunMessageEvent
{
    /**
     * Serial version UID for this Serializable class.
     */
    private static final long serialVersionUID = -1L;

    /**
     * The original {@link Request} that started the client transaction that
     * the {@link Response} carried in this event belongs to.
     */
    private final Request request;

    /**
     * Creates a new instance of this event.
     *
     * @param rawMessage the crude message we got off the wire.
     * @param response the STUN {@link Response} that we've just received.
     * @param request  the message itself
     */
    public StunResponseEvent(RawMessage rawMessage,
                             Response   response,
                             Request    request)
    {
        super(rawMessage, response);
        this.request = request;
    }

    /**
     * Returns the {@link Request} that started the transaction that this
     * {@link Response} has just arrived in.
     *
     * @return the {@link Request} that started the transaction that this
     * {@link Response} has just arrived in.
     */
    public Request getRequest()
    {
        return request;
    }

    /**
     * Returns the {@link Response} that has just arrived and that caused this
     * event.
     *
     * @return  the {@link Response} that has just arrived and that caused this
     * event.
     */
    public Response getResponse()
    {
        return (Response)getMessage();
    }
}
