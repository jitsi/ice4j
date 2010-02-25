/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.message;

import org.ice4j.*;

/**
 * A response descendant of the message class. The primary purpose of the
 * Response class is to allow better functional definition of the classes in the
 * stack package.
 *
 * @author Emil Ivov
 */
public class Response extends Message
{

    /**
     * Constructor.
     */
    Response()
    {
    }

    /**
     * Checks whether responseType is a valid response type and if yes sets it
     * as the type of the current instance.
     * @param responseType the type to set
     * @throws StunException ILLEGAL_ARGUMENT if responseType is not a valid
     * response type
     */
    public void setMessageType(char responseType)
        throws StunException
    {
        if(!isResponseType(responseType))
            throw new StunException(StunException.ILLEGAL_ARGUMENT,
                                    (int)(responseType)
                                    + " - is not a valid response type.");


        super.setMessageType(responseType);
    }
}
