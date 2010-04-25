/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.message;

/**
 * An indication descendant of the message class.
 *
 * For example, indication messages is used by TURN protocol
 * to send and receive encapsulated data.
 *
 * @author Sebastien Vincent
 */
public class Indication extends Message
{
    /**
     * Constructor.
     */
    Indication()
    {

    }

    /**
     * Checks whether indicationType is a valid response type and if yes sets it
     * as the type of the current instance.
     * @param indicationType the type to set
     * @throws IllegalArgumentException if indicationType is not a valid
     * response type
     */
    public void setMessageType(char indicationType)
        throws IllegalArgumentException
    {
        if(!isIndicationType(indicationType))
            throw new IllegalArgumentException(
                    (int)(indicationType)
                    + " - is not a valid response type.");

        super.setMessageType(indicationType);
    }
}

