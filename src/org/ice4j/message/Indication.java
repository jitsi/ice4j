/*
 * Ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.message;

import org.ice4j.*;

/**
 * An indication descendant of the message class. 
 * 
 * For example, indication messages is used by TURN protocol
 * to send and receive encapsulated data.
 *
 * <p>Organisation: <p> Louis Pasteur University, Strasbourg, France</p>
 * <p>Network Research Team (http://www-r2.u-strasbg.fr)</p></p>
 * @author Sebastien Vincent 
 * @version 0.1
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
     * @throws StunException ILLEGAL_ARGUMENT if indicationType is not a valid
     * response type
     */
    public void setMessageType(char indicationType)
        throws StunException
    {
        if(!isIndicationType(indicationType))
            throw new StunException(StunException.ILLEGAL_ARGUMENT,
                    (int)(indicationType)
                    + " - is not a valid response type.");

        super.setMessageType(indicationType);
    }
}

