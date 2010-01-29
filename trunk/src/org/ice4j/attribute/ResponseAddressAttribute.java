/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.attribute;

/**
 * The RESPONSE-ADDRESS attribute indicates where the response to a
 * Binding Request should be sent.  Its syntax is identical to MAPPED-
 * ADDRESS.
 *
 * <p>Copyright: Copyright (c) 2003</p>
 * <p>Organisation: Louis Pasteur University, Strasbourg, France</p>
 *                   <p>Network Research Team (http://www-r2.u-strasbg.fr)</p></p>
 * @author Emil Ivov
 * @version 0.1
 */

public class ResponseAddressAttribute extends AddressAttribute
{
    public static final String NAME = "RESPONSE-ADDRESS";

    /**
     * Creates a RESPONSE_ADDRESS attribute
     */
    public ResponseAddressAttribute()
    {
        super(RESPONSE_ADDRESS);
    }

}
